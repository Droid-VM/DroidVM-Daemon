// SPDX-License-Identifier: GPL-3.0-or-later
// Port of daemon/vm/backend/CrosvmBackendInstance.buildCommand and the
// launch environment. DataItem semantics as in store/vm_config.cpp.
#include "crosvm_command.h"
#include "command_common.h"
#include "gnss_port.h"
#include <algorithm>
#include <bit>
#include <climits>
#include <set>
#include <stdexcept>

namespace droidvm::vm {
namespace {
using namespace command;
const Names gpu_apis{"NONE", "VULKAN", "EGL", "OPENGLES", "ANGLE", "VULKAN_SYSTEM", "VULKAN_TURNIP", "VULKAN_PANVK", "DRM2KGSL"};
const Names gpu_modes{"NONE", "OPENGL", "VULKAN", "NATIVE"};
const Names blit_providers{"TURNIP", "PANVK", "SYSTEM", "OFF"};
const Names lend_modes{"DISABLED", "SINGLE", "CHUNKED"};
const Names sound_modes{"SPEAKER", "MICROPHONE"};
const Names sound_buffers{"LOW", "NORMAL", "SAFE"};
const Names sound_underruns{"SILENCE", "REPEAT", "WSOLA", "LPC"};
const Names serial_hardware{"SERIAL", "SBSA", "VIRTIO_CONSOLE"};
const Names serial_backends{"SINK", "APP_CONSOLE", "FILE", "UNIX", "UNIX_STREAM", "PTY", "STDOUT", "SYSLOG", "USB_ACM"};
const Names kms_planes{"SPLIT", "SINGLE"};
const Names virtio_transports{"PCI", "MMIO"};
// VpuDecoderBackend / VpuEncoderBackend (the same three names).
const Names vpu_backends{"MEDIACODEC", "AUTO", "MSM_VIDC"};
// CrosvmBackendInstance.quotable: a value inside a double-quoted crosvm key
// cannot carry its own quote or an escape, so a backslash becomes a space and
// a double quote a single one.
std::string quotable(std::string value) {
    for (auto& c : value) {
        if (c == '\\') c = ' ';
        else if (c == '"') c = '\'';
    }
    return value;
}
// NativeDisplay.MOTION_DEVICE_NAME
constexpr const char* motion_device_name = "DroidVM Motion Sensors";
// NativeDisplay.VIBRATOR_DEVICE_NAME
constexpr const char* vibrator_device_name = "DroidVM Vibrator";
// Guards loops that Java would only finish by exhausting its heap.
constexpr int64_t max_cpu_entries = 1 << 20;

int narrow(int64_t value) { return std::bit_cast<int32_t>(static_cast<uint32_t>(value)); }
// String.split(literal) without trailing empties; callers skip empties anyway.
std::vector<std::string> split(const std::string& text, char separator) {
    std::vector<std::string> parts;
    size_t begin = 0;
    while (true) {
        const auto at = text.find(separator, begin);
        parts.push_back(text.substr(begin, at == std::string::npos ? std::string::npos : at - begin));
        if (at == std::string::npos) break;
        begin = at + 1;
    }
    return parts;
}
std::optional<int64_t> parse_long(const std::string& text) {
    try { return config::java_long(text); } catch (const std::invalid_argument&) { return std::nullopt; }
}
// Integer.parseInt
std::optional<int32_t> parse_int(const std::string& text) {
    const auto value = parse_long(text);
    if (!value || *value < INT32_MIN || *value > INT32_MAX) return std::nullopt;
    return static_cast<int32_t>(*value);
}
// --- CpuUtils / CpuPlacementPlan ---
using CpuList = std::vector<int32_t>;
CpuList parse_cpu_set(const std::string& spec) {
    std::set<int32_t> set;
    for (auto part : split(spec, ',')) {
        part = trim(part);
        if (part.empty()) continue;
        const auto dash = part.find('-', 1);
        if (dash == std::string::npos) {
            if (const auto value = parse_int(part)) set.insert(*value);
            continue;
        }
        const auto lo = parse_int(trim(part.substr(0, dash))), hi = parse_int(trim(part.substr(dash + 1)));
        if (!lo || !hi || *lo > *hi) continue;
        if (int64_t(*hi) - *lo >= max_cpu_entries || *hi == INT32_MAX) throw std::runtime_error("CPU set range too large");
        for (int32_t i = *lo; i <= *hi; ++i) set.insert(i);
        if (static_cast<int64_t>(set.size()) > max_cpu_entries) throw std::runtime_error("CPU set too large");
    }
    return {set.begin(), set.end()};
}
// CpuUtils.compactRanges(joinCsv(sorted)), including its int overflow at MAX_VALUE.
std::string compact_ranges(CpuList nums) {
    std::sort(nums.begin(), nums.end());
    nums.erase(std::unique(nums.begin(), nums.end()), nums.end());
    if (nums.empty()) return "";
    std::string out;
    int32_t start = nums[0], prev = start;
    for (size_t i = 1; i <= nums.size(); ++i) {
        const int32_t cur = i < nums.size() ? nums[i] : INT32_MIN;
        if (cur == static_cast<int32_t>(static_cast<uint32_t>(prev) + 1)) { prev = cur; continue; }
        if (!out.empty()) out += ',';
        if (start == prev) out += decimal(start);
        else out += decimal(start) + "-" + decimal(prev);
        start = prev = cur;
    }
    return out;
}
std::map<int32_t, CpuList> parse_affinity(const std::string& spec) {
    std::map<int32_t, CpuList> out;
    if (trim(spec).empty()) return out;
    for (auto assignment : split(spec, ':')) {
        assignment = trim(assignment);
        if (assignment.empty()) continue;
        const auto eq = assignment.find('=');
        if (eq == std::string::npos || eq == 0) continue;
        const auto vcpu = parse_int(trim(assignment.substr(0, eq)));
        if (!vcpu || *vcpu < 0) continue;
        auto hosts = parse_cpu_set(assignment.substr(eq + 1));
        if (hosts.empty()) continue;
        out[*vcpu] = std::move(hosts);
    }
    return out;
}
std::map<int32_t, int64_t> parse_capacity(const std::string& spec) {
    std::map<int32_t, int64_t> out;
    for (auto pair : split(spec, ',')) {
        pair = trim(pair);
        if (pair.empty()) continue;
        const auto eq = pair.find('=');
        if (eq == std::string::npos || eq == 0) continue;
        const auto vcpu = parse_int(trim(pair.substr(0, eq)));
        if (!vcpu) continue;
        const auto cap = parse_long(trim(pair.substr(eq + 1)));
        if (cap && *vcpu >= 0 && *cap > 0) out[*vcpu] = *cap;
    }
    return out;
}
// CpuPlacementPlan.perfRequestsFit: crosvm's virtual cpufreq needs every vCPU
// below cpu_count bound, and each one's host cores in a single frequency
// domain (it reads each core's frequency table and panics when a vCPU's cores
// differ, or when a vCPU has none). A core of unknown frequency has no table.
bool perf_requests_fit(const std::map<int32_t, CpuList>& affinity, int64_t vcpus, const HostFacts& host) {
    std::map<int, int64_t> frequency;
    for (const auto& core : host.cpu_cores) if (core.max_frequency_khz > 0) frequency[core.index] = core.max_frequency_khz;
    for (int64_t vcpu = 0; vcpu < vcpus; ++vcpu) {
        if (vcpu > INT32_MAX) return false;
        const auto bound = affinity.find(static_cast<int32_t>(vcpu));
        if (bound == affinity.end() || bound->second.empty()) return false;
        int64_t domain = 0;
        for (const auto cpu : bound->second) {
            const auto at = frequency.find(cpu);
            if (at == frequency.end() || (domain != 0 && domain != at->second)) return false;
            domain = at->second;
        }
    }
    return true;
}
void cpu_placement(const Json::Value& item, const HostFacts& host, std::vector<std::string>& args) {
    const auto affinity = parse_affinity(string(item, "cpu_affinity", ""));
    if (affinity.empty()) return;
    std::map<int32_t, int64_t> capacity;
    std::vector<CpuList> clusters;
    if (boolean(item, "cpu_topology_auto", true)) {
        std::map<int, int64_t> by_index;
        for (const auto& core : host.cpu_cores) by_index[core.index] = core.capacity;
        for (const auto& [vcpu, hosts] : affinity) {
            int64_t min = 0;
            for (const auto cpu : hosts) {
                const auto at = by_index.find(cpu);
                if (at == by_index.end() || at->second <= 0) continue;
                min = min == 0 ? at->second : std::min(min, at->second);
            }
            if (min > 0) capacity[vcpu] = min;
        }
        const int vcpus = narrow(std::max<int64_t>(integer(item, "cpu_count", 1), 1));
        std::map<int64_t, CpuList> by_capacity;
        for (const auto& [vcpu, cap] : capacity) by_capacity[cap].push_back(vcpu);
        if (!by_capacity.empty()) {
            if (vcpus > max_cpu_entries) throw std::runtime_error("vCPU count too large for cluster derivation");
            auto& weakest = by_capacity.begin()->second;
            for (int vcpu = 0; vcpu < vcpus; ++vcpu) if (!capacity.contains(vcpu)) weakest.push_back(vcpu);
            std::sort(weakest.begin(), weakest.end());
            for (auto& [cap, members] : by_capacity) clusters.push_back(members);
        }
    } else {
        capacity = parse_capacity(string(item, "cpu_capacity", ""));
        for (const auto& group : split(string(item, "cpu_clusters", ""), ';')) {
            auto members = parse_cpu_set(group);
            if (!members.empty()) clusters.push_back(std::move(members));
        }
    }
    std::string text;
    for (const auto& [vcpu, hosts] : affinity) {
        if (hosts.empty()) continue;
        if (!text.empty()) text += ':';
        text += decimal(vcpu) + "=" + compact_ranges(hosts);
    }
    args.push_back("--cpu-affinity");
    args.push_back(text);
    if (!capacity.empty()) {
        text.clear();
        for (const auto& [vcpu, cap] : capacity) {
            if (!text.empty()) text += ',';
            text += decimal(vcpu) + "=" + decimal(cap);
        }
        args.push_back("--cpu-capacity");
        args.push_back(text);
    }
    if (clusters.size() > 1) {
        for (const auto& cluster : clusters) {
            if (cluster.empty()) continue;
            args.push_back("--cpu-cluster");
            args.push_back(compact_ranges(cluster));
        }
    }
    // Per-vCPU performance requests: each vCPU gets a window of crosvm's virtual
    // cpufreq device, and a guest request becomes that vCPU thread's
    // utilization clamp. Default on, but only where crosvm would not panic.
    if (boolean(item, "cpu_perf_requests", true) &&
        perf_requests_fit(affinity, std::max<int64_t>(integer(item, "cpu_count", 1), 1), host))
        args.push_back("--virt-cpufreq-upstream");
}

// --- VMScreenConfig ---
bool has_gpu_device(const Json::Value& config) { return screen_enabled(config, gpu0); }
// DisplayTransportCap.optionsFor; tokens double as identities.
std::vector<const char*> transport_options(const std::string& id, const std::string& exporter) {
    if (exporter == "NATIVE") return id == gpu0 ? std::vector<const char*>{"cpu", "gpu", "zero"} : std::vector<const char*>{"cpu", "gpu"};
    if (exporter == "VNC") return {"cpu", "gpu", "gpu-hw"};
    // crosvm refuses gpu here: it forbids the encoder, and WebRTC sends nothing without one.
    if (exporter == "WEBRTC") return {"cpu", "gpu-hw"};
    return {};
}
bool transport_implemented(const std::string& exporter, const std::string& cap) {
    if (exporter == "NATIVE") return cap == "cpu" || cap == "gpu";
    if (exporter == "VNC") return cap == "cpu" || cap == "gpu" || cap == "gpu-hw";
    if (exporter == "WEBRTC") return cap == "cpu" || cap == "gpu-hw";
    return false;
}
std::string transport_default(const std::string& id, const std::string& exporter) {
    std::string best = "cpu";
    for (const char* option : transport_options(id, exporter)) if (transport_implemented(exporter, option)) best = option;
    return best;
}
// VMScreenConfig.getTransportCap
std::string transport_cap(const Screen& screen) {
    const auto exporter = screen.exporter();
    const auto stored = lower(string(*screen.item, "transport_cap", ""));
    for (const char* option : transport_options(screen.id, exporter)) if (stored == option) return stored;
    return transport_default(screen.id, exporter);
}
// DisplayTransportCap.emittedToken
std::optional<std::string> emitted_token(const Screen& screen) {
    const auto exporter = screen.exporter();
    const auto options = transport_options(screen.id, exporter);
    const auto ceiling = transport_cap(screen), top = transport_default(screen.id, exporter);
    int ceiling_at = -1, top_at = -1;
    for (int i = 0; i < static_cast<int>(options.size()); ++i) {
        if (ceiling == options[i]) ceiling_at = i;
        if (top == options[i]) top_at = i;
    }
    if (ceiling_at < 0 || ceiling_at >= top_at) return std::nullopt;
    return ceiling;
}
std::string transport_cap_arg(const Screen& screen) {
    const auto token = emitted_token(screen);
    return token ? ",transport-cap=" + *token : "";
}
bool has_gpu_blit_binding(const Json::Value& config) {
    for (const auto& screen : screens_of(config)) {
        if (!screen.enabled() || screen.exporter() == "NONE") continue;
        const auto exporter = screen.exporter();
        if (exporter == "NATIVE" || ((exporter == "VNC" || exporter == "WEBRTC") && transport_cap(screen) != "cpu")) return true;
    }
    return false;
}

std::string gpu_mode(const Json::Value& item) {
    const auto mode = java_enum(item, "gpu_mode", "NONE", gpu_modes);
    if (mode != "NONE") return mode;
    const auto api = java_enum(item, "gpu_api", "NONE", gpu_apis);
    if (api == "EGL" || api == "OPENGLES" || api == "ANGLE") return "OPENGL";
    if (api == "VULKAN" || api == "VULKAN_SYSTEM" || api == "VULKAN_TURNIP" || api == "VULKAN_PANVK") return "VULKAN";
    if (api == "DRM2KGSL") return "NATIVE";
    return "NONE";
}
void guest_pool_options(std::string& pre_alloc, const Json::Value& item, int64_t guest_pool) {
    if (guest_pool <= 0) return;
    const auto step = integer(item, "gpu_guest_step_mb", 0);
    if (!pre_alloc.empty()) pre_alloc += ',';
    pre_alloc += "gpu-guest-mb=" + decimal(guest_pool);
    pre_alloc += ",gpu-guest-prealloc-mb=" + decimal(integer(item, "gpu_guest_prealloc_mb", guest_pool));
    pre_alloc += ",gpu-guest-step-mb=" + decimal(step);
    pre_alloc += ",gpu-guest-max-grants=" + decimal(integer(item, "gpu_guest_max_grants", 0));
}
// GuestPoolSizing.bootGuestPoolMb
int64_t boot_guest_pool_mb(const Json::Value& item) {
    if (!has_gpu_device(item)) return 0;
    const auto pvm = java_enum(item, "protected_vm", "PROTECTED_WITHOUT_FIRMWARE", protections);
    if (pvm == "PROTECTED_NORMAL" || pvm == "PSEUDO_UNPROTECTED") return 0;
    const auto pool = std::max<int64_t>(integer(item, "gpu_guest_pool_mb", 0), 0);
    const auto backend = java_enum(item, "gpu_backend", "NONE", gpu_backends);
    if (backend == "GPU_GFXSTREAM") return boolean(item, "gpu_udmabuf", true) ? pool : 0;
    if (backend == "GPU_VIRGLRENDERER") return pool;
    return 0;
}

// VpuConfig: one App switch for the whole virtio-media transport -- the two
// pools and every media device -- plus the pool sizes. Configs written before
// the keys existed keep the App's own defaults (off, 320/192 MiB); the system
// properties, when set, override the switch and the host pool for this launch.
//
// 320 MiB of media_host holds 26 4K NV12 buffers (12,441,600 B each): the 22
// ffmpeg's v4l2 camera input asks for, plus four. 192 MiB of media_guest
// holds 16: the 11 a 4K encode's driver-owned OUTPUT queue needs, plus five.
// Both are whole 2 MiB huge pages.
constexpr int64_t default_vpu_host_pool_mb = 320; // VpuConfig.DEFAULT_HOST_POOL_MB
constexpr int64_t default_vpu_guest_pool_mb = 192; // VpuConfig.DEFAULT_GUEST_POOL_MB
constexpr int64_t max_vpu_host_pool_mb = 65536; // checkInputField(etMediaHostPoolMb, false, 1, 65536)
struct VpuPlan {
    bool enabled = false;
    int64_t host_pool_mb = default_vpu_host_pool_mb;
    // VpuConfig.hostPoolIsDefaulted: the switch is on and the stored size is
    // one crosvm cannot be given (zero or less, or over the editor's limit).
    std::optional<int64_t> defaulted_from;
};
VpuPlan vpu_plan(const Json::Value& item, const HostFacts& host) {
    VpuPlan plan;
    plan.enabled = boolean(item, "vpu_enabled", false);
    const auto pool = integer(item, "vpu_host_pool_mb", default_vpu_host_pool_mb);
    plan.host_pool_mb = pool > 0 && pool <= max_vpu_host_pool_mb ? pool : default_vpu_host_pool_mb;
    if (plan.host_pool_mb != pool) plan.defaulted_from = pool;
    if (host.virtio_media_override) plan.enabled = *host.virtio_media_override;
    if (host.virtio_media_host_mb_override) {
        plan.host_pool_mb = *host.virtio_media_host_mb_override;
        plan.defaulted_from.reset();
    }
    if (!plan.enabled) plan.defaulted_from.reset();
    return plan;
}
// VpuConfig.guestPoolApplies: a guest-owned pool exists only where the host
// cannot otherwise read guest memory.
bool media_guest_pool_applies(const std::string& protection) {
    return protection == "PROTECTED_PROTECTED" || protection == "PROTECTED_WITHOUT_FIRMWARE";
}

struct Builder {
    const Json::Value& item;
    const CrosvmRun& run;
    const BootPlan& boot;
    const HostFacts& host;
    std::string data_dir;
    std::vector<std::string> args;
    bool gunyah = false;
    std::string vm_id() const { return config::uuid(item); }
    // VirtioTransport.fromItem: how the guest finds its virtio devices. A
    // config without the key is a PCI VM, what crosvm does with no flag.
    bool mmio() const { return java_enum(item, "virtio_transport", "PCI", virtio_transports) == "MMIO"; }
    // MotionSensors.rowOf: the first VIRTIO_GYROSCOPE row (crosvm has one motion device).
    const Json::Value* motion_row() const {
        const auto& list = member(item, "peripherals");
        if (!list.isArray()) return nullptr;
        for (const auto& peripheral : list)
            if (java_enum(peripheral, "type", "VIRTIO_SOUND", peripheral_types) == "VIRTIO_GYROSCOPE") return &peripheral;
        return nullptr;
    }
    std::string run_path() const { return path_join(data_dir, "run"); }

    void strace(CrosvmLaunch& launch) { launch.strace_dir = strace_args(item, host, args); }
    void hypervisor_args(const std::string& hypervisor, std::string& def_protected, CrosvmLaunch& launch) {
        args.push_back("--hypervisor");
        if (hypervisor == "KVM") { args.push_back("kvm"); return; }
        if (hypervisor == "GENIEZONE") { args.push_back("geniezone"); return; }
        if (hypervisor != "GUNYAH") throw std::invalid_argument("Unsupported hypervisor: " + hypervisor);
        const bool has_gpu = has_gpu_device(item);
        const auto backend = java_enum(item, "gpu_backend", "NONE", gpu_backends);
        const bool gfxstream = has_gpu && backend == "GPU_GFXSTREAM";
        const bool drm2kgsl = has_gpu && backend == "GPU_VIRGLRENDERER" && gpu_mode(item) == "NATIVE";
        const bool venus = has_gpu && backend == "GPU_VIRGLRENDERER" && gpu_mode(item) == "VULKAN";
        args.push_back("gunyah");
        const auto guest_pool = boot_guest_pool_mb(item);
        // One --pre-alloc for the whole VM: argh rejects a repeated option.
        std::string pre_alloc;
        if (gfxstream) {
            const bool udmabuf = boolean(item, "gpu_udmabuf", true);
            const auto host_pool = integer(item, "gpu_host_pool_mb", 0);
            if (host_pool > 0 || udmabuf) {
                pre_alloc = "gfx-host-mb=" + decimal(host_pool);
                if (udmabuf) guest_pool_options(pre_alloc, item, guest_pool);
            }
        }
        const auto pool_args = [&](const char* key, int64_t pool) {
            if (pool > 0) {
                if (!pre_alloc.empty()) pre_alloc += ',';
                pre_alloc += std::string(key) + "=" + decimal(pool);
            }
            guest_pool_options(pre_alloc, item, guest_pool);
        };
        if (drm2kgsl) pool_args("drm-host-mb", integer(item, "gpu_drm2kgsl_pool_mb", 0));
        if (venus) pool_args("venus-host-mb", integer(item, "gpu_venus_pool_mb", 256));
        // The virtio-media pools, from the VPU switch and nothing else: gunyah
        // refuses a virtio-media device without media_host, and no GPU device
        // is needed for either (a VPU-only VM is a real configuration).
        // media_host is consume_system_mem on the crosvm side, inside --mem;
        // media_guest is the guest driver's own pool beside the RAM, only where
        // the host cannot read guest memory, and boot_guest_prealloc_mb()
        // budgets it for the huge-page reserve.
        if (const auto vpu = vpu_plan(item, host); vpu.enabled) {
            if (vpu.defaulted_from)
                launch.warnings.push_back("video acceleration is on with a stored host pool size of " + decimal(*vpu.defaulted_from) +
                    ": using media-host-mb=" + decimal(vpu.host_pool_mb) + " instead, which crosvm requires before it will create a virtio-media device on gunyah");
            if (!pre_alloc.empty()) pre_alloc += ',';
            pre_alloc += "media-host-mb=" + decimal(vpu.host_pool_mb);
            if (const auto guest = boot_media_guest_mb(item); guest > 0) pre_alloc += ",media-guest-mb=" + decimal(guest);
        }
        if (!pre_alloc.empty()) {
            args.push_back("--pre-alloc");
            args.push_back(pre_alloc);
        }
        def_protected = "PROTECTED_WITHOUT_FIRMWARE";
    }
    void disks() {
        if (!present(item, "disks")) return;
        for (const auto* disk : items(item["disks"])) {
            auto path = string(*disk, "path", "");
            if (path.empty()) continue;
            if (!run.preserve_disk_paths && !run.disk_fds) path = optimized_path(std::move(path), host);
            const bool readonly = boolean(*disk, "readonly", false);
            const auto bus = java_enum(*disk, "bus", "VIRTIO", disk_buses);
            if (bus == "PFLASH") continue; // Not implemented by the legacy crosvm backend either.
            std::string backing;
            if (run.disk_backing_fds && bus != "PMEM") {
                const auto found = run.disk_backing_fds->find(path);
                if (!run.disk_fds || found == run.disk_backing_fds->end() || found->second.size() > 10)
                    throw std::invalid_argument("Missing or excessive retained crosvm backing chain");
                backing = ",backing-chain=[";
                for (const auto fd : found->second) {
                    if (fd < 3) throw std::invalid_argument("Invalid retained crosvm backing descriptor");
                    if (backing.back() != '[') backing += ',';
                    backing += "/proc/self/fd/" + std::to_string(fd);
                }
                backing += ']';
            }
            if (run.disk_fds) {
                const auto found = run.disk_fds->find(path);
                if (found == run.disk_fds->end() || found->second < 3)
                    throw std::invalid_argument("Missing retained crosvm disk descriptor");
                path = "/proc/self/fd/" + std::to_string(found->second);
            }
            auto arg = crosvm_option_value(path) + backing;
            if (bus == "SCSI") {
                arg += ",lock=false";
                if (readonly) arg += ",ro=true";
                args.push_back("--scsi-block");
            } else if (bus == "PMEM") {
                if (readonly) arg += ",ro=true";
                args.push_back("--pmem");
            } else if (bus == "CDROM") {
                args.push_back("--scsi-block");
                arg += ",ro=true,type=cdrom,lock=false";
            } else if (bus == "VIRTIO") {
                arg += ",lock=false";
                if (readonly) arg += ",ro=true";
                // A disk is the one virtio device crosvm moves to MMIO one at a time.
                args.push_back(mmio() ? "--virtio-mmio-block" : "--block");
            } else continue;
            args.push_back(arg);
        }
    }
    void networks() {
        if (!present(item, "networks")) return;
        for (const auto* net : items(item["networks"])) {
            const auto tap = string(*net, "tap_name", "");
            if (tap.empty()) continue;
            auto arg = "tap-name=" + tap;
            const auto mac = string(*net, "mac_address", "");
            if (!mac.empty()) arg += ",mac=" + mac;
            args.push_back("--net");
            args.push_back(arg);
        }
    }
    void shared_dirs() {
        if (!present(item, "shared_dirs")) return;
        for (const auto* dir : items(item["shared_dirs"])) {
            const auto path = string(*dir, "path", ""), tag = string(*dir, "tag", "");
            if (path.empty() || tag.empty()) continue;
            auto arg = path + ":" + tag + ":type=fs:cache=" + lower(java_enum(*dir, "cache", "AUTO", dir_caches)) +
                ":timeout=" + decimal(integer(*dir, "timeout", 5)) + ":writeback=" + java_bool(boolean(*dir, "writeback", false)) +
                ":posix_acl=" + java_bool(boolean(*dir, "posix_acl", true));
            if (!boolean(*dir, "root_access", false)) {
                const int uid = host.app_uid;
                if (uid <= 0 || !host.app_gids) continue;
                arg += ":uid=" + decimal(uid) + ":gid=" + decimal(uid);
                if (!host.app_gids->empty()) {
                    std::string joined;
                    for (const auto gid : *host.app_gids) joined += (joined.empty() ? "" : ",") + decimal(gid);
                    arg += ":supp_gids=" + joined;
                }
            }
            args.push_back("--shared-dir");
            args.push_back(arg);
        }
    }
    void gpu(bool gunyah) {
        const bool gpu_screen = screen_enabled(item, gpu0), fb_screen = screen_enabled(item, simplefb);
        const auto api = java_enum(item, "gpu_api", "NONE", gpu_apis);
        if (!gpu_screen && !fb_screen) return;
        if (gpu_screen) {
            const auto& screen = *find_screen(item, gpu0)->item;
            const auto backend = java_enum(item, "gpu_backend", "NONE", gpu_backends);
            const bool gfxstream = backend == "GPU_GFXSTREAM";
            std::string arg = backend == "GPU_2D" ? "2d" : backend == "GPU_GFXSTREAM" ? "gfxstream" : backend == "GPU_VIRGLRENDERER" ? "virglrenderer" : "none";
            if (gfxstream) arg += ",context-types=gfxstream-vulkan";
            arg += ",displays=[[mode=windowed[" + decimal(integer(screen, "width", 1280)) + "," + decimal(integer(screen, "height", 720)) + "]";
            arg += ",refresh-rate=" + decimal(integer(screen, "refresh_rate", 120));
            arg += ",dpi=[" + decimal(integer(screen, "dpi_h", 160)) + "," + decimal(integer(screen, "dpi_v", 160)) + "]]]";
            const auto bar = decimal(integer(item, "gpu_pci_bar_size", 0x100000000LL));
            if (gfxstream) {
                arg += ",vulkan=true,gles=true";
                arg += ",pci-bar-size=" + bar;
                const bool udmabuf = boolean(item, "gpu_udmabuf", true);
                if (!udmabuf && boolean(item, "gpu_dynamic_vram", false)) {
                    arg += ",vram-limit=" + decimal(integer(item, "gpu_vram_quota_mb", 2048));
                    arg += ",vram-folio-threshold-kb=" + decimal(integer(item, "gpu_vram_folio_threshold_kb", 1024));
                    arg += ",pool-blob-max-kb=" + decimal(integer(item, "gpu_pool_blob_max_kb", 4096));
                }
                if (gunyah) arg += ",gunyah-pvm=true";
                if (udmabuf) arg += ",udmabuf=true";
            } else if (gpu_mode(item) == "NATIVE") {
                arg += ",context-types=drm,vulkan=false,egl=true,gles=true,udmabuf=true,pci-bar-size=" + bar;
            } else if (gpu_mode(item) == "VULKAN") {
                arg += ",context-types=venus,vulkan=true,egl=true,gles=true,udmabuf=true,pci-bar-size=" + bar;
            } else {
                arg += ",vulkan=" + java_bool(api == "VULKAN");
                if (api == "EGL") arg += ",egl=true";
                else if (api == "OPENGLES" || api == "ANGLE") arg += ",gles=true";
            }
            args.push_back("--gpu");
            args.push_back(arg);
        }
        if (fb_screen) {
            const auto& fb = *find_screen(item, simplefb)->item;
            args.push_back("--simplefb");
            args.push_back("width=" + decimal(integer(fb, "width", 1280)) + ",height=" + decimal(integer(fb, "height", 720)) +
                ",poll-hz=" + decimal(integer(fb, "poll_hz", 30)));
        }
    }
    std::string vnc_arg(const Screen& screen) const {
        const auto vnc = vnc_binding(screen, run.vnc);
        std::string arg;
        if (!vnc.host.empty()) arg += "host=" + vnc.host + ",";
        arg += "port=" + decimal(std::max<int64_t>(vnc.port, 1));
        if (!vnc.password.empty()) arg += ",password=" + vnc.password;
        arg += ",view-only=" + java_bool(!screen.input_enabled());
        arg += ",screen=" + screen.id;
        return arg;
    }
    std::string webrtc_arg(const Screen& screen, const WebrtcBinding& rtc) const {
        if (rtc.port < 1 || rtc.port > 65535) throw std::invalid_argument("WebRTC port is not assigned for screen " + screen.id);
        if (!webrtc_token_valid(rtc.token))
            throw std::invalid_argument("WebRTC token may only use letters, digits, '-', '_', '.' and '~'");
        std::string arg;
        if (!rtc.host.empty()) arg += "host=" + crosvm_option_value(rtc.host) + ",";
        arg += "port=" + decimal(rtc.port);
        if (!rtc.token.empty()) arg += ",token=" + rtc.token;
        if (!rtc.stun.empty()) arg += ",stun=[" + crosvm_option_value(rtc.stun) + "]";
        arg += ",view-only=" + java_bool(!screen.input_enabled());
        arg += ",screen=" + screen.id;
        arg += ",codec=" + rtc.codec;
        // crosvm refuses a bitrate outside 500..=100000 kbit/s; anything else means "derive".
        if (rtc.bitrate >= 500 && rtc.bitrate <= 100000) arg += ",bitrate=" + decimal(rtc.bitrate);
        if (!rtc.adapt) arg += ",adapt=false";
        return arg;
    }
    void exporters_args(CrosvmLaunch& launch) {
        launch.kms = crosvm_kms_screen(item);
        for (const auto& screen : screens_of(item)) {
            if (!screen.enabled()) continue;
            const auto exporter = screen.exporter();
            if (exporter == "KMS") {
                // takeover=external: the daemon already owns the panel; crosvm only
                // verifies DRM master and never touches Android services itself.
                const auto card = string(*screen.item, "kms_card", kms_card_default);
                const auto planes = lower(java_enum(*screen.item, "kms_planes", "SPLIT", kms_planes));
                args.push_back("--kms-display");
                args.push_back("card=" + crosvm_option_value(card) + ",screen=" + screen.id + ",takeover=external,planes=" + planes);
            } else if (exporter == "NATIVE") {
                args.push_back("--android-display-service");
                args.push_back("name=droidvm_disp_" + vm_id() + "_" + screen.id + ",screen=" + screen.id + transport_cap_arg(screen));
            } else if (exporter == "VNC") {
                args.push_back("--vnc-server");
                args.push_back(vnc_arg(screen) + transport_cap_arg(screen));
                const auto binding = vnc_binding(screen, run.vnc);
                launch.vnc_endpoints.push_back({screen.id, binding.host, std::max<int64_t>(binding.port, 1),
                    binding.password, screen.input_enabled(), ""});
            } else if (exporter == "WEBRTC") {
                const auto rtc = webrtc_binding(screen);
                args.push_back("--webrtc-server");
                args.push_back(webrtc_arg(screen, rtc) + transport_cap_arg(screen));
                launch.webrtc_endpoints.push_back({screen.id, rtc.host, rtc.port, rtc.token, screen.input_enabled()});
            }
        }
    }
    // NativeDisplay.inputSocketPath; ids are canonical UUIDs and fixed screen ids.
    std::string socket_path(const std::string& screen, const char* channel, bool per_screen) const {
        const std::string tag = !per_screen ? "" : screen == gpu0 ? "_g0" : screen == simplefb ? "_sfb" : "_" + screen;
        auto path = path_join(run_path(), "dvmin_" + vm_id() + tag + "_" + channel + ".sock");
        // NativeDisplay.requireBindablePath, reached through startListening in start().
        if (path.size() > 107)
            throw std::invalid_argument("unix socket path is " + decimal(static_cast<int64_t>(path.size())) + " bytes, over the 107 sun_path allows: " + path);
        return path;
    }
    // The KMS screen's touch is the host digitizer itself: crosvm grabs the evdev
    // node (EVIOCGRAB) because Android's input stack is frozen while it owns the
    // panel. No socket exists for it, so the UI bridge has nothing to feed.
    void kms_inputs(const Screen& screen) {
        if (!screen.input_enabled() || !run.kms_touch_device) return;
        auto arg = "evdev[path=" + crosvm_option_value(*run.kms_touch_device);
        const auto width = integer(*screen.item, "kms_touch_width_mm", 0), height = integer(*screen.item, "kms_touch_height_mm", 0);
        if (width > 0 && height > 0) arg += ",width-mm=" + decimal(width) + ",height-mm=" + decimal(height);
        args.push_back("--input");
        args.push_back(arg + "]");
    }
    void inputs(CrosvmLaunch& launch) {
        for (const auto& screen : screens_of(item)) {
            // WebRTC input arrives over its DataChannel into crosvm's own per-binding devices.
            if (!screen.enabled() || screen.exporter() == "NONE" || screen.exporter() == "KMS" ||
                screen.exporter() == "WEBRTC" || !screen.input_enabled()) continue;
            launch.touch_screens.push_back(screen.id);
            if (screen.exporter() == "NATIVE") launch.native_input_screens.push_back(screen.id);
        }
        args.push_back("--input");
        args.push_back("mouse[path=" + socket_path("", "ms", false) + "]");
        const auto& natives = launch.native_input_screens;
        // NativeDisplayInputBridge.bindAll order: channel, then its screens.
        for (const auto& id : launch.touch_screens) launch.input_sockets.push_back({id, 0, socket_path(id, "mt", true)});
        for (const auto& id : natives) launch.input_sockets.push_back({id, 1, socket_path(id, "kbd", true)});
        launch.input_sockets.push_back({"", 2, socket_path("", "ms", false)});
        for (const auto& id : natives) launch.input_sockets.push_back({id, 3, socket_path(id, "tab", true)});
        for (const auto& id : launch.touch_screens) {
            args.push_back("--input");
            args.push_back("multi-touch[path=" + socket_path(id, "mt", true) + ",name=DroidVM Touch (" + id + ")]");
            if (std::find(natives.begin(), natives.end(), id) == natives.end()) continue;
            args.push_back("--input");
            args.push_back("absolute-mouse[path=" + socket_path(id, "tab", true) + ",name=DroidVM Tablet (" + id + ")]");
            args.push_back("--input");
            args.push_back("keyboard[path=" + socket_path(id, "kbd", true) + ",name=DroidVM Keyboard (" + id + ")]");
        }
    }
    // The VM's motion sensors (a VIRTIO_GYROSCOPE row, or the VM-level
    // motion_sensor switch from before the row existed): crosvm reads the
    // phone's own sensors (host-sensors), and a console that corrects them
    // overrides them through the SENSOR socket, which exists whenever the input
    // bridge does. Without a bridge nothing can override, so no path.
    //
    // Emitted after the other input devices: on an MMIO VM the input windows
    // follow the command line order, so the screens' devices keep their
    // addresses whether or not this one is there.
    void motion_sensors(CrosvmLaunch& launch) {
        const auto* row = motion_row();
        if (!row && !boolean(item, "motion_sensor", false)) return;
        std::string spec = "motion[";
        if (launch.input_bridge) {
            const auto path = socket_path("", "sen", false);
            launch.input_sockets.push_back({"", 4, path});
            spec += "path=" + path + ",";
        }
        spec += "host-sensors=true";
        // MotionSensors.magnetometer: only a row can carry it; on by default.
        if (row && boolean(*row, "magnetometer", true)) {
            if (host.crosvm_motion_magnetometer) spec += ",magnetometer=true";
            else launch.warnings.push_back("this crosvm's motion device has no magnetometer; the motion sensors start without it");
        }
        spec += std::string(",name=") + motion_device_name + "]";
        args.push_back("--input");
        args.push_back(spec);
    }
    // The vibrator (a VIRTIO_VIBRATOR row; one per VM): crosvm's virtio-input
    // device that declares FF_RUMBLE and only listens. Its socket is the
    // daemon's like the console's devices, so it rides the same bridge; a VM
    // exporting no screen has no bridge and so no vibrator. After the motion
    // sensors, for the reason motion_sensors() gives.
    void vibrator(CrosvmLaunch& launch) {
        const auto& list = member(item, "peripherals");
        bool wanted = false;
        if (list.isArray()) for (const auto& peripheral : list)
            wanted = wanted || java_enum(peripheral, "type", "VIRTIO_SOUND", peripheral_types) == "VIRTIO_VIBRATOR";
        if (!wanted) return;
        if (!launch.input_bridge) {
            launch.warnings.push_back("peripheral virtio_vibrator skipped: the VM exports no screen, so there is no input bridge for its socket");
            return;
        }
        if (!host.crosvm_input_vibrator) {
            launch.warnings.push_back("this crosvm has no vibrator input device; the VM starts without its vibrator");
            return;
        }
        const auto path = socket_path("", "vib", false);
        launch.input_sockets.push_back({"", input_channel_vibrator, path});
        args.push_back("--input");
        args.push_back("vibrator[path=" + path + ",name=" + vibrator_device_name + "]");
    }
    // On an MMIO VM, crosvm's switches that move the input devices, the network
    // cards and the GPU to virtio-mmio (the disks moved one by one in disks()).
    // A switch already among the extra options -- how such a VM was configured
    // before the setting existed -- is not repeated.
    void virtio_transport(CrosvmLaunch& launch) {
        if (!mmio()) return;
        std::set<std::string> extra;
        const auto& options = member(item, "extra_options");
        if (options.isArray()) for (const auto& option : options) if (option.isString()) extra.insert(option.asString());
        for (const char* flag : {"--virtio-mmio-input", "--virtio-mmio-net", "--virtio-mmio-gpu"})
            if (!extra.contains(flag)) args.push_back(flag);
        // The sound card's switch only when there is a card: it moves every
        // --virtio-snd the peripheral list emits.
        bool sound = false;
        const auto& list = member(item, "peripherals");
        if (list.isArray()) for (const auto& peripheral : list)
            sound = sound || java_enum(peripheral, "type", "VIRTIO_SOUND", peripheral_types) == "VIRTIO_SOUND";
        if (sound && !extra.contains("--virtio-mmio-snd")) {
            if (host.crosvm_virtio_mmio_snd) args.push_back("--virtio-mmio-snd");
            else launch.warnings.push_back("this crosvm has no --virtio-mmio-snd; the sound card stays on PCI");
        }
        // The virtio-console switch only when there is a console device: it
        // moves the configured virtio-console ports and the GNSS receiver's
        // named port (serials()), which a guest without PCI (iPadOS) could not
        // otherwise reach.
        bool console = run.gnss_input_fd && host.crosvm_serial_name;
        const auto& ports = member(item, "serial_ports");
        if (ports.isArray()) for (const auto& port : ports)
            console = console || java_enum(port, "hardware", "SERIAL", serial_hardware) == "VIRTIO_CONSOLE";
        if (console && !extra.contains("--virtio-mmio-console")) {
            if (host.crosvm_virtio_mmio_console) args.push_back("--virtio-mmio-console");
            else launch.warnings.push_back("this crosvm has no --virtio-mmio-console; the virtio-console ports stay on PCI");
        }
    }
    // HostAudioTable.PATH; the dump path is a literal in the Java too.
    // HostAudioDevices.ATTR_SEPARATOR: a host_device key is the endpoint, then
    // what the stream is for as attr=value,... after '#'. Passed to crosvm as
    // is, except the latency mode (performance=) when the installed crosvm's
    // AAudio backend does not know it: it would refuse the whole card.
    std::string sound_key(std::string key, bool& stripped) const {
        if (host.crosvm_sound_performance) return key;
        const auto hash = key.find('#');
        if (hash == std::string::npos) return key;
        std::string kept;
        bool dropped = false;
        for (const auto& pair : split(key.substr(hash + 1), ',')) {
            const auto eq = pair.find('=');
            if (eq != std::string::npos && eq > 0 && trim(pair.substr(0, eq)) == "performance") { dropped = true; continue; }
            if (!kept.empty()) kept += ',';
            kept += pair;
        }
        if (!dropped) return key;
        stripped = true;
        key.resize(hash);
        return kept.empty() ? key : key + '#' + kept;
    }
    std::string sound_config(const std::vector<const Json::Value*>& endpoints, const Json::Value& peripheral, bool& stripped) const {
        std::vector<const Json::Value*> outputs, inputs;
        for (const auto* endpoint : endpoints) (java_enum(*endpoint, "mode", "SPEAKER", sound_modes) == "MICROPHONE" ? inputs : outputs).push_back(endpoint);
        std::string cfg = host.viosnd_dump_exists ? "backend=file" : "backend=aaudio";
        if (host.viosnd_dump_exists) cfg += ",playback_path=/data/data/cn.classfun.droidvm/cache,playback_size=4194304";
        cfg += ",capture=" + java_bool(!inputs.empty());
        cfg += ",num_output_devices=" + decimal(static_cast<int64_t>(outputs.size()));
        cfg += ",num_input_devices=" + decimal(static_cast<int64_t>(inputs.size()));
        cfg += ",device_table=" + path_join(data_dir, "run", "audio_devices");
        const auto append = [&](const char* field, const std::vector<const Json::Value*>& list) {
            if (list.empty()) return;
            cfg += std::string(",") + field + "=[";
            for (size_t i = 0; i < list.size(); ++i) {
                std::string key;
                if (present(*list[i], "host_device")) {
                    const auto& value = (*list[i])["host_device"];
                    if (!value.isString()) throw std::runtime_error("Expected type STRING");
                    key = value.asString();
                }
                if (key.empty()) key = "DEFAULT|system default";
                key = sound_key(std::move(key), stripped);
                cfg += std::string(i == 0 ? "" : ",") + "[host_device=\"" + key + "\"]";
            }
            cfg += "]";
        };
        append("output_device_config", outputs);
        append("input_device_config", inputs);
        cfg += ",underrun=" + lower(java_enum(peripheral, "underrun", "SILENCE", sound_underruns));
        const auto buffer = java_enum(peripheral, "buffer", "NORMAL", sound_buffers);
        cfg += ",guest_outstanding_packets=" + std::string(buffer == "LOW" ? "2" : buffer == "SAFE" ? "12" : "6");
        cfg += ",uid=" + decimal(host.app_uid);
        return cfg;
    }
    void peripherals(CrosvmLaunch& launch) {
        const auto& list = member(item, "peripherals");
        if (!list.isArray()) return;
        static const Json::Value empty_object(Json::objectValue);
        int camera_seen = 0;
        bool uvc_skipped = false;
        for (const auto& peripheral : list) {
            const auto type = java_enum(peripheral, "type", "VIRTIO_SOUND", peripheral_types);
            // USB_CAMERA: one emulated USB (UVC) camera per row on crosvm's
            // xHCI. A row left on "follow the system" hands over its position
            // among the USB camera rows instead of an id, which is what makes
            // two default rows land on two different cameras rather than both
            // on the back one.
            if (type == "USB_CAMERA") {
                std::string key;
                if (present(peripheral, "host_device")) {
                    const auto& value = peripheral["host_device"];
                    if (!value.isString()) throw std::runtime_error("Expected type STRING");
                    key = value.asString();
                }
                // An older crosvm refuses the unknown flag and the VM would not
                // start at all; leave the camera out rather than the VM.
                if (!host.crosvm_uvc_camera) { uvc_skipped = true; continue; }
                args.push_back("--uvc-camera");
                args.push_back(key.empty() ? decimal(camera_seen) : key);
                ++camera_seen;
                continue;
            }
            // VIRTIO_GYROSCOPE is motion_sensors(), after the other input
            // devices; XHCI_USB and the unbacked types only log.
            if (type != "VIRTIO_SOUND") continue;
            if (host.app_uid <= 0) continue;
            std::vector<const Json::Value*> endpoints;
            const auto& rows = member(peripheral, "endpoints");
            if (present(peripheral, "endpoints")) {
                const auto size = rows.isArray() || rows.isObject() ? rows.size() : 0;
                for (Json::ArrayIndex i = 0; i < size; ++i) endpoints.push_back(rows.isArray() ? &rows[i] : &empty_object);
            }
            if (endpoints.empty()) continue;
            args.push_back("--virtio-snd");
            bool stripped = false;
            args.push_back(sound_config(endpoints, peripheral, stripped));
            if (stripped) launch.warnings.push_back("this crosvm's AAudio backend has no latency mode; the sound card's endpoints start in its default");
        }
        if (uvc_skipped) launch.warnings.push_back("peripheral usb_camera skipped: this crosvm has no --uvc-camera");
    }
    // Whether a USB_CAMERA row will be on the command line: it hangs off
    // crosvm's xHCI, so the VM keeps its USB controller for it.
    bool uvc_camera() const {
        if (!host.crosvm_uvc_camera || !member(item, "peripherals").isArray()) return false;
        for (const auto& peripheral : item["peripherals"])
            if (java_enum(peripheral, "type", "VIRTIO_SOUND", peripheral_types) == "USB_CAMERA") return true;
        return false;
    }
    // VpuConfig.codecDevicesAttached and appendCodecDevices: what the switch
    // itself buys, a hardware decoder and encoder (VpuConfig.CODEC_KINDS, in
    // that order: the encoder was appended so a guest's decoder node keeps its
    // number), each a helper under the app uid. After the camera rows, so the
    // cameras keep their /dev/videoN when codecs come or go. vpu_codec_enabled
    // (default on) takes only these away, never the pools or a camera. Only
    // Gunyah gets the media-host-mb pool (hypervisor_args), and crosvm refuses
    // a virtio-media device without it, so KVM/GenieZone get none.
    void codec_devices(CrosvmLaunch& launch) {
        if (!vpu_plan(item, host).enabled || !boolean(item, "vpu_codec_enabled", true)) return;
        if (!gunyah) {
            launch.warnings.push_back("codec devices skipped: they serve buffers from the media_host pool, which only a Gunyah VM is passed");
            return;
        }
        if (host.app_uid <= 0) {
            launch.warnings.push_back("cannot resolve app uid; codec devices skipped");
            return;
        }
        for (const char* kind : codec_kinds) {
            args.push_back("--virtio-media");
            args.push_back(codec_config(kind, launch));
        }
    }
    static constexpr const char* codec_kinds[] = {"decoder", "encoder"};
    // CrosvmBackendInstance.buildCodecConfig. The card is the name crosvm's
    // helper falls back to, passed explicitly so the guest's name for its
    // device is decided here. The backend choice (VpuDecoderBackend /
    // VpuEncoderBackend; MediaCodec, crosvm's default, adds nothing) goes in
    // the spelling the installed crosvm knows: backend=NAME where it has the
    // backend table, else vidc=true for the decoder's msm_vidc, else nothing
    // and the launcher says the device keeps MediaCodec.
    std::string codec_config(const std::string& kind, CrosvmLaunch& launch) const {
        auto cfg = "kind=" + kind + ",card=\"" + quotable("droidvm " + kind) + "\",uid=" + decimal(host.app_uid);
        const auto backend = java_enum(item, kind == "decoder" ? "vpu_decoder_backend" : "vpu_encoder_backend", "MEDIACODEC", vpu_backends);
        if (backend == "MEDIACODEC") return cfg;
        const auto name = backend == "AUTO" ? "auto" : "msm-vidc";
        if (host.crosvm_media_backend) return cfg + ",backend=" + name;
        if (kind == "decoder" && backend == "MSM_VIDC" && host.crosvm_media_vidc) return cfg + ",vidc=true";
        launch.warnings.push_back("this crosvm cannot choose the " + kind + "'s backend (" + name + "); it keeps MediaCodec");
        return cfg;
    }
    void serials(CrosvmLaunch& launch) {
        const auto& ports = member(item, "serial_ports");
        struct Arg { std::string type = "sink"; std::optional<std::string> path, input; bool interactive = false; };
        std::vector<Arg> resolved;
        std::vector<const Json::Value*> list;
        for (Json::ArrayIndex i = 0; ports.isArray() && i < ports.size(); ++i) {
            const auto& port = ports[i];
            const SerialRun none;
            const auto& state = i < run.serials.size() ? run.serials[i] : none;
            const auto backend = java_enum(port, "backend", "SINK", serial_backends);
            const auto path = string(port, "path", "");
            Arg arg;
            if (backend == "APP_CONSOLE") {
                if (state.pipe) {
                    arg.type = "file";
                    arg.path = "/proc/self/fd/" + decimal(state.pipe->first);
                    arg.input = "/proc/self/fd/" + decimal(state.pipe->second);
                    arg.interactive = true;
                }
            } else if (backend == "PTY") {
                arg.type = "pty";
                if (!path.empty()) arg.path = path;
                arg.interactive = true;
            } else if (backend == "FILE") { arg.type = "file"; arg.path = path; }
            else if (backend == "UNIX") { arg.type = "unix"; arg.path = path; }
            else if (backend == "UNIX_STREAM") { arg.type = "unix-stream"; arg.path = path; arg.interactive = true; }
            else if (backend == "STDOUT") arg.type = "stdout";
            else if (backend == "SYSLOG") arg.type = "syslog";
            else if (backend == "USB_ACM" && state.acm_dev_path) { arg.type = "dev"; arg.path = *state.acm_dev_path; arg.interactive = true; }
            resolved.push_back(std::move(arg));
            list.push_back(&port);
        }
        int console = -1;
        for (size_t i = 0; i < list.size() && console < 0; ++i) if (boolean(*list[i], "console", false)) console = static_cast<int>(i);
        for (size_t i = 0; i < resolved.size() && console < 0; ++i) if (resolved[i].interactive) console = static_cast<int>(i);
        for (size_t i = 0; i < list.size(); ++i) {
            const auto hardware = java_enum(*list[i], "hardware", "SERIAL", serial_hardware);
            const auto& arg = resolved[i];
            auto serial = "type=" + arg.type + ",hardware=" + (hardware == "SBSA" ? "sbsa" : hardware == "VIRTIO_CONSOLE" ? "virtio-console" : "serial") +
                ",num=" + decimal(narrow(integer(*list[i], "num", 1)));
            if (arg.path) serial += ",path=" + *arg.path;
            if (arg.input) serial += ",input=" + *arg.input;
            if (static_cast<int>(i) == console) {
                serial += ",console";
                if (hardware != "VIRTIO_CONSOLE") serial += ",earlycon";
            }
            args.push_back("--serial");
            args.push_back(serial);
        }
        gnss_serial(launch, list);
    }
    // The GNSS receiver's port, after the configured ones: a sink for what the
    // guest writes, its input the daemon's pipe, under a virtio-console number
    // no configured port uses (crosvm keys serials by type and number).
    void gnss_serial(CrosvmLaunch& launch, const std::vector<const Json::Value*>& configured) {
        if (!run.gnss_input_fd) return;
        if (!host.crosvm_serial_name) {
            launch.warnings.push_back("this crosvm cannot name a serial port; the VM starts without its GNSS receiver");
            return;
        }
        int num = 0;
        for (const auto* port : configured)
            if (java_enum(*port, "hardware", "SERIAL", serial_hardware) == "VIRTIO_CONSOLE")
                num = std::max(num, narrow(integer(*port, "num", 1)));
        args.push_back("--serial");
        args.push_back("type=sink,hardware=virtio-console,num=" + decimal(num + 1) + ",name=" + gnss_port_name +
            ",input=/proc/self/fd/" + decimal(*run.gnss_input_fd));
        launch.preserve_fds.push_back(*run.gnss_input_fd);
        launch.gnss = true;
    }

    // PCI MSI/MSI-X on Gunyah (pci_msi, on unless switched off): crosvm's
    // --mbi-spis puts a GICv2m-style MSI frame in front of mbi_spis SPIs, so
    // each virtio-pci queue and the xHCI get an edge interrupt of their own
    // instead of sharing INTx lines. Each guest finds the frame or not (Linux
    // by the device tree's msi-parent, Windows by the GIC MSI Frame
    // edk2-gunyah writes into the MADT), and one that knows neither keeps
    // INTx. Only Gunyah has the frame -- the other irq chips refuse it -- and a
    // count the user put in extra_options wins.
    //
    // Gunyah takes a VM's irqfds only from the device tree at start, which
    // grows it by about 9 KB; EDK2's PrePi copies the tree into the room after
    // its image header, which edk2-gunyah kept at 32 KB until a7903f0. An older
    // image would copy the tree over its own code, so a firmware without
    // mbi_min_firmware_code_offset of room boots without MSI instead.
    static constexpr int mbi_spis = 64;
    static constexpr int64_t mbi_min_firmware_code_offset = 0x20000;
    void mbi(CrosvmLaunch& launch) {
        if (!gunyah || !boolean(item, "pci_msi", true)) return;
        const auto& options = member(item, "extra_options");
        if (options.isArray()) for (const auto& option : options) if (option.isString() && option.asString() == "--mbi-spis") return;
        if (!host.crosvm_mbi_spis) {
            launch.warnings.push_back("this crosvm has no --mbi-spis; PCI devices keep INTx");
            return;
        }
        if (boot.uefi && host.firmware_code_offset < mbi_min_firmware_code_offset) {
            launch.warnings.push_back("PCI MSI off: the firmware starts its code at " + decimal(host.firmware_code_offset) +
                ", under " + decimal(mbi_min_firmware_code_offset) + " (an older edk2-gunyah)");
            return;
        }
        args.push_back("--mbi-spis");
        args.push_back(decimal(mbi_spis));
    }

    int64_t pflash_block_size() const {
        const auto size = host.pflash_vars_size;
        for (int64_t block : {262144, 65536, 4096}) if (size > 0 && size % block == 0) return block;
        return 262144;
    }

    void command(CrosvmLaunch& launch) {
        strace(launch);
        const auto& name = member(item, "name");
        if (!name.isString()) throw std::invalid_argument("VM name is not a string");
        for (auto arg : {path_join(data_dir, "usr", "bin", "crosvm"), std::string("--extended-status"), std::string("run"), std::string("--name"), name.asString()})
            args.push_back(std::move(arg));
        args.push_back("--mem");
        args.push_back(decimal(std::max<int64_t>(integer(item, "memory_mb", 512), 64)));
        args.push_back("--cpus");
        args.push_back(decimal(std::max<int64_t>(integer(item, "cpu_count", 1), 1)));
        cpu_placement(item, host, args);
        if (run.gpu_cgroup_path) {
            args.push_back("--gpu-cgroup-path");
            args.push_back(*run.gpu_cgroup_path);
        }
        const auto hypervisor = resolve_hypervisor(item, host, Backend::crosvm);
        if (!hypervisor) throw std::runtime_error("No supported hypervisor found for CROSVM backend");
        gunyah = *hypervisor == "GUNYAH";
        std::string def_protected = "PROTECTED_NORMAL";
        hypervisor_args(*hypervisor, def_protected, launch);
        auto protection = java_enum(item, "protected_vm", def_protected.c_str(), protections);
        if (protection == "PSEUDO_UNPROTECTED" && *hypervisor != "GUNYAH") protection = "PROTECTED_NORMAL";
        if (protection == "PROTECTED_PROTECTED") args.push_back("--protected-vm");
        else if (protection == "PROTECTED_WITHOUT_FIRMWARE") args.push_back("--protected-vm-without-firmware");
        else if (protection == "PSEUDO_UNPROTECTED") args.push_back("--protected-vm-pseudo-unprotected");
        if (!boolean(item, "balloon", false)) args.push_back("--no-balloon");
        if (!boolean(item, "pmu", false)) args.push_back("--no-pmu");
        if (!boolean(item, "rng", false)) args.push_back("--no-rng");
        if (!boolean(item, "smt", false)) args.push_back("--no-smt");
        bool xhci = false;
        if (member(item, "peripherals").isArray())
            for (const auto& peripheral : item["peripherals"]) xhci = xhci || java_enum(peripheral, "type", "VIRTIO_SOUND", peripheral_types) == "XHCI_USB";
        if (!xhci && !uvc_camera()) args.push_back("--no-usb");
        if (!boolean(item, "sandbox", false)) args.push_back("--disable-sandbox");
        if (boolean(item, "hugepages", true)) args.push_back("--hugepages");
        const auto& lend = member(item, "prepare_lend_mthp");
        const auto mthp = lend.isBool() ? (lend.asBool() ? "CHUNKED" : "DISABLED") : java_enum(item, "prepare_lend_mthp", "CHUNKED", lend_modes);
        if (mthp == "SINGLE" || mthp == "CHUNKED") {
            args.push_back("--prepare-lend-mthp-mode");
            args.push_back(mthp == "SINGLE" ? "single" : "chunked");
        }
        auto swiotlb = integer(item, "swiotlb_mb", 0);
        if (protection == "PSEUDO_UNPROTECTED") swiotlb = 0;
        if (swiotlb > 0) {
            args.push_back("--swiotlb");
            args.push_back(decimal(swiotlb));
        }
        if (!boot.initrd.empty()) { args.push_back("--initrd"); args.push_back(boot.initrd); }
        if (!boot.cmdline.empty()) { args.push_back("--params"); args.push_back(boot.cmdline); }
        if (run.control_socket_path) { args.push_back("--socket"); args.push_back(*run.control_socket_path); }
        if (host.soc_name) { args.push_back("--smbios"); args.push_back("processor-version=" + *host.soc_name); }
        disks();
        networks();
        shared_dirs();
        gpu(*hypervisor == "GUNYAH");
        exporters_args(launch);
        for (const auto& screen : screens_of(item)) {
            const auto exporter = screen.exporter();
            if (screen.enabled() && exporter == "KMS") kms_inputs(screen);
            else launch.input_bridge = launch.input_bridge || (screen.enabled() && exporter != "NONE" && exporter != "WEBRTC");
        }
        if (launch.input_bridge) inputs(launch);
        motion_sensors(launch);
        vibrator(launch);
        virtio_transport(launch);
        peripherals(launch);
        codec_devices(launch);
        serials(launch);
        mbi(launch);
        extra_options(item, args);
        if (boot.uefi) {
            args.push_back(boot.firmware.empty() ? path_join(data_dir, "/usr/share/droidvm/edk2-gunyah.fd") : boot.firmware);
            if (boot.vars_enabled) {
                const auto vars = boot.vars.empty() ? path_join(data_dir, "/usr/share/droidvm/edk2-gunyah.vars.fd") : boot.vars;
                args.push_back("--pflash");
                args.push_back("path=" + vars + ",block_size=" + decimal(pflash_block_size()));
            }
        } else if (!boot.kernel.empty()) args.push_back(boot.kernel);
    }

    void environment(CrosvmLaunch& launch) const {
        auto& env = launch.env;
        process_environment(item, host, env);
        const auto turnip = path_join(data_dir, "usr", "lib", "libvulkan_freedreno.so");
        // applyGfxstreamEnv
        if (has_gpu_device(item)) {
            const auto backend = java_enum(item, "gpu_backend", "NONE", gpu_backends);
            const bool gfxstream = backend == "GPU_GFXSTREAM";
            const bool venus = backend == "GPU_VIRGLRENDERER" && gpu_mode(item) == "VULKAN";
            if (gfxstream || venus) {
                if (gfxstream) env.emplace_back("GFXSTREAM_DEVICE_LOCAL_MEMORY_TYPE", "1");
                const auto api = java_enum(item, "gpu_api", "NONE", gpu_apis);
                if (api != "VULKAN_SYSTEM" && api != "VULKAN_PANVK" && host.turnip_exists) env.emplace_back("ANDROID_EMU_VK_LOADER_PATH", turnip);
                launch.udmabuf_limit_mb = integer(item, "gpu_udmabuf_limit_mb", 4096);
            }
        }
        // virtio-media imports guest-owned buffers out of media_guest through
        // udmabuf as well, whole, on a VM that may have no renderer at all.
        if (!launch.udmabuf_limit_mb && vpu_plan(item, host).enabled)
            launch.udmabuf_limit_mb = integer(item, "gpu_udmabuf_limit_mb", 4096);
        // applyDisplayBlitEnv
        if (has_gpu_blit_binding(item)) {
            const auto provider = java_enum(item, "display_blit_provider", "TURNIP", blit_providers);
            if (provider == "TURNIP") {
                if (host.turnip_exists) env.emplace_back("CROSVM_DISPLAY_VULKAN_LIBRARY", turnip);
            } else if (provider == "SYSTEM") {
                if (host.system_vulkan_hal) env.emplace_back("CROSVM_DISPLAY_VULKAN_LIBRARY", *host.system_vulkan_hal);
            } else env.emplace_back("GPU_DISPLAY_COPY_MODE", "cpu");
        }
        // applyGpuRtPrioEnv
        if (has_gpu_device(item)) {
            const auto prio = string(item, "gpu_rt_prio", "");
            if (!prio.empty() && run.gpu_cgroup_path) env.emplace_back("CROSVM_GPU_RT_PRIO", prio);
        }
        // Held touch contacts need the 40 ms SYN_REPORT keepalive for Windows
        // long-press (crosvm 0863c89); it is opt-in on the crosvm side.
        if (launch.kms && run.kms_touch_device) env.emplace_back("CROSVM_TOUCH_KEEPALIVE", "1");
    }
};
}

bool crosvm_retained_chain_supported(const Json::Value& caps) {
    if (!caps.isObject() || caps["schema"] != "droidvm-disk-capabilities-v1" ||
        caps["backing_chain"] != "explicit-paths-v1" || !caps["max_backing_depth"].isUInt() ||
        caps["max_backing_depth"].asUInt() < 10) return false;
    for (const auto* name : {"proc_fd", "raw", "qcow2", "block", "scsi"})
        if (!caps[name].isBool() || !caps[name].asBool()) return false;
    return true;
}
CrosvmLaunch crosvm_command(const Json::Value& config, const CrosvmRun& run, const BootPlan& boot, const HostFacts& host) {
    if (!config.isObject()) throw std::invalid_argument("VM config must be an object");
    Builder builder{config, run, boot, host, data_dir(host), {}};
    CrosvmLaunch launch;
    builder.command(launch);
    if (vnc_options_overridden(config, Backend::crosvm))
        for (auto& endpoint : launch.vnc_endpoints) endpoint.unavailable_reason = "unsupported";
    launch.argv = std::move(builder.args);
    if (run.disk_fds) for (const auto& [path, fd] : *run.disk_fds) launch.preserve_fds.push_back(fd);
    if (run.disk_backing_fds) for (const auto& [path, chain] : *run.disk_backing_fds) for (const auto fd : chain) {
        if (std::find(launch.preserve_fds.begin(), launch.preserve_fds.end(), fd) == launch.preserve_fds.end())
            launch.preserve_fds.push_back(fd);
    }
    builder.environment(launch);
    return launch;
}
bool crosvm_kms_screen(const Json::Value& config) {
    bool kms = false, other = false;
    for (const auto& screen : screens_of(config)) {
        if (!screen.enabled()) continue;
        const auto exporter = screen.exporter();
        if (exporter == "KMS") {
            // crosvm's gpu.rs replaces the whole display backend list with KMS, so
            // a second exporter on any screen would silently lose its frames.
            if (screen.id != gpu0) throw std::invalid_argument("KMS export is only available on the gpu-0 screen");
            kms = true;
        } else if (exporter != "NONE") other = true;
    }
    if (kms && other) throw std::invalid_argument("KMS export cannot be combined with another exporter on this VM");
    return kms;
}
bool resolves_to_gunyah(const Json::Value& item, const HostFacts& host) {
    // VMHypervisor.resolveConfigured with optEnum (unknown names are AUTO);
    // both backends prefer KVM, then Gunyah.
    const auto configured = java_enum(item, "hypervisor", "AUTO", hypervisors);
    if (configured != "AUTO") return configured == "GUNYAH";
    if (host.has_kvm) return false;
    return host.has_gunyah;
}
std::string screen_transport_cap(const Json::Value& config, const std::string& id) {
    const auto screen = find_screen(config, id.c_str());
    if (!screen) return transport_default(id, "NONE");
    return transport_cap(*screen);
}
int64_t boot_guest_prealloc_mb(const Json::Value& item) {
    int64_t mb = boot_media_guest_mb(item);
    const auto pool = boot_guest_pool_mb(item);
    if (pool <= 0) return mb;
    return mb + std::max<int64_t>(std::min<int64_t>(integer(item, "gpu_guest_prealloc_mb", pool), pool), 0);
}
int64_t boot_media_guest_mb(const Json::Value& item) {
    if (!boolean(item, "vpu_enabled", false)) return 0;
    if (!media_guest_pool_applies(java_enum(item, "protected_vm", "PROTECTED_WITHOUT_FIRMWARE", protections))) return 0;
    return std::max<int64_t>(integer(item, "vpu_guest_pool_mb", default_vpu_guest_pool_mb), 0);
}
}
