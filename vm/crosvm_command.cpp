// SPDX-License-Identifier: GPL-3.0-or-later
// Port of daemon/vm/backend/CrosvmBackendInstance.buildCommand and the
// launch environment. DataItem semantics as in store/vm_config.cpp.
#include "crosvm_command.h"
#include "store/network_config.h"
#include "store/vm_config.h"
#include "build_metadata.h"
#include <unicode/utf8.h>
#include <unicode/utf16.h>
#include <algorithm>
#include <bit>
#include <climits>
#include <set>
#include <stdexcept>

namespace droidvm::vm {
namespace {
using config::boolean;
using config::integer;
using config::java_enum;
using config::member;
using config::string;
using Names = std::vector<const char*>;
const Names hypervisors{"AUTO", "SOFT", "KVM", "GUNYAH", "GENIEZONE"};
const Names protections{"PROTECTED_NORMAL", "PROTECTED_PROTECTED", "PROTECTED_WITHOUT_FIRMWARE", "PSEUDO_UNPROTECTED"};
const Names gpu_backends{"NONE", "GPU_2D", "GPU_GFXSTREAM", "GPU_VIRGLRENDERER"};
const Names gpu_apis{"NONE", "VULKAN", "EGL", "OPENGLES", "ANGLE", "VULKAN_SYSTEM", "VULKAN_TURNIP", "VULKAN_PANVK", "DRM2KGSL"};
const Names gpu_modes{"NONE", "OPENGL", "VULKAN", "NATIVE"};
const Names exporters{"NATIVE", "VNC", "NONE"};
const Names blit_providers{"TURNIP", "PANVK", "SYSTEM", "OFF"};
const Names lend_modes{"DISABLED", "SINGLE", "CHUNKED"};
const Names disk_buses{"VIRTIO", "SCSI", "PMEM", "PFLASH", "CDROM"};
const Names dir_caches{"NEVER", "AUTO", "ALWAYS"};
const Names peripheral_types{"VIRTIO_SOUND", "INTEL_HDA", "VIRTIO_CAMERA", "XHCI_USB"};
const Names sound_modes{"SPEAKER", "MICROPHONE"};
const Names sound_buffers{"LOW", "NORMAL", "SAFE"};
const Names sound_underruns{"SILENCE", "REPEAT", "WSOLA", "LPC"};
const Names serial_hardware{"SERIAL", "SBSA", "VIRTIO_CONSOLE"};
const Names serial_backends{"SINK", "APP_CONSOLE", "FILE", "UNIX", "UNIX_STREAM", "PTY", "STDOUT", "SYSLOG", "USB_ACM"};
constexpr const char* gpu0 = "gpu-0";
constexpr const char* simplefb = "simplefb";
// Guards loops that Java would only finish by exhausting its heap.
constexpr int64_t max_cpu_entries = 1 << 20;

bool present(const Json::Value& object, const char* key) { return object.isObject() && object.isMember(key); }
int narrow(int64_t value) { return std::bit_cast<int32_t>(static_cast<uint32_t>(value)); }
std::string lower(std::string text) {
    for (auto& c : text) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return text;
}
std::string decimal(int64_t value) { return std::to_string(value); }
std::string java_bool(bool value) { return value ? "true" : "false"; }
// StringUtils.pathJoin
std::string path_join(std::string base, std::string child) {
    if (!base.empty() && base.back() == '/') base.pop_back();
    if (!child.empty() && child.front() == '/') child.erase(0, 1);
    return base + "/" + child;
}
template <typename... Rest> std::string path_join(std::string base, std::string child, Rest... rest) {
    return path_join(path_join(std::move(base), std::move(child)), std::move(rest)...);
}
// String.trim
std::string trim(const std::string& text) {
    size_t first = 0, last = text.size();
    while (first < last && static_cast<unsigned char>(text[first]) <= 0x20) ++first;
    while (last > first && static_cast<unsigned char>(text[last - 1]) <= 0x20) --last;
    return text.substr(first, last - first);
}
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
// String.hashCode over UTF-16 units.
uint32_t java_hash(const std::string& text) {
    uint32_t hash = 0;
    int32_t offset = 0, length = static_cast<int32_t>(text.size());
    while (offset < length) {
        UChar32 c;
        U8_NEXT(text.data(), offset, length, c);
        if (c < 0) c = 0xfffd;
        if (c > 0xffff) {
            hash = 31 * hash + U16_LEAD(c);
            hash = 31 * hash + U16_TRAIL(c);
        } else hash = 31 * hash + static_cast<uint32_t>(c);
    }
    return hash;
}
// DataItem iteration: array elements, or object values in the HashMap order a
// sequentially filled map has. Ties within one bucket fall back to key order,
// since jsoncpp does not keep the source order.
std::vector<const Json::Value*> items(const Json::Value& value) {
    std::vector<const Json::Value*> out;
    if (value.isArray()) {
        for (const auto& entry : value) out.push_back(&entry);
        return out;
    }
    if (!value.isObject()) return out;
    const auto names = value.getMemberNames();
    uint32_t capacity = 16;
    while (names.size() > capacity / 4 * 3) capacity *= 2;
    std::vector<std::pair<uint32_t, size_t>> order;
    for (size_t i = 0; i < names.size(); ++i) {
        auto hash = java_hash(names[i]);
        order.emplace_back((hash ^ (hash >> 16)) & (capacity - 1), i);
    }
    std::stable_sort(order.begin(), order.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
    for (const auto& [bucket, index] : order) out.push_back(&value[names[index]]);
    return out;
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
}

// --- VMScreenConfig ---
struct Screen {
    std::string id;
    const Json::Value* item;
    bool enabled() const { return boolean(*item, "enabled", false); }
    std::string exporter() const { return java_enum(*item, "exporter", "NONE", exporters); }
    bool input_enabled() const { return boolean(*item, "input_enabled", true); }
};
std::optional<Screen> find_screen(const Json::Value& config, const char* id) {
    const auto& screens = member(config, "screens");
    if (!screens.isObject() || !screens[id].isObject()) return std::nullopt;
    return Screen{id, &screens[id]};
}
std::vector<Screen> screens_of(const Json::Value& config) {
    std::vector<Screen> out;
    for (const char* id : {gpu0, simplefb}) if (auto screen = find_screen(config, id)) out.push_back(*screen);
    return out;
}
bool screen_enabled(const Json::Value& config, const char* id) {
    const auto screen = find_screen(config, id);
    return screen && screen->enabled();
}
bool has_gpu_device(const Json::Value& config) { return screen_enabled(config, gpu0); }
// DisplayTransportCap.optionsFor; tokens double as identities.
std::vector<const char*> transport_options(const std::string& id, const std::string& exporter) {
    if (exporter == "NATIVE") return id == gpu0 ? std::vector<const char*>{"cpu", "gpu", "zero"} : std::vector<const char*>{"cpu", "gpu"};
    if (exporter == "VNC") return {"cpu", "gpu", "gpu-hw"};
    return {};
}
bool transport_implemented(const std::string& exporter, const std::string& cap) {
    if (exporter == "NATIVE") return cap == "cpu" || cap == "gpu";
    if (exporter == "VNC") return cap == "cpu" || cap == "gpu" || cap == "gpu-hw";
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
        if (exporter == "NATIVE" || (exporter == "VNC" && transport_cap(screen) != "cpu")) return true;
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
// VMHypervisor.valueOf(hyp.toUpperCase()) + resolveConfigured(CROSVM, ...)
std::optional<std::string> resolve_hypervisor(const Json::Value& item, const HostFacts& host) {
    std::string configured = "AUTO";
    if (member(item, "hypervisor").isString()) {
        configured = java_enum(item, "hypervisor", "", hypervisors);
        if (configured.empty()) throw std::invalid_argument("No enum constant VMHypervisor." + member(item, "hypervisor").asString());
    }
    if (configured != "AUTO") return configured;
    if (host.has_kvm) return "KVM";
    if (host.has_gunyah) return "GUNYAH";
    if (host.has_gzvm) return "GENIEZONE";
    return std::nullopt;
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

struct Builder {
    const Json::Value& item;
    const CrosvmRun& run;
    const BootPlan& boot;
    const HostFacts& host;
    std::string data_dir;
    std::vector<std::string> args;
    std::string vm_id() const { return config::uuid(item); }
    std::string run_path() const { return path_join(data_dir, "run"); }

    void strace(CrosvmLaunch& launch) {
        if (!boolean(item, "strace", false)) return;
        std::optional<std::string> binary;
        if (host.strace_prebuilt_exists) binary = path_join(data_dir, "usr", "bin", "strace");
        else binary = host.strace_in_path;
        if (!binary) return;
        const auto dir = path_join(data_dir, "cache", "strace-" + vm_id());
        launch.strace_dir = dir;
        for (auto arg : {*binary, std::string("-Tttrvyyff"), std::string("-s"), std::string("8192"), std::string("-o"), path_join(dir, "strace.log")})
            args.push_back(std::move(arg));
    }
    void hypervisor_args(const std::string& hypervisor, std::string& def_protected) {
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
        if (gfxstream) {
            const bool udmabuf = boolean(item, "gpu_udmabuf", true);
            const auto host_pool = integer(item, "gpu_host_pool_mb", 0);
            if (host_pool > 0 || udmabuf) {
                auto pre_alloc = "gfx-host-mb=" + decimal(host_pool);
                if (udmabuf) guest_pool_options(pre_alloc, item, guest_pool);
                args.push_back("--pre-alloc");
                args.push_back(pre_alloc);
            }
        }
        const auto pool_args = [&](const char* key, int64_t pool) {
            std::string pre_alloc;
            if (pool > 0) pre_alloc += std::string(key) + "=" + decimal(pool);
            guest_pool_options(pre_alloc, item, guest_pool);
            if (pre_alloc.empty()) return;
            args.push_back("--pre-alloc");
            args.push_back(pre_alloc);
        };
        if (drm2kgsl) pool_args("drm-host-mb", integer(item, "gpu_drm2kgsl_pool_mb", 0));
        if (venus) pool_args("venus-host-mb", integer(item, "gpu_venus_pool_mb", 256));
        def_protected = "PROTECTED_WITHOUT_FIRMWARE";
    }
    void disks() {
        if (!present(item, "disks")) return;
        for (const auto* disk : items(item["disks"])) {
            auto path = string(*disk, "path", "");
            if (path.empty()) continue;
            constexpr std::string_view prefix = "/storage/emulated/";
            if (host.optimize_sdcard && path.starts_with(prefix)) path = "/data/media/" + path.substr(prefix.size());
            const bool readonly = boolean(*disk, "readonly", false);
            const auto bus = java_enum(*disk, "bus", "VIRTIO", disk_buses);
            auto arg = path;
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
                args.push_back("--block");
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
        const auto& vnc = member(*screen.item, "vnc");
        const auto& stored = vnc.isObject() ? vnc : Json::Value::nullSingleton();
        auto host_name = string(stored, "host", "");
        auto port = integer(stored, "port", -1);
        auto password = string(stored, "password", "");
        if (const auto at = run.vnc.find(screen.id); at != run.vnc.end()) {
            if (at->second.host) host_name = *at->second.host;
            if (at->second.port) port = *at->second.port;
            if (at->second.password) password = *at->second.password;
        }
        std::string arg;
        if (!host_name.empty()) arg += "host=" + host_name + ",";
        arg += "port=" + decimal(std::max<int64_t>(port, 1));
        if (!password.empty()) arg += ",password=" + password;
        arg += ",view-only=" + java_bool(!screen.input_enabled());
        arg += ",screen=" + screen.id;
        return arg;
    }
    void exporters_args() {
        for (const auto& screen : screens_of(item)) {
            if (!screen.enabled()) continue;
            const auto exporter = screen.exporter();
            if (exporter == "NATIVE") {
                args.push_back("--android-display-service");
                args.push_back("name=droidvm_disp_" + vm_id() + "_" + screen.id + ",screen=" + screen.id + transport_cap_arg(screen));
            } else if (exporter == "VNC") {
                args.push_back("--vnc-server");
                args.push_back(vnc_arg(screen) + transport_cap_arg(screen));
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
    void inputs(CrosvmLaunch& launch) {
        for (const auto& screen : screens_of(item)) {
            if (!screen.enabled() || screen.exporter() == "NONE" || !screen.input_enabled()) continue;
            launch.touch_screens.push_back(screen.id);
            if (screen.exporter() == "NATIVE") launch.native_input_screens.push_back(screen.id);
        }
        args.push_back("--input");
        args.push_back("mouse[path=" + socket_path("", "ms", false) + "]");
        const auto& natives = launch.native_input_screens;
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
    // HostAudioTable.PATH; the dump path is a literal in the Java too.
    std::string sound_config(const std::vector<const Json::Value*>& endpoints, const Json::Value& peripheral) const {
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
    void peripherals() {
        const auto& list = member(item, "peripherals");
        if (!list.isArray()) return;
        static const Json::Value empty_object(Json::objectValue);
        for (const auto& peripheral : list) {
            // XHCI_USB and the unbacked types only log.
            if (java_enum(peripheral, "type", "VIRTIO_SOUND", peripheral_types) != "VIRTIO_SOUND") continue;
            if (host.app_uid <= 0) continue;
            std::vector<const Json::Value*> endpoints;
            const auto& rows = member(peripheral, "endpoints");
            if (present(peripheral, "endpoints")) {
                const auto size = rows.isArray() || rows.isObject() ? rows.size() : 0;
                for (Json::ArrayIndex i = 0; i < size; ++i) endpoints.push_back(rows.isArray() ? &rows[i] : &empty_object);
            }
            if (endpoints.empty()) continue;
            args.push_back("--virtio-snd");
            args.push_back(sound_config(endpoints, peripheral));
        }
    }
    void serials() {
        const auto& ports = member(item, "serial_ports");
        if (!ports.isArray()) return;
        struct Arg { std::string type = "sink"; std::optional<std::string> path, input; bool interactive = false; };
        std::vector<Arg> resolved;
        std::vector<const Json::Value*> list;
        for (Json::ArrayIndex i = 0; i < ports.size(); ++i) {
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
    }
    void extra_options() {
        if (!present(item, "extra_options")) return;
        const auto& extra = item["extra_options"];
        if (extra.isNull()) return;
        if (!extra.isArray() && !extra.isObject()) throw std::runtime_error("Cannot iterate over extra_options");
        for (const auto* arg : items(extra)) {
            if (!arg->isString()) throw std::runtime_error("Expected type STRING");
            args.push_back(arg->asString());
        }
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
        const auto hypervisor = resolve_hypervisor(item, host);
        if (!hypervisor) throw std::runtime_error("No supported hypervisor found for CROSVM backend");
        std::string def_protected = "PROTECTED_NORMAL";
        hypervisor_args(*hypervisor, def_protected);
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
        if (!xhci) args.push_back("--no-usb");
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
        exporters_args();
        for (const auto& screen : screens_of(item)) launch.input_bridge = launch.input_bridge || (screen.enabled() && screen.exporter() != "NONE");
        if (launch.input_bridge) inputs(launch);
        peripherals();
        serials();
        extra_options();
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
        // VMBackendInstance.prepareProcess
        env.emplace_back("LD_PRELOAD", path_join(data_dir, "lib", "libsimpledump.so") + ":" + path_join(data_dir, "lib", "libcompat_a" + host.android_release + ".so"));
        env.emplace_back("LD_LIBRARY_PATH", path_join(data_dir, "usr", "lib"));
        const auto& configured = member(item, "environment_variables");
        if (configured.isArray()) {
            for (const auto& entry : configured) {
                if (!entry.isString()) continue;
                const auto raw = trim(entry.asString());
                const auto separator = raw.find('=');
                if (separator == std::string::npos || separator == 0) continue;
                const auto key = trim(raw.substr(0, separator));
                if (key.empty()) continue;
                env.emplace_back(key, raw.substr(separator + 1));
            }
        }
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
    }
};
}

CrosvmLaunch crosvm_command(const Json::Value& config, const CrosvmRun& run, const BootPlan& boot, const HostFacts& host) {
    if (!config.isObject()) throw std::invalid_argument("VM config must be an object");
    Builder builder{config, run, boot, host, host.data_dir.empty() ? std::string("/data/data/" DROIDVM_PACKAGE_NAME) : host.data_dir, {}};
    CrosvmLaunch launch;
    builder.command(launch);
    launch.argv = std::move(builder.args);
    builder.environment(launch);
    return launch;
}
}
