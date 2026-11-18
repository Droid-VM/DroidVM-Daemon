// SPDX-License-Identifier: GPL-3.0-or-later
// Host reads behind CrosvmBackendInstance: VMHypervisor, HostSocName,
// AppGroups, CpuUtils, resolveSystemVulkanHal and friends.
#include "host_facts.h"
#include "cpu_topology.h"
#include "host_devices.h"
#include "build_metadata.h"
#include "qcom_chips.h"
#include "vm/command_common.h"
#include "store/network_config.h"
#include "runtime/child.h"
#include <chrono>
#include <mutex>
#include <algorithm>
#include <cerrno>
#include <cctype>
#include <climits>
#include <cmath>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <linux/input.h>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <unistd.h>

namespace droidvm::vm {
namespace {
const std::string data_dir = "/data/data/" DROIDVM_PACKAGE_NAME;
bool exists(const std::string& path) { struct stat info{}; return stat(path.c_str(), &info) == 0; }
std::optional<std::string> read_text(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    return std::string((std::istreambuf_iterator<char>(input)), {});
}
std::string trim(const std::string& text) {
    size_t first = 0, last = text.size();
    while (first < last && static_cast<unsigned char>(text[first]) <= ' ') ++first;
    while (last > first && static_cast<unsigned char>(text[last - 1]) <= ' ') --last;
    return text.substr(first, last - first);
}
std::optional<int> java_int(const std::string& text) {
    try {
        const auto value = config::java_long(text);
        if (value < INT_MIN || value > INT_MAX) return {};
        return static_cast<int>(value);
    } catch (const std::invalid_argument&) { return {}; }
}
std::string remove_all(std::string text, char c) { text.erase(std::remove(text.begin(), text.end(), c), text.end()); return text; }
std::optional<std::string> find_in_path(const std::string& name) {
    const char* path = getenv("PATH");
    if (!path) return {};
    std::stringstream parts(path);
    std::string directory;
    while (std::getline(parts, directory, ':')) {
        while (!directory.empty() && directory.back() == '/') directory.pop_back();
        const auto candidate = directory + "/" + name;
        struct stat info{};
        if (stat(candidate.c_str(), &info) == 0 && S_ISREG(info.st_mode) && access(candidate.c_str(), X_OK) == 0) return candidate;
    }
    return {};
}
}
std::string system_property(const char* name) {
    char value[PROP_VALUE_MAX] = {};
    __system_property_get(name, value);
    return value;
}
std::optional<std::string> host_soc_name() {
    auto soc = trim(system_property("ro.vendor.qti.soc_model"));
    if (soc.empty()) soc = trim(system_property("ro.soc.model"));
    if (soc.empty()) return {};
    // QcomChipName.lookupChipName: strip separators, else the stripped id.
    const auto key = remove_all(remove_all(remove_all(soc, '-'), '_'), ' ');
    std::string name = key;
    for (const auto& [id, chip] : qcom_chips) if (key == id) name = chip;
    return !name.empty() && name != soc ? name : soc;
}
std::optional<std::vector<int>> app_groups(uid_t uid, const std::string& cache) {
    DIR* proc = opendir("/proc");
    if (proc) {
        std::optional<std::vector<int>> live;
        while (const auto* entry = readdir(proc)) {
            if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
            const std::string base = std::string("/proc/") + entry->d_name;
            struct stat info{};
            if (stat(base.c_str(), &info) != 0 || info.st_uid != uid) continue;
            auto cmdline = read_text(base + "/cmdline");
            if (!cmdline) continue;
            cmdline = cmdline->substr(0, cmdline->find('\0'));
            if (*cmdline != DROIDVM_PACKAGE_NAME) continue;
            const auto status = read_text(base + "/status");
            if (!status) continue;
            std::stringstream lines(*status);
            std::string line;
            while (std::getline(lines, line)) {
                if (!line.starts_with("Groups:")) continue;
                std::vector<int> gids;
                std::stringstream fields(line.substr(7));
                std::string field;
                while (fields >> field) if (const auto gid = java_int(field)) gids.push_back(*gid);
                live = gids;
                break;
            }
            if (live) break;
        }
        closedir(proc);
        if (live) {
            std::string text;
            for (size_t i = 0; i < live->size(); ++i) text += (i ? "," : "") + std::to_string((*live)[i]);
            std::ofstream(cache, std::ios::binary | std::ios::trunc) << text;
            return live;
        }
    }
    const auto stored = read_text(cache);
    if (!stored) return {};
    const auto text = trim(*stored);
    if (text.empty()) return {};
    std::vector<int> gids;
    std::stringstream fields(text);
    std::string field;
    while (std::getline(fields, field, ',')) {
        field = trim(field);
        if (field.empty()) continue;
        const auto gid = java_int(field);
        if (!gid) return {}; // Integer.parseInt failure discards the cache
        gids.push_back(*gid);
    }
    if (gids.empty()) return {};
    return gids;
}
std::vector<CpuCore> cpu_cores(const std::string& root) {
    std::vector<CpuCore> result;
    const auto fallback = static_cast<int>(std::clamp<long>(sysconf(_SC_NPROCESSORS_ONLN), 1, 4096));
    for (const auto& core : read_cpu_topology(root, fallback)) result.push_back({core.index, core.capacity, core.max_frequency_khz});
    return result;
}
std::optional<std::string> host_touchscreen(const std::string& directory) {
    std::vector<std::string> names;
    if (DIR* dir = opendir(directory.c_str())) {
        while (auto* entry = readdir(dir)) names.emplace_back(entry->d_name);
        closedir(dir);
    } else return std::nullopt;
    // "event10" must not sort before "event2": compare the numeric suffix.
    std::sort(names.begin(), names.end(), [](const std::string& a, const std::string& b) {
        const auto number = [](const std::string& name) { return name.size() > 5 ? java_int(name.substr(5)).value_or(INT_MAX) : INT_MAX; };
        return number(a) < number(b);
    });
    for (const auto& node : names) {
        if (!node.starts_with("event")) continue;
        const auto path = directory + "/" + node;
        const int raw = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (raw < 0) continue;
        unsigned long events[(EV_MAX + sizeof(long) * 8) / (sizeof(long) * 8)] = {};
        unsigned long axes[(ABS_MAX + sizeof(long) * 8) / (sizeof(long) * 8)] = {};
        const auto bit = [](const unsigned long* bits, unsigned index) { return (bits[index / (sizeof(long) * 8)] >> (index % (sizeof(long) * 8))) & 1u; };
        const bool touch = ioctl(raw, EVIOCGBIT(0, sizeof(events)), events) >= 0 && bit(events, EV_ABS) &&
            ioctl(raw, EVIOCGBIT(EV_ABS, sizeof(axes)), axes) >= 0 && bit(axes, ABS_MT_POSITION_X) && bit(axes, ABS_MT_POSITION_Y);
        close(raw);
        if (touch) return path;
    }
    return std::nullopt;
}
HostFacts probe_host(const HostProbe& probe) {
    HostFacts host;
    const auto devices = probe_host_devices(data_dir);
    host.has_kvm = devices.kvm.value_or(false);
    host.has_gunyah = devices.gunyah.value_or(false);
    host.has_gzvm = devices.geniezone.value_or(false);
    host.soc_name = host_soc_name();
    host.app_uid = static_cast<int>(probe.app_uid);
    if (host.app_uid > 0) host.app_gids = app_groups(probe.app_uid, probe.gid_cache);
    host.cpu_cores = cpu_cores();
    struct stat vars{};
    host.pflash_vars_size = !probe.vars_path.empty() && stat(probe.vars_path.c_str(), &vars) == 0 && S_ISREG(vars.st_mode) ? vars.st_size : 0;
    host.android_release = system_property("ro.build.version.release");
    host.strace_prebuilt_exists = exists(data_dir + "/usr/bin/strace");
    host.strace_in_path = find_in_path("strace");
    host.optimize_sdcard = probe.optimize_sdcard;
    host.turnip_exists = devices.turnip.value_or(false);
    host.system_vulkan_hal = devices.system_vulkan_hal;
    host.viosnd_dump_exists = exists("/data/local/tmp/viosnd_dump");
    // P1: the properties override the VM's own VpuConfig choice when set; an
    // absent property leaves the persisted per-VM vpu_* keys in charge.
    const auto media = trim(system_property("droidvm.virtiomedia"));
    if (!media.empty()) {
        auto lower = media;
        for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        host.virtio_media_override = !(lower == "0" || lower == "false" || lower == "off");
    }
    const auto media_mb = java_int(trim(system_property("droidvm.virtiomedia.hostmb")));
    if (media_mb && *media_mb > 0 && *media_mb <= 65536) host.virtio_media_host_mb_override = *media_mb;
    return host;
}
}
namespace droidvm::vm {
namespace {
void write_text(const std::string& path, const std::string& value) {
    std::ofstream out(path);
    out << value << '\n';
}
}
std::optional<std::string> prepare_gpu_cgroup(const Json::Value& config, std::string& warning) {
    warning.clear();
    if (!config::boolean(config, "gpu_cgroup_enabled") || !command::screen_enabled(config, "gpu-0")) return {};
    const auto& stored = config::member(config, "gpu_cgroup_path");
    const auto path = command::trim(stored.isString() ? stored.asString() : "/dev/cpuset/gpuworker");
    const auto cpus = command::trim(config::string(config, "gpu_cgroup_cpus"));
    if (path.empty() || path[0] != '/') { warning = "gpu-cgroup-path is not an absolute path: '" + path + "'; skipping"; return {}; }
    if (cpus.empty()) { warning = "gpu_cgroup_cpus is empty; cannot set up cpuset, skipping"; return {}; }
    // File.getParent; mems is copied from it (one NUMA node on Android).
    auto parent = path.substr(0, path.find_last_of('/'));
    if (path == "/") parent = "/dev/cpuset";
    else if (parent.empty()) parent = "/";
    auto failed = [&](const std::string& detail) -> std::optional<std::string> {
        warning = "Failed to set up gpuworker cpuset at " + path + " (cpus=" + cpus + "): " + detail;
        return {};
    };
    std::error_code error;
    std::filesystem::create_directories(path, error);
    struct stat info{};
    if (stat(path.c_str(), &info) != 0 || !S_ISDIR(info.st_mode)) return failed("mkdir failed");
    // cgroupfs files report size 0, so the script's [ ! -s ] always rewrites mems.
    for (const char* name : {"mems", "cpuset.mems"}) {
        const auto file = path + "/" + name;
        if (stat(file.c_str(), &info) != 0 || info.st_size != 0) continue;
        auto value = command::trim(read_text(parent + "/" + name).value_or(""));
        if (value.empty()) value = "0";
        write_text(file, value);
    }
    for (const char* name : {"cpus", "cpuset.cpus"}) {
        const auto file = path + "/" + name;
        if (access(file.c_str(), F_OK) == 0) write_text(file, cpus);
    }
    auto current = read_text(path + "/cpus");
    if (!current) current = read_text(path + "/cpuset.cpus");
    if (!current || command::trim(*current).empty()) return failed("cpus not set");
    return path;
}
}
namespace droidvm::vm {
bool host_has_gps_receiver() {
    // PackageManager.hasSystemFeature(FEATURE_LOCATION_GPS), asked once: the
    // feature list is fixed for the life of the boot.
    static std::mutex mutex;
    static std::optional<bool> cached;
    std::lock_guard lock(mutex);
    if (cached) return *cached;
    try {
        ChildOptions options;
        options.argv = {"/system/bin/pm", "has-feature", "android.hardware.location.gps"};
        const auto result = Child(options).communicate({}, std::chrono::seconds(15), 4096);
        if (result.timed_out) return false; // not cached: asked again next time
        cached = result.output.find("true") != std::string::npos;
    } catch (const std::exception&) {
        return false;
    }
    return *cached;
}
}
namespace droidvm::vm {
int64_t firmware_code_offset(const std::string& path) {
    unsigned char bytes[8];
    std::ifstream input(path, std::ios::binary);
    if (!input || !input.read(reinterpret_cast<char*>(bytes), sizeof(bytes))) return -1;
    const auto word = [&](int at) {
        return static_cast<uint32_t>(bytes[at]) | static_cast<uint32_t>(bytes[at + 1]) << 8 |
            static_cast<uint32_t>(bytes[at + 2]) << 16 | static_cast<uint32_t>(bytes[at + 3]) << 24;
    };
    const uint32_t code0 = word(0), code1 = word(4);
    // `adr x1, .` then a forward `b`: imm26 is signed, and one that branches back has no room.
    if (code0 != 0x10000001u || (code1 & 0xfe000000u) != 0x14000000u) return -1;
    return 4 + 4 * static_cast<int64_t>(code1 & 0x01ffffffu);
}
}
