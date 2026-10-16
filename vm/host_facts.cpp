// SPDX-License-Identifier: GPL-3.0-or-later
// Host reads behind CrosvmBackendInstance: VMHypervisor, HostSocName,
// AppGroups, CpuUtils, resolveSystemVulkanHal and friends.
#include "host_facts.h"
#include "build_metadata.h"
#include "qcom_chips.h"
#include "store/network_config.h"
#include <algorithm>
#include <cerrno>
#include <climits>
#include <cmath>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <regex>
#include <set>
#include <sstream>
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
int64_t read_long(const std::string& path) {
    const auto raw = read_text(path);
    if (!raw) return 0;
    const auto text = trim(*raw);
    if (text.empty()) return 0;
    try { return config::java_long(text); } catch (const std::invalid_argument&) { return 0; }
}
std::string remove_all(std::string text, char c) { text.erase(std::remove(text.begin(), text.end(), c), text.end()); return text; }
std::optional<std::string> vulkan_hal() {
    DIR* dir = opendir("/vendor/lib64/hw");
    if (!dir) return {};
    std::optional<std::string> result;
    while (const auto* entry = readdir(dir)) {
        const std::string name = entry->d_name;
        if (!name.starts_with("vulkan.") || !name.ends_with(".so")) continue;
        // Skip the software fallbacks; the GPU driver is wanted.
        if (name.find("lvp") != std::string::npos || name.find("swiftshader") != std::string::npos ||
            name.find("pastel") != std::string::npos) continue;
        result = "/vendor/lib64/hw/" + name;
        break;
    }
    closedir(dir);
    return result;
}
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
    std::vector<int> indices;
    if (DIR* dir = opendir(root.c_str())) {
        static const std::regex pattern("cpu[0-9]+");
        while (const auto* entry = readdir(dir)) {
            const std::string name = entry->d_name;
            struct stat info{};
            if (!std::regex_match(name, pattern) || stat((root + "/" + name).c_str(), &info) != 0 || !S_ISDIR(info.st_mode)) continue;
            if (const auto index = java_int(name.substr(3))) indices.push_back(*index);
        }
        closedir(dir);
    }
    if (indices.empty()) {
        const auto count = std::max<long>(1, sysconf(_SC_NPROCESSORS_ONLN));
        for (long i = 0; i < count; ++i) indices.push_back(static_cast<int>(i));
    } else std::sort(indices.begin(), indices.end());
    std::vector<int64_t> frequencies, capacities;
    int64_t fastest = 0;
    for (const auto index : indices) {
        const auto cpu = root + "/cpu" + std::to_string(index);
        auto frequency = read_long(cpu + "/cpufreq/cpuinfo_max_freq");
        if (frequency <= 0) frequency = read_long(cpu + "/cpufreq/scaling_max_freq");
        frequencies.push_back(frequency);
        capacities.push_back(read_long(cpu + "/cpu_capacity"));
        fastest = std::max(fastest, frequency);
    }
    std::vector<CpuCore> result;
    for (size_t i = 0; i < indices.size(); ++i) {
        auto capacity = capacities[i];
        // No cpu_capacity: the frequency ratio, as arm64 without DT capacities.
        if (capacity <= 0 && frequencies[i] > 0 && fastest > 0)
            capacity = std::max<int64_t>(1, std::llround(1024.0 * static_cast<double>(frequencies[i]) / static_cast<double>(fastest)));
        result.push_back({indices[i], capacity});
    }
    return result;
}
HostFacts probe_host(const HostProbe& probe) {
    HostFacts host;
    host.has_kvm = exists("/dev/kvm");
    host.has_gunyah = exists("/dev/gunyah");
    host.has_gzvm = exists("/dev/gzvm");
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
    host.turnip_exists = exists(data_dir + "/usr/lib/libvulkan_freedreno.so");
    host.system_vulkan_hal = vulkan_hal();
    host.viosnd_dump_exists = exists("/data/local/tmp/viosnd_dump");
    return host;
}
}
