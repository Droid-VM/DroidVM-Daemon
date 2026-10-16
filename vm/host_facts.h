// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "vm/crosvm_command.h"
#include <optional>
#include <string>
#include <sys/types.h>

namespace droidvm::vm {
// Reads the host the way the legacy daemon does (as root) for one launch.
struct HostProbe {
    uid_t app_uid = 0; // Os.stat(DATA_DIR).st_uid, the package manager's answer
    std::string gid_cache; // AppGroups CACHE_PATH, under the daemon's run directory
    bool optimize_sdcard = true; // appConfig KEY_OPTIMIZE_SDCARD
    std::string vars_path; // pflash vars file whose size picks the block size
};
HostFacts probe_host(const HostProbe& probe);
// HostSocName.get: SoC property, marketing name from the app's chip table.
std::optional<std::string> host_soc_name();
std::optional<std::vector<int>> app_groups(uid_t uid, const std::string& cache);
std::vector<CpuCore> cpu_cores(const std::string& root = "/sys/devices/system/cpu");
std::string system_property(const char* name);
// CrosvmBackendInstance.prepareGpuCgroup without a shell: the cpuset path
// crosvm may join, or empty (soft failure, reason in warning).
std::optional<std::string> prepare_gpu_cgroup(const Json::Value& config, std::string& warning);
}
