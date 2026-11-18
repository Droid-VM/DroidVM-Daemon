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
// First evdev node reporting multi-touch absolute axes (the panel digitizer),
// in event-number order; nullopt when none is readable. Does not grab it.
std::optional<std::string> host_touchscreen(const std::string& directory = "/dev/input");
// CrosvmBackendInstance.prepareGpuCgroup without a shell: the cpuset path
// crosvm may join, or empty (soft failure, reason in warning).
std::optional<std::string> prepare_gpu_cgroup(const Json::Value& config, std::string& warning);
// Gnss.hostHasReceiver: the phone declares FEATURE_LOCATION_GPS (`pm
// has-feature`, as root, cached once answered). A VIRTIO_GNSS row on AUTO
// takes the receiver only when this holds, else the location alone.
bool host_has_gps_receiver();
// CrosvmBackendInstance.firmwareCodeOffset: where an EDK2 image of the
// arm64-Linux-header kind (edk2-gunyah's) starts its code -- its first word is
// `adr x1, .`, its second a `b` over the room PrePi copies the device tree
// into. -1 for a file that does not start that way or cannot be read.
int64_t firmware_code_offset(const std::string& path);
}
