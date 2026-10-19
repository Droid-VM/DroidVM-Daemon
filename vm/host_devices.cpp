// SPDX-License-Identifier: GPL-3.0-or-later
#include "host_devices.h"
#include <filesystem>

namespace droidvm::vm {
namespace {
std::optional<bool> present(const std::filesystem::path& path, bool regular = false) {
    std::error_code error;
    const auto status = std::filesystem::status(path, error);
    if (error == std::errc::no_such_file_or_directory || error == std::errc::not_a_directory) return false;
    if (error) return {};
    return regular ? std::filesystem::is_regular_file(status) : std::filesystem::exists(status);
}
}
HostDeviceFacts probe_host_devices(const std::string& data_directory, const std::string& device_root,
    const std::string& hal_root) {
    namespace fs = std::filesystem;
    HostDeviceFacts result;
    result.kvm = present(fs::path(device_root) / "kvm");
    result.gunyah = present(fs::path(device_root) / "gunyah");
    result.geniezone = present(fs::path(device_root) / "gzvm");
    result.kgsl = present(fs::path(device_root) / "kgsl-3d0");
    result.turnip = present(fs::path(data_directory) / "usr/lib/libvulkan_freedreno.so", true);
    std::error_code error;
    fs::directory_iterator cursor(hal_root, error), end;
    if (error == std::errc::no_such_file_or_directory || error == std::errc::not_a_directory) {
        result.system_vulkan = false;
        return result;
    }
    if (error) return result;
    size_t entries = 0;
    bool uncertain = false;
    while (cursor != end && !error) {
        if (++entries > 16384) return result;
        const auto name = cursor->path().filename().string();
        // Same software fallback exclusions as the original launch probe.
        if (name.starts_with("vulkan.") && name.ends_with(".so") &&
            name.find("lvp") == std::string::npos && name.find("swiftshader") == std::string::npos &&
            name.find("pastel") == std::string::npos) {
            const auto available = present(cursor->path(), true);
            if (available == true) {
                result.system_vulkan = true;
                result.system_vulkan_hal = cursor->path().string();
                return result;
            }
            uncertain |= !available.has_value();
        }
        cursor.increment(error);
    }
    if (!error && !uncertain) result.system_vulkan = false;
    return result;
}
}
