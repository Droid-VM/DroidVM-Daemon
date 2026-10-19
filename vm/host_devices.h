// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <optional>
#include <string>

namespace droidvm::vm {
struct HostDeviceFacts {
    std::optional<bool> kvm, gunyah, geniezone, kgsl, turnip, system_vulkan;
    std::optional<std::string> system_vulkan_hal;
};
// Metadata observation only; presence is not a successful driver/device test.
HostDeviceFacts probe_host_devices(const std::string& data_directory,
    const std::string& device_root = "/dev", const std::string& hal_root = "/vendor/lib64/hw");
}
