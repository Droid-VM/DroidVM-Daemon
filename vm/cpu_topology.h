// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace droidvm::vm {
struct HostCpuCore {
    int index;
    int64_t max_frequency_khz = 0;
    int64_t capacity = 0;
    bool capacity_estimated = false;
    std::optional<bool> online;
};
// Read-only sysfs observation. Only the legacy launch caller requests fallback
// identities; the Web catalogue must never invent host core identities.
std::vector<HostCpuCore> read_cpu_topology(
    const std::string& root = "/sys/devices/system/cpu", int fallback_count = 0);
}
