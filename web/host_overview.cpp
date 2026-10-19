// SPDX-License-Identifier: GPL-3.0-or-later
#include "host_overview.h"
#include "services/context.h"
#include <cmath>

namespace droidvm::web {
namespace {
Json::Value bytes(const std::optional<uint64_t>& value) {
    return value ? Json::Value(std::to_string(*value)) : Json::Value();
}
Json::Value count(const std::optional<uint32_t>& value) {
    return value ? Json::Value(Json::UInt(*value)) : Json::Value();
}
Json::Value label(const std::optional<std::string>& value) {
    if (!value || value->empty() || value->size() > 256) return {};
    for (unsigned char c : *value) if (c < 0x20 || c == 0x7f) return {};
    return *value;
}
}
Json::Value host_overview_catalog(const HostOverview& value) {
    if (value.daemon.pid <= 0 || value.daemon.pid > 9007199254740991LL ||
        value.daemon.version.empty() || value.daemon.version.size() > 256)
        throw ServiceError(ErrorCode::unavailable, "Host overview cannot be represented");
    Json::Value result(Json::objectValue);
    result["observedAtMs"] = std::to_string(value.observed_at_ms);
    auto& host = result["host"];
    host["kernelRelease"] = label(value.host.kernel_release);
    host["machine"] = label(value.host.machine);
    host["deviceModel"] = label(value.host.device_model);
    host["socModel"] = label(value.host.soc_model);
    result["daemon"]["pid"] = Json::Int64(value.daemon.pid);
    result["daemon"]["version"] = value.daemon.version;
    auto& cpu = result["cpu"];
    cpu["logicalCount"] = value.cpu.logical_count && *value.cpu.logical_count ? count(value.cpu.logical_count) : Json::Value();
    cpu["usagePercent"] = Json::Value(); cpu["sampleWindowMs"] = Json::Value();
    if (value.cpu.usage_percent && std::isfinite(*value.cpu.usage_percent) &&
        *value.cpu.usage_percent >= 0 && *value.cpu.usage_percent <= 100 &&
        value.cpu.sample_window_ms && *value.cpu.sample_window_ms > 0 && *value.cpu.sample_window_ms <= 9007199254740991ULL) {
        cpu["usagePercent"] = *value.cpu.usage_percent;
        cpu["sampleWindowMs"] = Json::UInt64(*value.cpu.sample_window_ms);
    }
    auto& memory = result["memory"];
    memory["totalBytes"] = bytes(value.memory.total_bytes);
    memory["availableBytes"] = bytes(value.memory.available_bytes);
    if (value.memory.total_bytes && value.memory.available_bytes && *value.memory.available_bytes > *value.memory.total_bytes)
        memory["availableBytes"] = Json::Value();
    auto& storage = result["storage"];
    storage["totalBytes"] = bytes(value.storage.total_bytes);
    storage["freeBytes"] = bytes(value.storage.free_bytes);
    storage["availableBytes"] = bytes(value.storage.available_bytes);
    if (value.storage.total_bytes && value.storage.free_bytes && *value.storage.free_bytes > *value.storage.total_bytes)
        storage["freeBytes"] = Json::Value();
    if ((value.storage.total_bytes && value.storage.available_bytes && *value.storage.available_bytes > *value.storage.total_bytes) ||
        (value.storage.free_bytes && value.storage.available_bytes && *value.storage.available_bytes > *value.storage.free_bytes))
        storage["availableBytes"] = Json::Value();
    auto& inventory = result["inventory"];
    inventory["vmCount"] = count(value.inventory.vm_count);
    inventory["runningVmCount"] = count(value.inventory.running_vm_count);
    inventory["networkCount"] = count(value.inventory.network_count);
    inventory["runningNetworkCount"] = count(value.inventory.running_network_count);
    inventory["diskCount"] = count(value.inventory.disk_count);
    inventory["diskVirtualBytes"] = bytes(value.inventory.disk_virtual_bytes);
    inventory["diskVirtualKnownCount"] = count(value.inventory.disk_virtual_known_count);
    inventory["diskVirtualObservedAtMs"] = bytes(value.inventory.disk_virtual_observed_at_ms);
    return result;
}
}
