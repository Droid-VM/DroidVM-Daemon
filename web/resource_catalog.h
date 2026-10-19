// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "services/config_snapshot.h"
#include "vm/cpu_topology.h"
#include "vm/host_devices.h"
#include <functional>
#include <optional>
#include <set>

namespace droidvm::web {
// The production binding supplies the existing native disk path/chain helpers.
// No filesystem probing, image process, credential or persistence in this view.
Json::Value disk_catalog(const DiskConfigSnapshot& snapshot,
    const std::function<std::string(const Json::Value&)>& path,
    const std::set<std::string>& valid_paths, const std::set<std::string>& backing_paths);
Json::Value network_catalog(const Json::Value& active);
Json::Value audio_catalog(const Json::Value& snapshot);
Json::Value usb_catalog(const Json::Value& snapshot);
Json::Value cpu_catalog(const std::vector<vm::HostCpuCore>& cores);
Json::Value host_device_catalog(const vm::HostDeviceFacts& facts, const Json::Value& system_blit);
Json::Value disk_detail(const Json::Value& catalog, const VmConfigSnapshot& vms,
    const std::string& id, const std::string& state, const Json::Value& image,
    const std::optional<std::string>& effective_compression = std::nullopt);
}
