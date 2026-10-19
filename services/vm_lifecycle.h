// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "context.h"
#include "config_snapshot.h"
#include "vm/observation.h"
#include <functional>

namespace droidvm {
class VmConfigService;
class VmService;

struct ConfiguredVmStart {
    std::string revision, vm_id, boot_entry;
    Json::Value overrides;
    std::optional<bool> clear_logs = std::nullopt;
    std::optional<vm::Observation> observed = std::nullopt;
};
// Admission only: the existing VM worker may still be STARTING or fail later.
struct ConfiguredVmStartAdmission {
    std::string vm_id, revision, durable_revision;
};

// Shared application service for IPC and WebUI. Owns no VM, configuration,
// worker or file; all state and final admission remain with existing owners.
class VmLifecycleService {
public:
    using Snapshot = std::shared_ptr<const VmConfigSnapshot>;
    struct Dependencies {
        std::function<Snapshot(const CallContext&)> snapshot;
        std::function<Snapshot(const CallContext&, const Snapshot&)> confirm_durable;
        std::function<bool(const Json::Value&)> protection_override_supported;
        std::function<bool(const CallContext&, const ConfiguredVmStart&, const Json::Value&)> start;
    };
    // Production binding: reuse the coordinated config and live inventory.
    VmLifecycleService(VmConfigService& config, VmService& runtime);
    explicit VmLifecycleService(Dependencies dependencies);
    ConfiguredVmStartAdmission start(const CallContext& caller, const ConfiguredVmStart& request) const;
private:
    const Dependencies dependencies_;
};
}
