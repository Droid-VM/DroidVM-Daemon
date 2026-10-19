// SPDX-License-Identifier: GPL-3.0-or-later
#include "vm_lifecycle.h"

namespace droidvm {
VmLifecycleService::VmLifecycleService(Dependencies dependencies) : dependencies_(std::move(dependencies)) {
    if (!dependencies_.snapshot || !dependencies_.confirm_durable || !dependencies_.protection_override_supported || !dependencies_.start)
        throw std::invalid_argument("Missing VM lifecycle dependencies");
}
ConfiguredVmStartAdmission VmLifecycleService::start(const CallContext& caller, const ConfiguredVmStart& request) const {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || caller.principal.empty()) throw ServiceError(ErrorCode::permission_denied, "Administrator permission required");
    if (request.revision.empty() || request.vm_id.empty()) throw ServiceError(ErrorCode::invalid_argument, "Missing revision or VM ID");
    if (request.boot_entry.size() > (64u << 10)) throw ServiceError(ErrorCode::invalid_argument, "Invalid boot entry");
    if (!request.overrides.isNull() && !request.overrides.isObject()) throw ServiceError(ErrorCode::invalid_argument, "Invalid start overrides");
    auto snapshot = dependencies_.snapshot(caller);
    if (!snapshot || !snapshot->document["vms"].isArray()) throw ServiceError(ErrorCode::unavailable, "VM configuration unavailable");
    if (snapshot->revision != request.revision) throw ServiceError(ErrorCode::conflict, "VM configuration changed; reload before starting");
    if (snapshot->durability_uncertain) {
        // Sync precisely the observed document. A newer revision is a conflict,
        // never an instruction to silently reload and start another definition.
        snapshot = dependencies_.confirm_durable(caller, snapshot);
        if (!snapshot || snapshot->durability_uncertain) throw ServiceError(ErrorCode::commit_uncertain, "VM configuration durability is uncertain");
    }
    for (const auto& row : snapshot->document["vms"]) if (row["id"] == request.vm_id) {
        if (request.overrides.isMember("pseudo_unprotected") && !dependencies_.protection_override_supported(row))
            throw ServiceError(ErrorCode::invalid_argument, "Protection override requires crosvm with Gunyah");
        if (!dependencies_.start(caller, request, row))
            throw ServiceError(ErrorCode::conflict, "VM start was not admitted; reload state before retrying");
        return {request.vm_id, request.revision, snapshot->revision != request.revision ? snapshot->revision : std::string()};
    }
    throw ServiceError(ErrorCode::not_found, "VM not found");
}
}
