// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "agent/plan.h"
#include "agent/runner.h"
#include <string>

namespace droidvm { class ConfigurationService; class TaskControl; struct CallContext; }
namespace droidvm::agent {
class RescueSessions;
struct Confirmation {
    std::string disk_revision, vm_revision;
};
struct NativeResult {
    RunnerResult execution;
    // Retained for trusted cleanup/recovery if removal could not complete.
    std::string managed_vm_id;
    // Internal custody receipt; never a VM ID or an implicit public capability.
    std::string rescue_session_id;
};
struct NativeRunOptions {
    // Opt-in only. Caller owns the sessions through all accepted work and must
    // close/expire them before runtime dependencies are destroyed. HTTP uses
    // this only after explicit rescue opt-in; default is automatic cleanup.
    RescueSessions* rescue_sessions = nullptr;
};
// Internal synchronous adapter for an existing background TaskService worker.
// No HTTP registration or nested task submission. data_dir is trusted startup
// configuration, never an action field; built-in assets are resolved below it.
// ConfigurationService must outlive accepted work. Retained reservations have
// independent state for safe teardown, but failed managed VMs still need recovery.
// The fixed wrapper finalizes guest mounts before host cleanup; retained writable
// inodes are fsynced after stop/retire while our reservation remains held.
// Public rescue sessions expose a separate ID, never the managed VM identity.
NativeResult run_managed(ConfigurationService& configuration, const CallContext& caller,
    Request request, const Confirmation& confirmed, const std::string& data_dir,
    TaskControl& control, NativeRunOptions options = {});
}
