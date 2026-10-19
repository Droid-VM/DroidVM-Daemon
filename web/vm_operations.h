// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include "services/tasks.h"
#include "vm/observation.h"

namespace droidvm::web {
struct VmOperation {
    std::string request_id, vm_id, action;
    vm::Observation observed;
    std::string config_revision;
};
// Values only; the existing background task pool owns work after HTTP disconnect.
using ApplyVmOperation = std::function<void(const CallContext&, const VmOperation&)>;
VmOperations vm_operations(TaskService& tasks, ApplyVmOperation apply);
}
