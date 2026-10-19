// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include "services/tasks.h"

namespace droidvm::web {
using ExecuteDiskOperation = std::function<TaskCompletion(const CallContext&, const Json::Value&, TaskControl&)>;
BackgroundOperations disk_operations(TaskService& tasks, ExecuteDiskOperation execute);
DiskRecoveryOperations disk_recovery(TaskService& tasks,
    std::function<size_t(const CallContext&)> pending,
    std::function<Json::Value(const CallContext&)> recover);
}
