// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "agent/native.h"
#include "http_api.h"
#include "services/tasks.h"

namespace droidvm::web {
using ExecuteAgentOperation = std::function<agent::NativeResult(const CallContext&, agent::Request,
    const agent::Confirmation&, TaskControl&, bool rescue)>;
// New nonce per POST: a request ID may only be submitted once. After a lost
// response, use find rather than resubmitting a password or destructive action.
BackgroundOperations agent_operations(TaskService& tasks, ExecuteAgentOperation execute,
    TaskService::Now now = [] { return TaskService::Clock::now(); });
DiskRecoveryOperations agent_recovery(TaskService& tasks,
    std::function<size_t(const CallContext&)> pending,
    std::function<Json::Value(const CallContext&)> recover);

// Strict operation-specific allowlist. Returns null on an invalid receipt;
// callers must NEVER fall back to projecting the original raw task result.
Json::Value project_agent_result(const Json::Value& result);
}
