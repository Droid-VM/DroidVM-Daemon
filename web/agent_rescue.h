// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "agent/rescue_sessions.h"
#include "http_api.h"
#include "services/tasks.h"

namespace droidvm::web {
// Existing registry and TaskService own all lifetimes; no new threads, timers,
// console buffers, task registry or VM owner is introduced by this adapter.
AgentRescueOperations agent_rescue(TaskService& tasks, agent::RescueSessions& sessions,
    agent::RescueSessions::Now now = [] { return agent::RunnerClock::now(); });
bool valid_rescue_session_id(std::string_view id) noexcept;
Json::Value project_agent_rescue_cleanup(const Json::Value& result);
}
