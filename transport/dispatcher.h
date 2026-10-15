// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "services/system.h"
#include "services/tasks.h"

namespace droidvm {
struct ClientSession {
    Caller caller;
    std::string subscription;
    uint64_t cursor = 0;
};
// Existing system/legacy shapes stay in their adapter; new task commands expose
// structured errors and decimal cursors without changing old command results.
class RequestDispatcher {
public:
    RequestDispatcher(SystemService& system, TaskService& tasks) : system_(system), tasks_(tasks) {}
    Json::Value execute(ClientSession& session, const std::string& command, const Json::Value& request);
    std::optional<Json::Value> events(ClientSession& session);
    void disconnected(ClientSession& session) noexcept;
private:
    SystemService& system_;
    TaskService& tasks_;
};
}
