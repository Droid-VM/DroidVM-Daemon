// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "services/system.h"
#include "services/tasks.h"
#include "services/network_config.h"
#include "services/network_host.h"
#include "services/network.h"

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
    RequestDispatcher(SystemService& system, TaskService& tasks, NetworkConfigService* networks = nullptr,
                      NetworkHostService* host_network = nullptr, NetworkService* runtime = nullptr)
        : system_(system), tasks_(tasks), networks_(networks), host_network_(host_network), runtime_(runtime) {}
    bool has_maintenance() const { return runtime_ != nullptr; }
    void maintenance() { if (runtime_) runtime_->schedule_reconcile(tasks_); }
    bool background(const std::string& command) const;
    Json::Value execute_background(const CallContext& caller, const std::string& command, const Json::Value& request);
    TaskService& workers() { return tasks_; }
    Json::Value execute(ClientSession& session, const std::string& command, const Json::Value& request);
    std::optional<Json::Value> events(ClientSession& session);
    void disconnected(ClientSession& session) noexcept;
private:
    SystemService& system_;
    TaskService& tasks_;
    NetworkConfigService* networks_;
    NetworkHostService* host_network_;
    NetworkService* runtime_;
};
}
