// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "network_config.h"
#include "network/backend.h"
#include "network/forwarding.h"
#include <chrono>
#include <functional>
#include <deque>

namespace droidvm {
class TaskService;
enum class NetworkState { stopped, starting, running, recovering, stopping, failed };
const char* network_state_name(NetworkState state);
struct NetworkView {
    std::string id;
    NetworkState state = NetworkState::stopped;
    uint64_t generation = 0;
    std::string error;
    bool desired_running = false;
    Json::Value tools{Json::arrayValue};
};
// Backend operations run on caller workers with one operation per network.
// Independent networks can progress concurrently. Queries never wait for I/O.
// The owner stops/drains worker submissions before shutdown/destruction.
class NetworkService {
public:
    using Factory = std::function<std::unique_ptr<network::Backend>(const Json::Value&)>;
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;
    NetworkService(NetworkConfigService& configs, Factory factory, Now now = [] { return Clock::now(); });
    ~NetworkService();
    NetworkView get(const CallContext& caller, const std::string& id);
    NetworkView start(const CallContext& caller, const std::string& id);
    NetworkView stop(const CallContext& caller, const std::string& id);
    // Owner schedules bounded worker ticks; no hidden unbounded watchdog thread.
    // Healthy backends refresh every five seconds. Refresh failures retain the
    // config lease and retry; unhealthy backends recover with the same backoff.
    NetworkView reconcile(const CallContext& caller, const std::string& id);
    Json::Value tool_log(const CallContext& caller, const std::string& id, const std::string& key);
    void schedule_reconcile(TaskService& workers); // event-loop caller, no backend I/O
    void request_autostart(const CallContext& caller); // once, before serving
    Json::Value shutdown(); // attempts every network, reports cleanup failures
private:
    struct Slot;
    NetworkConfigService& configs_;
    Factory factory_;
    Now now_;
    network::Forwarding forwarding_;
    std::mutex mutex_;
    std::map<std::string, std::shared_ptr<Slot>> slots_;
    bool shutting_down_ = false;
    bool maintenance_pending_ = false;
    std::string maintenance_cursor_;
    Clock::time_point next_maintenance_{};
    std::deque<std::string> autostart_;
    std::shared_ptr<Slot> slot(const CallContext& caller, const std::string& id);
    static NetworkView view(Slot& slot);
    static void state(Slot& slot, NetworkState state, bool desired, std::string error = {});
    static void cleanup(Slot& slot);
    NetworkView start_impl(const CallContext& caller, const std::string& id, bool only_initial);
};
}
