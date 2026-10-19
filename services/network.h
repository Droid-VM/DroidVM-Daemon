// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "network_config.h"
#include "network_state.h"
#include "network/backend.h"
#include "network/forwarding.h"
#include <chrono>
#include <functional>
#include <deque>

namespace droidvm {
class TaskService;
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
    // Browser confirmation is checked under the same operation lock as the
    // effect. Start additionally compares configuration under its writer lock
    // before acquiring the runtime lease; stop uses that writer lock directly.
    NetworkView change_if_matches(const CallContext& caller, const std::string& id, bool start,
        uint64_t generation, NetworkState expected_state, const std::string& configuration_revision);
    // Owner schedules bounded worker ticks; no hidden unbounded watchdog thread.
    // Healthy backends refresh every five seconds. Refresh failures retain the
    // config lease and retry; unhealthy backends recover with the same backoff.
    NetworkView reconcile(const CallContext& caller, const std::string& id);
    Json::Value tool_log(const CallContext& caller, const std::string& id, const std::string& key);
    void schedule_reconcile(TaskService& workers); // event-loop caller, no backend I/O
    void request_autostart(const CallContext& caller); // once, before serving
    bool autostart_settled(); // every auto_up network was tried
    // VMInstance.setupTap: a stopped network is started first. The NIC is
    // already sanitized and validated against this network's config.
    void attach_nic(const CallContext& caller, const std::string& id, const Json::Value& nic, const std::string& tap);
    void detach_nic(const CallContext& caller, const std::string& id, const Json::Value& nic, const std::string& tap);
    Json::Value forward_failures(const CallContext& caller, const std::string& id);
    // InfoHandler's RUNNING-only lists and appendInfo; empty when busy or not running.
    Json::Value live(const CallContext& caller, const std::string& id);
    // Cached actual DHCP leases, at most 15s old; no backend I/O or operation wait.
    // Null is unknown. Private/static reservations are never synthesized here.
    Json::Value observed_leases(const CallContext& caller, const std::string& id);
    bool pd_action(const CallContext& caller, const std::string& id, int vlan, bool release);
    bool manual(const CallContext& caller, const std::string& id, bool address, const std::string& value, bool add);
    // NetworkInstance.findRunningVMUsing: a running VM's name blocks a user stop.
    void set_in_use(std::function<std::string(const std::string& id)> in_use) { in_use_ = std::move(in_use); }
    Json::Value shutdown(); // attempts every network, reports cleanup failures
private:
    friend class ConfigurationService;
    struct Slot;
    struct Access;
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
    bool autostart_running_ = false;
    std::function<std::string(const std::string&)> in_use_;
    Access slot(const CallContext& caller, const std::string& id);
    std::shared_ptr<Slot> cleanup_slot(const CallContext& caller, const std::string& id);
    // Coordinator holds exclusive configuration gate and affected VM leases.
    // Bypass public lookup/in_use callbacks, which would re-enter those locks.
    void stop_for_delete(const std::string& id);
    static void stop_slot(Slot& slot);
    static NetworkView view(Slot& slot);
    static void state(Slot& slot, NetworkState state, bool desired, std::string error = {});
    static void cleanup(Slot& slot);
    void observe_leases(Slot& slot); // worker, operation held; failures only invalidate telemetry
    struct Expectation { uint64_t generation; NetworkState state; std::string revision; };
    NetworkView start_impl(const CallContext& caller, const std::string& id, bool only_initial, const Expectation* expected = nullptr);
    NetworkView stop_impl(const CallContext& caller, const std::string& id, const Expectation* expected = nullptr);
    static void check_expected(Slot& slot, const Expectation& expected);
};
}
