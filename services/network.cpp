// SPDX-License-Identifier: GPL-3.0-or-later
#include "network.h"
#include "store/network_config.h"
#include "tasks.h"

namespace droidvm {
const char* network_state_name(NetworkState state) {
    switch (state) {
        case NetworkState::stopped: return "STOPPED";
        case NetworkState::starting: return "STARTING";
        case NetworkState::running: return "RUNNING";
        case NetworkState::recovering: return "RECOVERING";
        case NetworkState::stopping: return "STOPPING";
        case NetworkState::failed: return "FAILED";
    }
    return "FAILED";
}
struct NetworkService::Slot {
    std::mutex operation, observation;
    NetworkView view;
    std::unique_ptr<NetworkRuntimeLease> lease;
    std::unique_ptr<network::Forwarding::Lease> forwarding;
    std::unique_ptr<network::Backend> backend;
    Clock::time_point next_recovery{};
    Clock::time_point next_refresh{};
};
NetworkService::NetworkService(NetworkConfigService& configs, Factory factory, Now now)
    : configs_(configs), factory_(std::move(factory)), now_(std::move(now)) {
    if (!factory_ || !now_) throw std::invalid_argument("network lifecycle dependencies missing");
}
NetworkService::~NetworkService() { try { shutdown(); } catch (...) {} }
std::shared_ptr<NetworkService::Slot> NetworkService::slot(const CallContext& caller, const std::string& id) {
    const auto canonical = config::uuid(configs_.get(caller, id)); // authorization + existence
    std::lock_guard lock(mutex_);
    auto& result = slots_[canonical];
    if (!result) { result = std::make_shared<Slot>(); result->view.id = canonical; }
    return result;
}
NetworkView NetworkService::view(Slot& slot) { std::lock_guard lock(slot.observation); return slot.view; }
void NetworkService::state(Slot& slot, NetworkState state, bool desired, std::string error) {
    auto tools = slot.backend ? slot.backend->tools() : Json::Value(Json::arrayValue);
    std::lock_guard lock(slot.observation);
    slot.view.tools = std::move(tools);
    slot.view.state = state; slot.view.desired_running = desired;
    slot.view.error = error.substr(0, 4096); ++slot.view.generation;
}
NetworkView NetworkService::get(const CallContext& caller, const std::string& id) { return view(*slot(caller, id)); }
Json::Value NetworkService::tool_log(const CallContext& caller, const std::string& id, const std::string& key) {
    auto target = slot(caller, id);
    std::unique_lock operation(target->operation, std::try_to_lock);
    if (!operation.owns_lock()) throw ServiceError(ErrorCode::conflict, "Network operation already in progress");
    auto lines = target->backend ? target->backend->tool_log(key) : Json::Value();
    if (lines.isNull()) throw ServiceError(ErrorCode::not_found, "tool " + key + " not available");
    return lines;
}
void NetworkService::cleanup(Slot& slot) {
    if (slot.backend) slot.backend->stop();
    slot.backend.reset(); slot.forwarding.reset(); slot.lease.reset();
}
NetworkView NetworkService::start(const CallContext& caller, const std::string& id) {
    return start_impl(caller, id, false);
}
NetworkView NetworkService::start_impl(const CallContext& caller, const std::string& id, bool only_initial) {
    auto target = slot(caller, id);
    std::unique_lock operation(target->operation, std::try_to_lock);
    if (!operation.owns_lock()) throw ServiceError(ErrorCode::conflict, "Network operation already in progress");
    { std::lock_guard lock(mutex_); if (shutting_down_) throw ServiceError(ErrorCode::unavailable, "Network service is shutting down"); }
    if (only_initial && view(*target).generation != 0) return view(*target);
    if (view(*target).state == NetworkState::running) {
        if (target->backend && target->backend->healthy()) return view(*target);
        state(*target, NetworkState::failed, true, "Network backend exited; recovery required");
        throw ServiceError(ErrorCode::unavailable, view(*target).error);
    }
    if (target->lease || target->backend) throw ServiceError(ErrorCode::conflict, "Network requires cleanup before starting");
    state(*target, NetworkState::starting, true);
    try {
        target->lease = configs_.prepare_runtime(caller, id);
        target->backend = factory_(target->lease->config());
        if (!target->backend) throw std::runtime_error("Network backend unavailable");
        target->backend->start(target->lease->config());
        if (!target->backend->healthy()) throw std::runtime_error("Network backend is not ready");
        target->forwarding = forwarding_.acquire(target->lease->config());
        if (!target->backend->healthy()) throw std::runtime_error("Network backend is not ready");
        target->next_recovery = {};
        target->next_refresh = now_() + std::chrono::seconds(5);
        state(*target, NetworkState::running, true);
    } catch (const std::exception& error) {
        std::string detail = error.what();
        try { cleanup(*target); state(*target, NetworkState::stopped, false, detail); }
        catch (const std::exception& cleanup_error) {
            state(*target, NetworkState::failed, false, detail + "; cleanup: " + cleanup_error.what());
        }
        const auto* service_error = dynamic_cast<const ServiceError*>(&error);
        throw ServiceError(service_error ? service_error->code() : ErrorCode::unavailable, view(*target).error);
    }
    return view(*target);
}
NetworkView NetworkService::stop(const CallContext& caller, const std::string& id) {
    auto target = slot(caller, id);
    if (in_use_) if (const auto vm = in_use_(view(*target).id); !vm.empty())
        throw ServiceError(ErrorCode::conflict, "Network is in use by running VM " + vm);
    std::unique_lock operation(target->operation, std::try_to_lock);
    if (!operation.owns_lock()) throw ServiceError(ErrorCode::conflict, "Network operation already in progress");
    state(*target, NetworkState::stopping, false);
    try { cleanup(*target); state(*target, NetworkState::stopped, false); }
    catch (const std::exception& error) {
        state(*target, NetworkState::failed, false, error.what());
        throw ServiceError(ErrorCode::io_error, view(*target).error);
    }
    return view(*target);
}
NetworkView NetworkService::reconcile(const CallContext& caller, const std::string& id) {
    auto target = slot(caller, id);
    std::unique_lock operation(target->operation, std::try_to_lock);
    if (!operation.owns_lock()) return view(*target);
    { std::lock_guard lock(mutex_); if (shutting_down_) return view(*target); }
    if (!view(*target).desired_running || !target->backend || !target->lease) return view(*target);
    if (target->backend->healthy()) {
        if (now_() < target->next_refresh) return view(*target);
        try {
            if (target->forwarding) forwarding_.refresh();
            target->backend->refresh();
            if (!target->backend->healthy()) throw std::runtime_error("Network backend became unavailable during refresh");
            const auto previous = view(*target);
            // An unchanged poll must not generate a new observable revision.
            if (previous.state != NetworkState::running || !previous.error.empty() || previous.tools != target->backend->tools())
                state(*target, NetworkState::running, true);
        } catch (const std::exception& error) {
            state(*target, NetworkState::failed, true, error.what());
            // A control-plane failure can invalidate a still-live process.
            // Keep the same backoff before rebuilding it as after recovery.
            if (!target->backend->healthy()) target->next_recovery = now_() + std::chrono::seconds(5);
        }
        target->next_refresh = now_() + std::chrono::seconds(5);
        return view(*target);
    }
    if (now_() < target->next_recovery) {
        if (view(*target).state != NetworkState::failed)
            state(*target, NetworkState::failed, true, "Network backend exited; recovery retry deferred");
        return view(*target);
    }
    target->next_recovery = now_() + std::chrono::seconds(5);
    state(*target, NetworkState::recovering, true);
    try {
        target->backend->recover(target->lease->config());
        if (!target->backend->healthy()) throw std::runtime_error("Recovered network is not ready");
        if (target->forwarding) forwarding_.refresh();
        if (!target->backend->healthy()) throw std::runtime_error("Recovered network is not ready");
        state(*target, NetworkState::running, true);
    } catch (const std::exception& error) { state(*target, NetworkState::failed, true, error.what()); }
    target->next_refresh = now_() + std::chrono::seconds(5);
    target->next_recovery = now_() + std::chrono::seconds(5);
    return view(*target);
}
Json::Value NetworkService::shutdown() {
    std::vector<std::shared_ptr<Slot>> targets;
    { std::lock_guard lock(mutex_); shutting_down_ = true; for (const auto& [id, target] : slots_) targets.push_back(target); }
    forwarding_.shutdown();
    Json::Value failures(Json::arrayValue);
    for (auto& target : targets) {
        std::lock_guard operation(target->operation);
        state(*target, NetworkState::stopping, false);
        try { cleanup(*target); state(*target, NetworkState::stopped, false); }
        catch (const std::exception& error) {
            state(*target, NetworkState::failed, false, error.what());
            Json::Value failure; failure["id"] = view(*target).id; failure["error"] = view(*target).error;
            failures.append(std::move(failure));
        }
    }
    return failures;
}
void NetworkService::attach_nic(const CallContext& caller, const std::string& id, const Json::Value& nic, const std::string& tap) {
    auto target = slot(caller, id);
    if (view(*target).state != NetworkState::running) {
        try { start(caller, id); }
        catch (const ServiceError& error) { throw ServiceError(error.code(), "Failed to start network " + id + ": " + error.what()); }
        if (view(*target).state != NetworkState::running)
            throw ServiceError(ErrorCode::unavailable, "Network " + id + " still not running after start (state=" + network_state_name(view(*target).state) + ")");
    }
    std::lock_guard operation(target->operation);
    if (!target->backend || !target->backend->healthy()) throw ServiceError(ErrorCode::unavailable, "Network " + id + " is not running");
    target->backend->attach(nic, tap);
}
void NetworkService::detach_nic(const CallContext& caller, const std::string& id, const Json::Value& nic, const std::string& tap) {
    auto target = slot(caller, id);
    std::lock_guard operation(target->operation);
    if (target->backend) target->backend->detach(nic, tap);
}
Json::Value NetworkService::forward_failures(const CallContext& caller, const std::string& id) {
    auto target = slot(caller, id);
    std::unique_lock operation(target->operation, std::try_to_lock);
    if (!operation.owns_lock() || !target->backend) return Json::Value(Json::objectValue);
    return target->backend->forward_failures();
}
void NetworkService::schedule_reconcile(TaskService& workers) {
    std::string id;
    bool autostart = false;
    {
        std::lock_guard lock(mutex_);
        if (shutting_down_ || maintenance_pending_ || now_() < next_maintenance_ || (slots_.empty() && autostart_.empty())) return;
        next_maintenance_ = now_() + std::chrono::milliseconds(250);
        if (!autostart_.empty()) { id = autostart_.front(); autostart_.pop_front(); autostart = true; }
        else {
            auto at = slots_.upper_bound(maintenance_cursor_);
            for (size_t visited = 0; visited < slots_.size(); ++visited) {
                if (at == slots_.end()) at = slots_.begin();
                if (view(*at->second).desired_running) { id = at->first; break; }
                ++at;
            }
        }
        if (id.empty()) return;
        maintenance_cursor_ = id; maintenance_pending_ = true; autostart_running_ = autostart;
    }
    auto release = [this] { std::lock_guard lock(mutex_); maintenance_pending_ = false; autostart_running_ = false; };
    try {
        workers.post({"network-watchdog", true, true, true}, [this, id, release, autostart](bool discarded) {
            try {
                if (!discarded) {
                    const CallContext caller{"network-watchdog", true, true, true};
                    if (autostart) {
                        // An explicit start/stop before this worker runs wins.
                        start_impl(caller, id, true);
                    } else reconcile(caller, id);
                }
            }
            catch (...) { release(); throw; }
            release();
        });
    } catch (...) {
        std::lock_guard lock(mutex_); maintenance_pending_ = false; autostart_running_ = false;
        if (autostart) autostart_.push_front(id);
        throw;
    }
}
bool NetworkService::autostart_settled() {
    std::lock_guard lock(mutex_);
    return shutting_down_ || (autostart_.empty() && !autostart_running_);
}
void NetworkService::request_autostart(const CallContext& caller) {
    auto rows = configs_.list(caller);
    std::lock_guard lock(mutex_);
    if (maintenance_pending_ || !slots_.empty() || !autostart_.empty() || shutting_down_)
        throw std::logic_error("autostart must be prepared before serving");
    for (const auto& row : rows) if (config::boolean(row, "auto_up")) autostart_.push_back(config::uuid(row));
}
}
