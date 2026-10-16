// SPDX-License-Identifier: GPL-3.0-or-later
#include "network.h"
#include "store/network_config.h"

namespace droidvm {
struct NetworkService::Slot {
    std::mutex operation, observation;
    NetworkView view;
    std::unique_ptr<NetworkRuntimeLease> lease;
    std::unique_ptr<network::Backend> backend;
    Clock::time_point next_recovery{};
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
    std::lock_guard lock(slot.observation);
    slot.view.state = state; slot.view.desired_running = desired;
    slot.view.error = error.substr(0, 4096); ++slot.view.generation;
}
NetworkView NetworkService::get(const CallContext& caller, const std::string& id) { return view(*slot(caller, id)); }
void NetworkService::cleanup(Slot& slot) {
    if (slot.backend) slot.backend->stop();
    slot.backend.reset(); slot.lease.reset();
}
NetworkView NetworkService::start(const CallContext& caller, const std::string& id) {
    auto target = slot(caller, id);
    std::unique_lock operation(target->operation, std::try_to_lock);
    if (!operation.owns_lock()) throw ServiceError(ErrorCode::conflict, "Network operation already in progress");
    { std::lock_guard lock(mutex_); if (shutting_down_) throw ServiceError(ErrorCode::unavailable, "Network service is shutting down"); }
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
        target->next_recovery = {};
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
    if (target->backend->healthy()) return view(*target);
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
        state(*target, NetworkState::running, true);
    } catch (const std::exception& error) { state(*target, NetworkState::failed, true, error.what()); }
    return view(*target);
}
Json::Value NetworkService::shutdown() {
    std::vector<std::shared_ptr<Slot>> targets;
    { std::lock_guard lock(mutex_); shutting_down_ = true; for (const auto& [id, target] : slots_) targets.push_back(target); }
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
}
