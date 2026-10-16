// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "context.h"
#include "store/json_file.h"
#include <map>
#include <memory>
#include <mutex>
#include <set>

namespace droidvm {
class TaskService;
// Hold from startup preparation through successful backend cleanup. Releasing
// this guard only permits edits; it does not stop processes or remove resources.
class NetworkRuntimeLease {
public:
    ~NetworkRuntimeLease();
    NetworkRuntimeLease(const NetworkRuntimeLease&) = delete;
    NetworkRuntimeLease& operator=(const NetworkRuntimeLease&) = delete;
    const Json::Value& config() const { return config_; }
    const std::string& bridge_mac() const { return bridge_mac_; }
private:
    friend class NetworkConfigService;
    struct Registry;
    NetworkRuntimeLease(std::shared_ptr<Registry> registry, std::string id, Json::Value config, std::string mac);
    std::shared_ptr<Registry> registry_;
    std::string id_, bridge_mac_;
    Json::Value config_;
};
// Persistent configuration ownership; no socket, Android Context or kernel
// network side effects. Runtime activation/deletion will compose this service.
class NetworkConfigService {
public:
    explicit NetworkConfigService(int files_directory, uid_t owner, config::JsonFile::Observer observer = {},
        TaskService* events = nullptr, bool claim_ownership = false);
    bool has_events() const { return events_ != nullptr; }
    Json::Value list(const CallContext& caller) const;
    Json::Value get(const CallContext& caller, const std::string& id) const;
    bool exists(const CallContext& caller, const std::string& id) const;
    std::string create(const CallContext& caller, Json::Value value);
    std::string update(const CallContext& caller, Json::Value value);
    // Compare the exact configuration returned by get(), under the writer lock.
    // Runtime projections are not valid expectations. No implicit retry/merge
    // with a concurrently changed target; unrelated network edits are allowed.
    std::string update_if_matches(const CallContext& caller, const Json::Value& expected, Json::Value value);
    bool remove(const CallContext& caller, const std::string& id); // false when unknown; conflict while reserved
    // Persist stable Linux MAC/DUID/PD table identities before returning a
    // runtime lease. occupied_tables excludes host tables from NEW allocation;
    // existing allocations still require backend ownership checks before use.
    std::unique_ptr<NetworkRuntimeLease> prepare_runtime(const CallContext& caller, const std::string& id,
        const std::set<uint32_t>& occupied_tables = {});
    bool recovered() const;
    size_t inactive() const;
private:
    struct State {
        Json::Value document;
        std::map<std::string, Json::ArrayIndex> ids;
        size_t inactive = 0;
        bool recovered = false;
        bool durability_uncertain = false;
        Json::Value active{Json::arrayValue};
    };
    config::JsonFile file_;
    TaskService* events_;
    mutable std::mutex state_mutex_;
    std::mutex writer_mutex_;
    std::shared_ptr<const State> state_;
    std::shared_ptr<NetworkRuntimeLease::Registry> runtime_;
    std::shared_ptr<const State> state() const;
    static std::shared_ptr<State> decode(Json::Value document, bool recovered);
    std::string change(const CallContext& caller, Json::Value value, bool update, const Json::Value* expected = nullptr);
    void install(std::shared_ptr<State> next);
    void publish(std::shared_ptr<State> next);
    void require_stopped(const std::string& id) const;
};
}
