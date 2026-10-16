// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "context.h"
#include "config_gate.h"
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
    // Two full-sized documents (observed/replacement) plus operation envelopes.
    static constexpr size_t max_import_bytes = 2 * config::JsonFile::max_bytes + (1u << 20);
    explicit NetworkConfigService(int files_directory, uid_t owner, config::JsonFile::Observer observer = {},
        TaskService* events = nullptr, bool claim_ownership = false, std::shared_ptr<ConfigurationGate> gate = {});
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
    // Internal atomic import primitive. Each operation contains config and
    // expected (null for creation, exact observed object for replacement).
    // No deletes; preserve all unrelated/inactive entries and root extensions.
    Json::Value merge_if_matches(const CallContext& caller, const Json::Value& operations);
    bool remove(const CallContext& caller, const std::string& id); // false when unknown; conflict while reserved
    // Persist stable Linux MAC/DUID/PD table identities before returning a
    // runtime lease. occupied_tables excludes host tables from NEW allocation;
    // existing allocations still require backend ownership checks before use.
    std::unique_ptr<NetworkRuntimeLease> prepare_runtime(const CallContext& caller, const std::string& id,
        const std::set<uint32_t>& occupied_tables = {});
    bool recovered() const;
    size_t inactive() const;
private:
    friend class ConfigurationService;
    friend class NetworkService;
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
    std::shared_ptr<ConfigurationGate> gate_;
    bool coordinated_removal_ = false; // Startup binding; only coordinator may erase IDs.
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
