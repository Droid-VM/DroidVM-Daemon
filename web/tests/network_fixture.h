// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "web/network_configuration.h"
#include "web/network_details.h"
#include "web/network_operations.h"
#include "web/network_deletion.h"
#include "web/resource_catalog.h"
#include "common/wire.h"
#include "common/identity.h"
#include <mutex>

// Explicit in-memory persistence substitute. Production uses ConfigUploads and
// NetworkConfigService; this fixture does not configure host networking.
struct FixtureNetworks {
    std::mutex mutex;
    droidvm::TaskService& tasks;
    Json::Value rows;
    std::string upload, principal, data;
    size_t total = 0;
    std::string revision = droidvm::random_id(true);
    struct Runtime { uint64_t generation = 0; bool running = false; };
    std::map<std::string, Runtime> runtime;
    struct DeletionUpload { std::string id, principal, revision, data; size_t bytes = 0; } deletion;
    std::mutex deletion_mutex;
    unsigned deletions = 0, recoveries = 0;
    bool uncertain_deletion = false, recovery_pending = false;
    explicit FixtureNetworks(droidvm::TaskService& service) : tasks(service) {
        rows = droidvm::wire::parse(R"([{"id":"fixture-network","schema":2,"name":"测试网络","bridge_type":"linux","uplink_mode":"l3","private":"omit","extension":{"counter":18446744073709551615},"l3":{"vlans":[
            {"vlan_id":0,"ipv4":{"cidr":"192.0.2.1/24","snat":true,"dhcp":{"enabled":true}},"ipv6":{"cidr":"2001:db8::1/64","snat":true,"dhcp":{"enabled":true,"offset_start":9007199254740994,"offset_end":9007199254740995}}},
            {"vlan_id":10,"ipv4":{"cidr":"192.0.2.1/24","dhcp":{"enabled":false}}},
            {"vlan_id":20,"ipv4":{"cidr":"192.0.2.1/24","snat":false,"dhcp":{"enabled":true}}}
        ]}}])");
        publish();
    }
    void publish() { revision = droidvm::random_id(true); tasks.publish_network_config(std::make_shared<const Json::Value>(rows)); }
    Json::Value catalog() { std::lock_guard lock(mutex); return droidvm::web::network_catalog(rows); }
    Json::Value detail(const std::string& id, const droidvm::VmConfigSnapshot& vms) {
        std::lock_guard lock(mutex);
        for (const auto& row : rows) if (row["id"] == id) {
            const auto& state = runtime[id];
            droidvm::web::NetworkObservation observed{id, state.running ? "RUNNING" : "STOPPED", state.generation, state.running};
            const auto live = state.running ? droidvm::wire::parse(R"({
                "address_entries":[{"addr":"192.0.2.1/24","family":4,"vlan":0,"bound":true,"source":"configured"}],
                "live_interfaces":[{"name":"tap-fixture","state":"UP","address":"02:00:00:00:00:01","vlan":0}],
                "pd":[{"vlan":0,"state":"BOUND","prefix":"2001:db8::/64","address":"2001:db8::1/64"}],
                "neighbors":[{"dst":"192.0.2.2","lladdr":"02:00:00:00:00:02","dev":"tap-fixture","state":["REACHABLE"]}],
                "dhcp_leases":[{"ip":"192.0.2.2","mac":"02:00:00:00:00:02","hostname":"fixture-guest","expires":9007199254740993,"vlan":0}],
                "gvswitch_socket":"/private/not-for-web"
            })") : Json::Value(Json::objectValue);
            return droidvm::web::network_detail(row, vms, observed, observed, live, revision);
        }
        throw droidvm::ServiceError(droidvm::ErrorCode::not_found, "Network missing");
    }
    void execute(const droidvm::web::NetworkOperation& op) {
        std::lock_guard lock(mutex);
        bool found = false;
        for (const auto& row : rows) if (row["id"] == op.network_id) found = true;
        if (!found) throw droidvm::ServiceError(droidvm::ErrorCode::not_found, "Network missing");
        auto& state = runtime[op.network_id];
        if (op.configuration_revision != revision || op.generation != state.generation ||
            op.state != (state.running ? droidvm::NetworkState::running : droidvm::NetworkState::stopped))
            throw droidvm::ServiceError(droidvm::ErrorCode::conflict, "Network observation changed");
        state.running = op.start; state.generation += 2;
    }
    // The caller holds the VM configuration mutex. This is deliberately only
    // an in-memory atomic observation substitute, never ConfigTransaction redo.
    Json::Value erase(const Json::Value& expected, const std::string& vm_revision,
        std::shared_ptr<droidvm::VmConfigSnapshot>& saved, const std::function<void()>& require_stopped) {
        std::lock_guard lock(mutex);
        if (recovery_pending) throw droidvm::ServiceError(droidvm::ErrorCode::unavailable, "Fixture recovery required");
        if (vm_revision != saved->revision)
            throw droidvm::ServiceError(droidvm::ErrorCode::conflict, "VM configuration changed");
        if (!expected.isObject() || !expected["id"].isString())
            throw droidvm::ServiceError(droidvm::ErrorCode::invalid_argument, "Missing expected network");
        const auto id = expected["id"].asString();
        Json::Value kept(Json::arrayValue); bool found = false;
        for (const auto& row : rows) {
            if (row["id"] != id) { kept.append(row); continue; }
            if (row != expected) throw droidvm::ServiceError(droidvm::ErrorCode::conflict, "Network configuration changed");
            found = true;
        }
        if (!found) throw droidvm::ServiceError(droidvm::ErrorCode::not_found, "Network missing");
        auto next = std::make_shared<droidvm::VmConfigSnapshot>(*saved);
        for (auto& vm : next->document["vms"]) {
            if (!vm["networks"].isArray()) continue;
            Json::Value nics(Json::arrayValue);
            for (const auto& nic : vm["networks"]) {
                if (nic["network_id"] != id) nics.append(nic);
                else if (vm["id"] == "native-http-vm") require_stopped();
            }
            vm["networks"] = std::move(nics);
        }
        next->revision = droidvm::random_id(true); next->persisted = true;
        next->encoded = std::make_shared<const std::string>(droidvm::wire::stringify(next->document));
        auto& state = runtime[id]; state.running = false; state.generation += 2;
        rows = std::move(kept); saved = std::move(next); ++deletions;
        publish(); tasks.publish_vm_config(saved);
        if (uncertain_deletion) {
            uncertain_deletion = false; recovery_pending = true;
            throw droidvm::ServiceError(droidvm::ErrorCode::commit_uncertain, "Fixture deletion installed; recovery required");
        }
        Json::Value result; result["networkId"] = id; result["vmRevision"] = saved->revision; result["persistence"] = "persisted";
        return result;
    }
    void recover_configuration() {
        std::lock_guard lock(mutex);
        // No real journal or filesystem fault is represented by this switch.
        recovery_pending = false; ++recoveries;
    }
    droidvm::web::JsonConfigurationStaging deletion_staging(
        std::function<Json::Value(const Json::Value&, const std::string&)> commit) {
        return {
            [this](const droidvm::CallContext& caller, const std::string& observed, size_t bytes) {
                std::lock_guard lock(deletion_mutex);
                if (!deletion.id.empty()) throw droidvm::ServiceError(droidvm::ErrorCode::resource_exhausted, "Fixture deletion upload occupied");
                deletion = {droidvm::random_id(true), caller.principal, observed, {}, bytes}; return deletion.id;
            },
            [this](const droidvm::CallContext& caller, const std::string& id, size_t offset, std::string_view bytes) {
                std::lock_guard lock(deletion_mutex);
                if (deletion.id.empty() || deletion.id != id || deletion.principal != caller.principal)
                    throw droidvm::ServiceError(droidvm::ErrorCode::not_found, "Deletion upload missing");
                if (offset < deletion.data.size() && offset + bytes.size() <= deletion.data.size() &&
                    std::string_view(deletion.data).substr(offset, bytes.size()) == bytes) return deletion.data.size();
                if (offset != deletion.data.size() || bytes.size() > deletion.bytes - deletion.data.size())
                    throw droidvm::ServiceError(droidvm::ErrorCode::invalid_argument, "Invalid deletion upload offset");
                deletion.data.append(bytes); return deletion.data.size();
            },
            [this, commit](const droidvm::CallContext& caller, const std::string& id) {
                DeletionUpload pending;
                {
                    std::lock_guard lock(deletion_mutex);
                    if (deletion.id.empty() || deletion.id != id || deletion.principal != caller.principal)
                        throw droidvm::ServiceError(droidvm::ErrorCode::not_found, "Deletion upload missing");
                    if (deletion.data.size() != deletion.bytes)
                        throw droidvm::ServiceError(droidvm::ErrorCode::invalid_argument, "Incomplete deletion upload");
                    pending = std::move(deletion); deletion = {};
                }
                const auto body = droidvm::wire::parse(pending.data);
                if (!body.isObject() || body.size() != 1 || !body["expected"].isObject())
                    throw droidvm::ServiceError(droidvm::ErrorCode::invalid_argument, "Invalid deletion confirmation");
                return commit(body["expected"], pending.revision);
            },
            [this](const droidvm::CallContext& caller, const std::string& id) {
                std::lock_guard lock(deletion_mutex);
                if (deletion.id == id && deletion.principal == caller.principal) deletion = {};
            }
        };
    }
    void require_upload(const droidvm::CallContext& caller, const std::string& id) const {
        if (upload.empty() || id != upload || principal != caller.principal)
            throw droidvm::ServiceError(droidvm::ErrorCode::not_found, "Upload missing");
    }
    droidvm::web::JsonConfigurationStaging staging() {
        return {
            [this](const droidvm::CallContext& caller, const std::string&, size_t bytes) {
                std::lock_guard lock(mutex);
                if (!upload.empty()) throw droidvm::ServiceError(droidvm::ErrorCode::resource_exhausted, "Fixture upload occupied");
                upload = droidvm::random_id(true); principal = caller.principal; total = bytes; data.clear(); return upload;
            },
            [this](const droidvm::CallContext& caller, const std::string& id, size_t offset, std::string_view bytes) {
                std::lock_guard lock(mutex); require_upload(caller, id);
                if (offset != data.size() || bytes.size() > total - data.size())
                    throw droidvm::ServiceError(droidvm::ErrorCode::invalid_argument, "Invalid upload offset");
                data.append(bytes); return data.size();
            },
            [this](const droidvm::CallContext& caller, const std::string& id) {
                std::lock_guard lock(mutex); require_upload(caller, id);
                if (data.size() != total) throw droidvm::ServiceError(droidvm::ErrorCode::invalid_argument, "Incomplete upload");
                auto encoded = std::move(data); upload.clear(); principal.clear();
                const auto envelope = droidvm::wire::parse(encoded);
                if (!envelope.isObject() || envelope.size() != 1 || !envelope["operations"].isArray() || envelope["operations"].size() > 1024)
                    throw droidvm::ServiceError(droidvm::ErrorCode::invalid_argument, "Invalid fixture import");
                auto next = rows; Json::Value ids(Json::arrayValue);
                for (const auto& op : envelope["operations"]) {
                    if (!op.isObject() || op.size() != 2 || !op.isMember("expected") || !op["config"].isObject() || !op["config"]["id"].isString())
                        throw droidvm::ServiceError(droidvm::ErrorCode::invalid_argument, "Invalid fixture edit");
                    bool found = false;
                    for (auto& row : next) if (row["id"] == op["config"]["id"]) {
                        if (runtime[row["id"].asString()].running)
                            throw droidvm::ServiceError(droidvm::ErrorCode::conflict, "Fixture network is running");
                        if (row != op["expected"]) throw droidvm::ServiceError(droidvm::ErrorCode::conflict, "Network changed");
                        row = op["config"]; found = true; break;
                    }
                    if (!found) {
                        if (!op["expected"].isNull()) throw droidvm::ServiceError(droidvm::ErrorCode::conflict, "Network removed");
                        next.append(op["config"]);
                    }
                    ids.append(op["config"]["id"]);
                }
                rows = std::move(next); publish(); return ids;
            },
            [this](const droidvm::CallContext& caller, const std::string& id) {
                std::lock_guard lock(mutex); require_upload(caller, id); upload.clear(); principal.clear(); data.clear();
            }
        };
    }
};
