// SPDX-License-Identifier: GPL-3.0-or-later
#include "network_config.h"
#include "tasks.h"
#include "store/network_config.h"
#include "store/vm_ownership.h"
#include "common/identity.h"
#include <regex>
#include <set>
#include <vector>

namespace droidvm {
struct NetworkRuntimeLease::Registry { std::mutex mutex; std::set<std::string> ids; };
NetworkRuntimeLease::NetworkRuntimeLease(std::shared_ptr<Registry> registry, std::string id, Json::Value config, std::string mac)
    : registry_(std::move(registry)), id_(std::move(id)), bridge_mac_(std::move(mac)), config_(std::move(config)) {
    std::lock_guard lock(registry_->mutex);
    if (!registry_->ids.insert(id_).second) throw ServiceError(ErrorCode::conflict, "Network is already reserved for runtime");
}
NetworkRuntimeLease::~NetworkRuntimeLease() { std::lock_guard lock(registry_->mutex); registry_->ids.erase(id_); }
namespace {
void access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || caller.principal.empty()) throw ServiceError(ErrorCode::permission_denied, "Administrator permission required");
}
std::string identity(const std::string& id) {
    Json::Value value;
    value["id"] = id;
    try { return config::uuid(value); }
    catch (const std::invalid_argument&) { throw ServiceError(ErrorCode::invalid_argument, "Invalid network ID"); }
}
const Json::Value& vlans(const Json::Value& row) { return config::member(config::member(row, "l3"), "vlans"); }
int64_t route_table(const Json::Value& vlan) {
    return config::integer(config::member(config::member(vlan, "ipv6"), "pd"), "route_table");
}
std::string generated_mac() {
    // Match NetUtils.generateRandomMac's fixed 02 prefix and 40 random bits.
    const auto bytes = random_id(false);
    std::string result = "02";
    for (size_t i = 2; i < 12; i += 2) result += ":" + bytes.substr(i, 2);
    return result;
}
// Known fields retain replacement/removal semantics. Unrecognized fields from
// a newer UI survive an edit by an older client. Explicit null still clears.
struct Shape { std::set<std::string> keys; std::map<std::string, Shape> children; };
const Shape& network_shape() {
    static const Shape dhcp{{"enabled", "offset_start", "offset_end"}, {}};
    static const Shape ipv4{{"cidr", "snat", "dhcp"}, {{"dhcp", dhcp}}};
    static const Shape ipv6{{"source", "cidr", "snat", "dhcp", "slaac", "pd"},
        {{"dhcp", dhcp}, {"slaac", {{"enabled"}, {}}}, {"pd", {{"uplink", "duid", "route_table"}, {}}}}};
    static const Shape vlan{{"vlan_id", "ipv4", "ipv6", "dns_servers", "ipv4_secondary", "ipv6_secondary"},
        {{"ipv4", ipv4}, {"ipv6", ipv6}}};
    static const Shape root{{"id", "name", "schema", "bridge_name", "bridge_type", "uplink_mode", "stp", "auto_up", "l2", "l3"},
        {{"l2", {{"uplink", "pseudo_bridge"}, {}}}, {"l3", {{"mac_address", "vlans"}, {{"vlans", vlan}}}}}};
    return root;
}
void preserve(const Json::Value& old, Json::Value& next, const Shape& shape) {
    if (!old.isObject() || !next.isObject()) return;
    for (const auto& key : old.getMemberNames()) if (!shape.keys.contains(key) && !next.isMember(key)) next[key] = old[key];
    for (const auto& [key, child] : shape.children) {
        if (!old.isMember(key)) continue;
        if (key == "vlans") {
            if (!old[key].isArray() || !next.isMember(key) || !next[key].isArray()) continue;
            for (auto& item : next[key]) if (item.isObject()) {
                for (const auto& previous : old[key]) if (previous.isObject() &&
                    static_cast<uint32_t>(config::integer(previous, "vlan_id")) == static_cast<uint32_t>(config::integer(item, "vlan_id"))) {
                    preserve(previous, item, child);
                    break;
                }
            }
        } else if (old[key].isObject()) {
            if (next.isMember(key)) preserve(old[key], next[key], child);
            else {
                Json::Value extensions(Json::objectValue);
                preserve(old[key], extensions, child);
                if (!extensions.empty()) next[key] = std::move(extensions);
            }
        }
    }
}
}
std::shared_ptr<NetworkConfigService::State> NetworkConfigService::decode(Json::Value document, bool recovered) {
    if (!document.isObject() || !document["networks"].isArray())
        throw ServiceError(ErrorCode::invalid_argument, "Invalid networks configuration document");
    auto& rows = document["networks"];
    if (rows.size() > 1024) throw ServiceError(ErrorCode::resource_exhausted, "Network configuration limit exceeded");
    auto result = std::make_shared<State>();
    result->revision = random_id(true);
    std::set<std::string> names;
    for (Json::ArrayIndex i = 0; i < rows.size(); ++i) {
        auto& row = rows[i];
        if (!row.isObject()) throw ServiceError(ErrorCode::invalid_argument, "Invalid network configuration entry");
        auto migrated = config::migrate_network(row);
        if (!migrated) { ++result->inactive; continue; }
        if (config::schema(row) != 2) {
            try { config::validate_network(*migrated); }
            catch (const std::invalid_argument&) { ++result->inactive; continue; }
        }
        std::string id;
        try { id = config::uuid(*migrated); }
        catch (const std::invalid_argument&) { throw ServiceError(ErrorCode::invalid_argument, "Invalid stored network ID"); }
        const auto& name = config::member(*migrated, "name");
        if (!name.isString()) throw ServiceError(ErrorCode::invalid_argument, "Stored network name is missing");
        if (!result->ids.emplace(id, i).second || !names.insert(name.asString()).second)
            throw ServiceError(ErrorCode::conflict, "Duplicate stored network ID or name");
        row = std::move(*migrated);
        result->active.append(row);
    }
    result->document = std::move(document);
    result->recovered = recovered;
    return result;
}
NetworkConfigService::NetworkConfigService(int directory, uid_t owner, config::JsonFile::Observer observer, TaskService* events, bool claim_ownership,
        std::shared_ptr<ConfigurationGate> gate)
    : file_(directory, "networks.json", owner, std::move(observer)), events_(events), gate_(std::move(gate)), runtime_(std::make_shared<NetworkRuntimeLease::Registry>()) {
    // Opt-in until every legacy writer and upgrade path has migrated.
    if (claim_ownership) config::claim_network_config(directory, owner);
    auto loaded = file_.load();
    Json::Value empty;
    empty["networks"] = Json::Value(Json::arrayValue);
    auto initial = decode(loaded ? std::move(loaded->value) : std::move(empty), loaded && loaded->recovered);
    // A previous process could have died after rename and before directory
    // fsync. Verify durability on first runtime preparation after reopening.
    initial->durability_uncertain = loaded.has_value();
    publish(std::move(initial));
}
std::shared_ptr<const NetworkConfigService::State> NetworkConfigService::state() const {
    std::lock_guard guard(state_mutex_);
    return state_;
}
bool NetworkConfigService::recovered() const { auto admission = ConfigurationGate::enter(gate_); return state()->recovered; }
size_t NetworkConfigService::inactive() const { auto admission = ConfigurationGate::enter(gate_); return state()->inactive; }
Json::Value NetworkConfigService::list(const CallContext& caller) const {
    access(caller);
    auto admission = ConfigurationGate::enter(gate_);
    auto current = state();
    Json::Value result(Json::arrayValue);
    // Preserve stored order, not map/UUID order.
    std::set<Json::ArrayIndex> indices;
    for (const auto& [id, index] : current->ids) indices.insert(index);
    for (auto index : indices) result.append(current->document["networks"][index]);
    return result;
}
NetworkConfigService::Snapshot NetworkConfigService::snapshot(const CallContext& caller) const {
    access(caller);
    auto admission = ConfigurationGate::enter(gate_);
    auto current = state();
    return {current->active, current->revision};
}
Json::Value NetworkConfigService::get(const CallContext& caller, const std::string& id) const {
    return get_with_revision(caller, id).config;
}
NetworkConfigService::Snapshot NetworkConfigService::get_with_revision(const CallContext& caller, const std::string& id) const {
    access(caller);
    auto admission = ConfigurationGate::enter(gate_);
    auto current = state();
    auto found = current->ids.find(identity(id));
    if (found == current->ids.end()) throw ServiceError(ErrorCode::not_found, "Network not found");
    return {current->document["networks"][found->second], current->revision};
}
bool NetworkConfigService::exists(const CallContext& caller, const std::string& id) const {
    access(caller);
    auto admission = ConfigurationGate::enter(gate_);
    try { return state()->ids.contains(identity(id)); }
    catch (const ServiceError& error) { if (error.code() == ErrorCode::invalid_argument) return false; throw; }
}
std::string NetworkConfigService::create(const CallContext& caller, Json::Value value) { return change(caller, std::move(value), false); }
std::string NetworkConfigService::update(const CallContext& caller, Json::Value value) { return change(caller, std::move(value), true); }
std::string NetworkConfigService::update_if_matches(const CallContext& caller, const Json::Value& expected, Json::Value value) {
    access(caller);
    if (!expected.isObject()) throw ServiceError(ErrorCode::invalid_argument, "Expected network configuration is required");
    return change(caller, std::move(value), true, &expected);
}
bool NetworkConfigService::remove(const CallContext& caller, const std::string& input_id) {
    access(caller);
    auto admission = ConfigurationGate::enter(gate_);
    if (coordinated_removal_)
        throw ServiceError(ErrorCode::conflict, "Network deletion requires a coordinated confirmation");
    const auto id = identity(input_id);
    std::lock_guard writer(writer_mutex_);
    const auto previous = state();
    const auto found = previous->ids.find(id);
    if (found == previous->ids.end()) return false;
    require_stopped(id);
    auto document = previous->document;
    Json::Value rows(Json::arrayValue);
    for (Json::ArrayIndex i = 0; i < document["networks"].size(); ++i) if (i != found->second) rows.append(document["networks"][i]);
    document["networks"] = std::move(rows);
    install(decode(std::move(document), false));
    return true;
}
Json::Value NetworkConfigService::merge_if_matches(const CallContext& caller, const Json::Value& operations,
        const std::string& expected_revision) {
    access(caller);
    auto admission = ConfigurationGate::enter(gate_);
    if (!operations.isArray() || operations.size() > 1024)
        throw ServiceError(ErrorCode::invalid_argument, "Invalid network import operations");
    try { config::encode_json(operations, max_import_bytes); }
    catch (const std::exception&) { throw ServiceError(ErrorCode::resource_exhausted, "Network import is too large"); }
    struct Edit { std::string id; Json::Value value; const Json::Value* expected; };
    std::vector<Edit> edits;
    std::set<std::string> ids;
    for (const auto& operation : operations) {
        if (!operation.isObject() || !operation.isMember("expected")
            || (!operation["expected"].isNull() && !operation["expected"].isObject()))
            throw ServiceError(ErrorCode::invalid_argument, "Network import expectation is required");
        for (const auto& key : operation.getMemberNames())
            if (key != "config" && key != "expected")
                throw ServiceError(ErrorCode::invalid_argument, "Unexpected network import field");
        auto value = operation["config"];
        std::string id;
        try {
            if (!value.isObject() || config::schema(value) != 2)
                throw std::invalid_argument("Unsupported network config schema (expected 2)");
            id = config::uuid(value);
            config::validate_network(value);
        } catch (const std::invalid_argument& error) { throw ServiceError(ErrorCode::invalid_argument, error.what()); }
        if (!ids.insert(id).second) throw ServiceError(ErrorCode::invalid_argument, "Repeated network import ID");
        try { config::encode_json(value, 256u << 10); }
        catch (const std::exception&) { throw ServiceError(ErrorCode::resource_exhausted, "Network configuration is too large"); }
        edits.push_back({std::move(id), std::move(value), &operation["expected"]});
    }
    Json::Value changed(Json::arrayValue);
    std::lock_guard writer(writer_mutex_);
    const auto previous = state();
    if (!expected_revision.empty() && previous->revision != expected_revision)
        throw ServiceError(ErrorCode::conflict, "Network configuration changed; preview the backup again");
    if (edits.empty()) return changed;
    auto document = previous->document;
    auto& rows = document["networks"];
    std::vector<Json::ArrayIndex> changed_indices;
    for (auto& edit : edits) {
        const auto found = previous->ids.find(edit.id);
        if (edit.expected->isNull()) {
            if (found != previous->ids.end()) throw ServiceError(ErrorCode::conflict, "Imported network already exists");
            // Inactive/future records reserve their IDs too.
            for (const auto& row : rows) {
                std::string reserved;
                try { reserved = config::uuid(row); } catch (const std::invalid_argument&) {}
                if (reserved == edit.id) throw ServiceError(ErrorCode::conflict, "Network ID is reserved by an inactive configuration");
            }
            changed_indices.push_back(rows.size());
            rows.append(std::move(edit.value));
        } else {
            if (found == previous->ids.end() || previous->document["networks"][found->second] != *edit.expected)
                throw ServiceError(ErrorCode::conflict, "Network configuration changed; reload before importing");
            require_stopped(edit.id);
            preserve(rows[found->second], edit.value, network_shape());
            rows[found->second] = std::move(edit.value);
            changed_indices.push_back(found->second);
        }
        changed.append(edit.id);
    }
    // Validate names against the final document, allowing atomic name swaps.
    // Inactive/future entries reserve names just as in single-entry edits.
    for (const auto index : changed_indices)
        for (Json::ArrayIndex other = 0; other < rows.size(); ++other)
            if (other != index && config::string(rows[index], "name") == config::string(rows[other], "name"))
                throw ServiceError(ErrorCode::conflict, "Imported network name is already reserved");
    install(decode(std::move(document), false));
    return changed;
}
void NetworkConfigService::require_stopped(const std::string& id) const {
    std::lock_guard lock(runtime_->mutex);
    if (runtime_->ids.contains(id)) throw ServiceError(ErrorCode::conflict, "Network configuration is reserved by runtime");
}
std::unique_ptr<NetworkRuntimeLease> NetworkConfigService::prepare_runtime(const CallContext& caller,
        const std::string& input_id, const std::set<uint32_t>& occupied_tables, const std::string& expected_revision) {
    access(caller);
    auto admission = ConfigurationGate::enter(gate_);
    const auto id = identity(input_id);
    std::lock_guard writer(writer_mutex_);
    require_stopped(id);
    const auto previous = state();
    if (!expected_revision.empty() && previous->revision != expected_revision)
        throw ServiceError(ErrorCode::conflict, "Network configuration changed; reload before starting");
    const auto found = previous->ids.find(id);
    if (found == previous->ids.end()) throw ServiceError(ErrorCode::not_found, "Network not found");
    auto document = previous->document;
    auto& value = document["networks"][found->second];
    try { config::validate_network(value); }
    catch (const std::invalid_argument& error) { throw ServiceError(ErrorCode::invalid_argument, error.what()); }
    const bool linux_backend = config::string(value, "bridge_type") != "gvisor";
    const bool l3 = config::string(value, "uplink_mode") != "l2";
    std::string mac = l3 ? config::string(config::member(value, "l3"), "mac_address") : "";
    if (linux_backend && mac.empty()) {
        mac = config::string(value, "generated_mac");
        if (mac.empty()) value["generated_mac"] = mac = generated_mac();
        if (!std::regex_match(mac, std::regex("([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")))
            throw ServiceError(ErrorCode::invalid_argument, "Invalid stored generated bridge MAC");
    }
    if (linux_backend && l3 && vlans(value).isArray()) {
        // Reserve all known persisted table numbers, even on inactive/future
        // entries or currently static VLANs. Never rewrite another network.
        std::map<uint32_t, size_t> used;
        for (const auto& row : document["networks"]) if (vlans(row).isArray()) for (const auto& vlan : vlans(row)) {
            const auto table = route_table(vlan);
            if (table > 0 && table <= UINT32_MAX) ++used[static_cast<uint32_t>(table)];
        }
        uint64_t candidate = 9991;
        for (auto& vlan : value["l3"]["vlans"]) {
            if (!vlan.isObject() || config::string(config::member(vlan, "ipv6"), "source") != "dhcp_pd") continue;
            auto& pd = vlan["ipv6"]["pd"];
            auto table = route_table(vlan);
            if (table < 0 || table > UINT32_MAX || (table >= 253 && table <= 255))
                throw ServiceError(ErrorCode::invalid_argument, "Invalid or reserved PD route table");
            if (table && used[static_cast<uint32_t>(table)] != 1)
                throw ServiceError(ErrorCode::conflict, "PD route table is reserved by another VLAN");
            if (!table) {
                while (candidate <= UINT32_MAX && (used.contains(static_cast<uint32_t>(candidate)) ||
                    occupied_tables.contains(static_cast<uint32_t>(candidate)))) ++candidate;
                if (candidate > UINT32_MAX) throw ServiceError(ErrorCode::resource_exhausted, "No PD route table available");
                table = static_cast<int64_t>(candidate);
                pd["route_table"] = Json::Int64(table);
                used[static_cast<uint32_t>(table)] = 1;
            }
            if (config::string(pd, "duid").empty()) {
                std::string duid = "00:03:00:01:" + mac;
                for (auto& c : duid) if (c >= 'A' && c <= 'F') c += 'a' - 'A';
                pd["duid"] = std::move(duid);
            }
        }
    }
    try { config::encode_json(value, 256u << 10); }
    catch (const std::exception&) { throw ServiceError(ErrorCode::resource_exhausted, "Prepared network configuration is too large"); }
    const auto prepared = value;
    // A prior post-rename failure must be synced again even if identities did
    // not change. Never launch after merely observing uncertain in-memory data.
    if (document != previous->document || previous->durability_uncertain || previous->recovered)
        install(decode(std::move(document), false));
    return std::unique_ptr<NetworkRuntimeLease>(new NetworkRuntimeLease(runtime_, id, prepared, mac));
}
std::string NetworkConfigService::change(const CallContext& caller, Json::Value value, bool updating, const Json::Value* expected) {
    access(caller);
    auto admission = ConfigurationGate::enter(gate_);
    std::string id;
    try {
        if (!value.isObject() || config::schema(value) != 2) throw std::invalid_argument("Unsupported network config schema (expected 2)");
        id = config::uuid(value);
    }
    catch (const std::invalid_argument& error) { throw ServiceError(ErrorCode::invalid_argument, error.what()); }
    // Preserve the old handler order: duplicate/missing IDs are reported before
    // validating the other fields. Recheck under the writer lock after validation.
    auto initial = state();
    if (updating && !initial->ids.contains(id)) throw ServiceError(ErrorCode::not_found, "Network not found");
    if (!updating && initial->ids.contains(id)) throw ServiceError(ErrorCode::conflict, "Network already exists");
    try { config::validate_network(value); }
    catch (const std::invalid_argument& error) { throw ServiceError(ErrorCode::invalid_argument, error.what()); }
    // Bound each accepted edit before holding the writer mutex or touching disk.
    try { config::encode_json(value, 256u << 10); }
    catch (const std::exception&) { throw ServiceError(ErrorCode::resource_exhausted, "Network configuration is too large"); }
    std::lock_guard writer(writer_mutex_);
    auto previous = state();
    auto found = previous->ids.find(id);
    if (updating && found == previous->ids.end()) throw ServiceError(ErrorCode::not_found, "Network not found");
    if (!updating && found != previous->ids.end()) throw ServiceError(ErrorCode::conflict, "Network already exists");
    if (expected && previous->document["networks"][found->second] != *expected)
        throw ServiceError(ErrorCode::conflict, "Network configuration changed; reload before saving");
    if (updating) require_stopped(id);
    auto document = previous->document;
    auto& rows = document["networks"];
    for (Json::ArrayIndex i = 0; i < rows.size(); ++i) {
        if (updating && i == found->second) continue;
        std::string reserved_id;
        try { reserved_id = config::uuid(rows[i]); } catch (const std::invalid_argument&) {}
        if (reserved_id == id) throw ServiceError(ErrorCode::conflict, "Network ID is reserved by an inactive configuration");
        if (config::string(rows[i], "name") == config::string(value, "name"))
            throw ServiceError(ErrorCode::invalid_argument, "Config name already exists: " + config::string(value, "name"));
    }
    if (updating) { preserve(rows[found->second], value, network_shape()); rows[found->second] = std::move(value); }
    else rows.append(std::move(value));
    auto next = decode(std::move(document), false);
    install(std::move(next));
    return id;
}
void NetworkConfigService::install(std::shared_ptr<State> next) {
    try { config::encode_json(next->document, config::JsonFile::max_bytes); }
    catch (const std::exception&) { throw ServiceError(ErrorCode::resource_exhausted, "Network configuration storage limit exceeded"); }
    try { file_.save(next->document); }
    catch (const config::CommitError& error) {
        if (error.installed) {
            next->durability_uncertain = true;
            publish(next);
        }
        throw ServiceError(error.installed ? ErrorCode::commit_uncertain : ErrorCode::io_error,
            error.installed ? "Configuration installed; durability could not be confirmed" : "Configuration could not be saved");
    } catch (const std::exception&) { throw ServiceError(ErrorCode::io_error, "Configuration could not be saved"); }
    publish(std::move(next));
}
void NetworkConfigService::publish(std::shared_ptr<State> next) {
    // Writer -> state -> journal. Journal reads only the immutable projection;
    // it never calls back into this service. Pre-rename failures publish nothing.
    std::lock_guard guard(state_mutex_);
    state_ = std::move(next);
    if (events_) events_->publish_network_config(std::shared_ptr<const Json::Value>(state_, &state_->active));
}
}
