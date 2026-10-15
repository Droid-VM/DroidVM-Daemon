// SPDX-License-Identifier: GPL-3.0-or-later
#include "network_config.h"
#include "store/network_config.h"
#include <set>

namespace droidvm {
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
    }
    result->document = std::move(document);
    result->recovered = recovered;
    return result;
}
NetworkConfigService::NetworkConfigService(int directory, uid_t owner, config::JsonFile::Observer observer)
    : file_(directory, "networks.json", owner, std::move(observer)) {
    auto loaded = file_.load();
    Json::Value empty;
    empty["networks"] = Json::Value(Json::arrayValue);
    state_ = decode(loaded ? std::move(loaded->value) : std::move(empty), loaded && loaded->recovered);
}
std::shared_ptr<const NetworkConfigService::State> NetworkConfigService::state() const {
    std::lock_guard guard(state_mutex_);
    return state_;
}
bool NetworkConfigService::recovered() const { return state()->recovered; }
size_t NetworkConfigService::inactive() const { return state()->inactive; }
Json::Value NetworkConfigService::list(const CallContext& caller) const {
    access(caller);
    auto current = state();
    Json::Value result(Json::arrayValue);
    // Preserve stored order, not map/UUID order.
    std::set<Json::ArrayIndex> indices;
    for (const auto& [id, index] : current->ids) indices.insert(index);
    for (auto index : indices) result.append(current->document["networks"][index]);
    return result;
}
Json::Value NetworkConfigService::get(const CallContext& caller, const std::string& id) const {
    access(caller);
    auto current = state();
    auto found = current->ids.find(identity(id));
    if (found == current->ids.end()) throw ServiceError(ErrorCode::not_found, "Network not found");
    return current->document["networks"][found->second];
}
bool NetworkConfigService::exists(const CallContext& caller, const std::string& id) const {
    access(caller);
    try { return state()->ids.contains(identity(id)); }
    catch (const ServiceError& error) { if (error.code() == ErrorCode::invalid_argument) return false; throw; }
}
std::string NetworkConfigService::create(const CallContext& caller, Json::Value value) { return change(caller, std::move(value), false); }
std::string NetworkConfigService::update(const CallContext& caller, Json::Value value) { return change(caller, std::move(value), true); }
std::string NetworkConfigService::change(const CallContext& caller, Json::Value value, bool updating) {
    access(caller);
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
    try { config::encode_json(next->document, config::JsonFile::max_bytes); }
    catch (const std::exception&) { throw ServiceError(ErrorCode::resource_exhausted, "Network configuration storage limit exceeded"); }
    try { file_.save(next->document); }
    catch (const config::CommitError& error) {
        if (error.installed) {
            std::lock_guard guard(state_mutex_);
            state_ = next;
        }
        throw ServiceError(error.installed ? ErrorCode::commit_uncertain : ErrorCode::io_error,
            error.installed ? "Configuration installed; durability could not be confirmed" : "Configuration could not be saved");
    } catch (const std::exception&) { throw ServiceError(ErrorCode::io_error, "Configuration could not be saved"); }
    { std::lock_guard guard(state_mutex_); state_ = std::move(next); }
    return id;
}
}
