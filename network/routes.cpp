// SPDX-License-Identifier: GPL-3.0-or-later
#include "routes.h"
#include "netlink.h"
#include "store/network_config.h"
#include "services/context.h"
#include <algorithm>
#include <arpa/inet.h>
#include <set>
#include <system_error>

namespace droidvm::network {
namespace {
[[noreturn]] void invalid(const char* text) { throw ServiceError(ErrorCode::io_error, text); }
[[noreturn]] void conflict(const char* text) { throw ServiceError(ErrorCode::conflict, text); }
template<class T> T scalar(const rtattr* a) {
    if (RTA_PAYLOAD(a) != sizeof(T)) invalid("invalid route attribute");
    T value; memcpy(&value, RTA_DATA(a), sizeof(value)); return value;
}
std::string canonical(const std::string& text, bool ipv6) {
    const auto prefix = config::NetworkPrefix::parse(text, ipv6);
    return prefix.network();
}
bool key(const Route& a, const Route& b) { return a.ipv6 == b.ipv6 && a.table == b.table && a.prefix == b.prefix; }
bool exact(const Route& a, const Route& b) {
    return key(a, b) && a.simple && !a.preferred_source && a.output == b.output && a.metric == b.metric &&
        a.protocol == b.protocol && a.scope == b.scope && a.type == b.type;
}
bool connected(const Route& a, const Route& b) {
    return key(a, b) && a.simple && a.output == b.output && a.protocol == RTPROT_KERNEL &&
        (a.type == RTN_UNICAST || (a.table == RT_TABLE_LOCAL && (a.type == RTN_LOCAL || a.type == RTN_BROADCAST)));
}
Route from_record(const Json::Value& record) {
    Route route; route.ipv6 = record["ipv6"].asBool(); route.simple = true;
    route.prefix = record["prefix"].asString(); route.table = record["table"].asUInt();
    route.output = record["link"]["index"].asUInt(); route.metric = link_cookie(record["link"]);
    route.protocol = OwnedRoutes::protocol; route.type = RTN_UNICAST;
    route.scope = route.ipv6 ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
    return route;
}
}
std::vector<Route> routes(bool ipv6) {
    NetlinkMessage<rtmsg> request;
    request.header.nlmsg_type = RTM_GETROUTE; request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.payload.rtm_family = ipv6 ? AF_INET6 : AF_INET;
    std::vector<Route> result;
    try {
        for (const auto& bytes : netlink_exchange(request.header, RTM_NEWROUTE)) {
            const auto* header = reinterpret_cast<const nlmsghdr*>(bytes.data());
            if (header->nlmsg_len < NLMSG_LENGTH(sizeof(rtmsg))) invalid("short route snapshot");
            const auto* row = reinterpret_cast<const rtmsg*>(NLMSG_DATA(header));
            if (row->rtm_family != request.payload.rtm_family || row->rtm_dst_len > (ipv6 ? 128 : 32)) invalid("invalid route snapshot family or prefix");
            Route route; route.ipv6 = ipv6; route.table = row->rtm_table; route.protocol = row->rtm_protocol;
            route.scope = row->rtm_scope; route.type = row->rtm_type;
            // Carrier/offload status can change after installation (an empty
            // bridge reports LINKDOWN). These are not route selectors; ONLINK,
            // cloned routes and other semantic flags must still be rejected.
            constexpr uint32_t status_flags = RTNH_F_DEAD | RTNH_F_LINKDOWN | RTNH_F_OFFLOAD | RTNH_F_TRAP |
                RTM_F_OFFLOAD | RTM_F_TRAP | RTM_F_OFFLOAD_FAILED;
            route.simple = !row->rtm_src_len && !row->rtm_tos && !(row->rtm_flags & ~status_flags);
            std::array<unsigned char, 16> address{};
            auto length = static_cast<int>(RTM_PAYLOAD(header));
            std::set<uint16_t> seen;
            for (const auto* a = RTM_RTA(row); RTA_OK(a, length); a = RTA_NEXT(a, length)) {
                if (!seen.insert(a->rta_type).second) invalid("duplicate route attribute");
                switch (a->rta_type) {
                    case RTA_TABLE: route.table = scalar<uint32_t>(a); break;
                    case RTA_OIF: route.output = scalar<uint32_t>(a); break;
                    case RTA_PRIORITY: route.metric = scalar<uint32_t>(a); break;
                    case RTA_DST:
                        if (RTA_PAYLOAD(a) != (ipv6 ? 16u : 4u)) invalid("invalid route destination");
                        memcpy(address.data(), RTA_DATA(a), RTA_PAYLOAD(a)); break;
                    case RTA_PREFSRC:
                        if (RTA_PAYLOAD(a) != (ipv6 ? 16u : 4u)) invalid("invalid route preferred source");
                        route.preferred_source = true; break;
                    case RTA_PREF: if (scalar<uint8_t>(a)) route.simple = false; break;
                    case RTA_CACHEINFO: {
                        const auto cache = scalar<rta_cacheinfo>(a);
                        if (cache.rta_expires || cache.rta_error) route.simple = false;
                        break;
                    }
                    default: route.simple = false; break;
                }
            }
            if (length || (row->rtm_dst_len && !seen.contains(RTA_DST))) invalid("malformed route snapshot");
            char text[INET6_ADDRSTRLEN];
            if (!inet_ntop(request.payload.rtm_family, address.data(), text, sizeof(text))) invalid("invalid route destination bytes");
            route.prefix = canonical(std::string(text) + "/" + std::to_string(row->rtm_dst_len), ipv6);
            result.push_back(std::move(route));
        }
    } catch (const std::system_error& error) { throw ServiceError(ErrorCode::io_error, error.what()); }
    return result;
}
std::vector<uint32_t> referenced_route_tables(const std::vector<PolicyRule>& rules) {
    std::vector<uint32_t> result; std::set<uint32_t> seen;
    for (const auto& rule : rules) if (rule.lookup && rule.table && seen.insert(rule.table).second) result.push_back(rule.table);
    return result;
}
void change_route(const Route& route, bool add) {
    if (!route.table || !route.output || route.output > INT32_MAX || !route.metric || !route.protocol ||
        !route.simple || route.preferred_source || route.type != RTN_UNICAST || route.scope != (route.ipv6 ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK))
        throw ServiceError(ErrorCode::invalid_argument, "invalid owned direct route identity");
    const auto prefix = config::NetworkPrefix::parse(route.prefix, route.ipv6);
    if (route.prefix != canonical(route.prefix, route.ipv6)) throw ServiceError(ErrorCode::invalid_argument, "route destination must be canonical");
    NetlinkMessage<rtmsg> message;
    message.header.nlmsg_type = add ? RTM_NEWROUTE : RTM_DELROUTE;
    if (add) message.header.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
    message.payload.rtm_family = route.ipv6 ? AF_INET6 : AF_INET;
    message.payload.rtm_dst_len = prefix.prefix(); message.payload.rtm_protocol = route.protocol;
    message.payload.rtm_type = route.type; message.payload.rtm_scope = route.scope;
    std::array<unsigned char, 16> address{};
    if (inet_pton(message.payload.rtm_family, prefix.address().c_str(), address.data()) != 1) invalid("cannot encode route destination");
    message.attribute(RTA_DST, address.data(), route.ipv6 ? 16 : 4);
    message.attribute(RTA_TABLE, &route.table, sizeof(route.table));
    message.attribute(RTA_OIF, &route.output, sizeof(route.output));
    message.attribute(RTA_PRIORITY, &route.metric, sizeof(route.metric));
    try { netlink_exchange(message.header); }
    catch (const std::system_error& error) {
        if (!add && (error.code().value() == ESRCH || error.code().value() == ENOENT)) return;
        throw ServiceError(error.code().value() == EEXIST ? ErrorCode::conflict : ErrorCode::io_error, error.what());
    }
}
OwnedRoutes::OwnedRoutes(int directory, uid_t uid, OwnedLinks& links, Observer observer, config::JsonFile::Observer file_observer)
    : links_(links), file_(directory, "network-routes.json", uid, std::move(file_observer)), observer_(std::move(observer)) {
    const auto loaded = file_.load();
    if (loaded && loaded->recovered) invalid("network route primary is damaged; recovery requires latest inventory");
    document_ = loaded ? loaded->value : Json::Value(Json::objectValue);
    if (!loaded) { document_["schema"] = 1; document_["routes"] = Json::Value(Json::arrayValue); }
    if (document_["schema"] != 1 || !document_["routes"].isArray() || document_["routes"].size() > 4096) invalid("invalid route inventory");
    std::set<std::string> keys;
    for (const auto& row : document_["routes"]) {
        const auto& link = row["link"];
        if (!row.isObject() || !row["ipv6"].isBool() || !row["prefix"].isString() || !row["table"].isUInt() || !row["table"].asUInt() ||
            (row["stage"] != "pending" && row["stage"] != "owned") || !link.isObject() || !link["owner"].isString() ||
            link["owner"].asString().empty() || !link["name"].isString() || !link["index"].isUInt() || !link["index"].asUInt() ||
            !link["boot"].isString() || !link["tag"].isString() || !link["namespace_device"].isUInt64() || !link["namespace_inode"].isUInt64())
            invalid("invalid route ownership record");
        Netbox::interface_name(link["name"].asString()); link_cookie(link);
        const auto route = from_record(row);
        if (route.prefix != canonical(route.prefix, route.ipv6) || !keys.insert(std::to_string(route.ipv6) + ":" + std::to_string(route.table) + ":" + route.prefix).second)
            invalid("noncanonical or duplicate route ownership record");
    }
}
void OwnedRoutes::save(Json::Value next) {
    try { file_.save(next); }
    catch (const config::CommitError& error) { if (error.installed) document_ = std::move(next); throw; }
    document_ = std::move(next);
}
void OwnedRoutes::check_identity(const Json::Value& row) const {
    const auto& link = row["link"];
    if (!same_scope(link, links_.scope()) || !same_link(link, links_.identity(link["owner"].asString(), link["name"].asString())))
        conflict("route interface identity or namespace changed");
}
void OwnedRoutes::remove_at(Json::ArrayIndex index) {
    const auto record = document_["routes"][index]; const auto route = from_record(record);
    if (record["link"]["boot"] == links_.scope()["boot"]) {
        if (!same_scope(record["link"], links_.scope())) conflict("route network namespace changed");
        size_t count = 0; bool foreign = false;
        for (const auto& live : routes(route.ipv6)) if (key(live, route)) {
            if (connected(live, route)) continue;
            if (exact(live, route)) ++count; else foreign = true;
        }
        if (count > 1) conflict("ambiguous duplicate route");
        if (!count && foreign) conflict("route was replaced or acquired a foreign selector");
        if (count) {
            check_identity(record); point("before_route_delete");
            change_route(route, false); point("route_deleted");
            for (const auto& live : routes(route.ipv6)) if (exact(live, route)) conflict("route deletion did not converge");
        }
    }
    auto next = document_; next["routes"].removeIndex(index, nullptr); save(std::move(next)); point("route_record_removed");
}
void OwnedRoutes::reconcile(const std::string& owner, const std::string& output, bool ipv6,
                            const std::vector<std::string>& prefixes, const std::vector<uint32_t>& tables) {
    Netbox::interface_name(output);
    std::set<std::string> unique_prefixes;
    for (const auto& prefix : prefixes) unique_prefixes.insert(canonical(prefix, ipv6));
    std::set<uint32_t> unique_tables(tables.begin(), tables.end());
    if (unique_tables.contains(0) || unique_tables.size() > 4096 || unique_prefixes.size() > 4096 ||
        (!unique_tables.empty() && unique_prefixes.size() > 4096 / unique_tables.size()))
        throw ServiceError(ErrorCode::resource_exhausted, "invalid or excessive return route set");
    std::lock_guard guard(mutex_);
    const auto identity = unique_tables.empty() || unique_prefixes.empty() ? Json::Value() : links_.identity(owner, output);
    std::vector<Json::Value> desired;
    for (const auto table : unique_tables) for (const auto& prefix : unique_prefixes) {
        Json::Value row; row["link"] = identity; row["table"] = table; row["prefix"] = prefix;
        row["ipv6"] = ipv6; row["stage"] = "pending"; desired.push_back(std::move(row));
    }
    const auto snapshot = routes(ipv6);
    // Preflight ALL destinations. Reuse only kernel dependents of this same
    // interface. Never replace an external equal-prefix route to win priority.
    for (const auto& row : desired) {
        const auto route = from_record(row);
        for (const auto& record : document_["routes"]) if (key(from_record(record), route) && !same_link(record["link"], identity))
            conflict("route destination belongs to another interface or owner");
        for (const auto& live : snapshot) if (key(live, route)) {
            bool ours = false;
            for (const auto& record : document_["routes"]) if (key(from_record(record), route) && exact(live, from_record(record))) ours = true;
            if (!ours && !connected(live, route)) conflict("foreign route occupies return subnet");
        }
    }
    // Remove obsolete records for this interface/family, retaining unchanged
    // entries so routine polls do not cause route churn or storage writes.
    for (auto i = document_["routes"].size(); i > 0; --i) {
        const auto record = document_["routes"][i - 1];
        if (record["link"]["name"] != output || record["ipv6"] != ipv6) continue;
        if (record["link"]["owner"] != owner) conflict("return routes belong to another owner");
        const auto route = from_record(record);
        bool wanted = false;
        for (const auto& row : desired) if (key(route, from_record(row))) { wanted = true; break; }
        if (!wanted) remove_at(i - 1);
    }
    for (const auto& wanted : desired) {
        const auto route = from_record(wanted);
        const auto fresh = routes(ipv6);
        Json::ArrayIndex index = document_["routes"].size();
        for (Json::ArrayIndex i = 0; i < document_["routes"].size(); ++i) if (key(from_record(document_["routes"][i]), route)) { index = i; break; }
        size_t own = 0, borrowed = 0;
        for (const auto& live : fresh) if (key(live, route)) {
            if (index < document_["routes"].size() && exact(live, route)) ++own;
            else if (connected(live, route)) ++borrowed;
            else conflict("return route changed during reconciliation");
        }
        if (own > 1 || borrowed > 1) conflict("ambiguous return route set");
        if (own && borrowed) { remove_at(index); check_identity(wanted); continue; }
        if (own) {
            check_identity(wanted);
            if (document_["routes"][index]["stage"] != "owned") {
                auto next = document_; next["routes"][index]["stage"] = "owned"; save(std::move(next));
            }
            continue;
        }
        if (index < document_["routes"].size()) remove_at(index);
        if (borrowed) { check_identity(wanted); continue; }
        if (document_["routes"].size() >= 4096) throw ServiceError(ErrorCode::resource_exhausted, "return route inventory full");
        check_identity(wanted);
        auto next = document_; index = next["routes"].size(); next["routes"].append(wanted);
        save(std::move(next)); point("route_intent_saved");
        change_route(route, true); point("route_created");
        size_t count = 0;
        for (const auto& live : routes(ipv6)) if (key(live, route)) {
            if (!exact(live, route)) conflict("created route identity differs");
            ++count;
        }
        if (count != 1) conflict("created route absent or ambiguous");
        check_identity(wanted);
        next = document_; next["routes"][index]["stage"] = "owned";
        save(std::move(next)); point("route_identity_saved");
    }
}
Json::Value OwnedRoutes::cleanup_locked(const std::string* owner) {
    Json::Value errors(Json::arrayValue);
    for (auto i = document_["routes"].size(); i > 0; --i) {
        const auto record = document_["routes"][i - 1];
        if (owner && record["link"]["owner"] != *owner) continue;
        try { remove_at(i - 1); }
        catch (const std::exception& error) {
            Json::Value failure; failure["name"] = record["link"]["name"]; failure["error"] = error.what(); errors.append(std::move(failure));
        }
    }
    return errors;
}
Json::Value OwnedRoutes::cleanup(const std::string& owner) { std::lock_guard guard(mutex_); return cleanup_locked(&owner); }
Json::Value OwnedRoutes::recover_all() { std::lock_guard guard(mutex_); return cleanup_locked(nullptr); }
Json::Value OwnedRoutes::inventory() const { std::lock_guard guard(mutex_); return document_; }
}
