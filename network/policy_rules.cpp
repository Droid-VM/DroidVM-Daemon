// SPDX-License-Identifier: GPL-3.0-or-later
#include "policy_rules.h"
#include "netlink.h"
#include "services/context.h"
#include <algorithm>
#include <charconv>
#include <linux/fib_rules.h>
#include <net/if.h>
#include <set>
#include <system_error>

namespace droidvm::network {
namespace {
[[noreturn]] void invalid(const char* message) { throw ServiceError(ErrorCode::io_error, message); }
[[noreturn]] void conflict(const char* message) { throw ServiceError(ErrorCode::conflict, message); }
template<class T> T scalar(const rtattr* attribute) {
    if (RTA_PAYLOAD(attribute) != sizeof(T)) invalid("invalid routing rule attribute");
    T value; memcpy(&value, RTA_DATA(attribute), sizeof(value)); return value;
}
bool key(const PolicyRule& a, const PolicyRule& b) {
    return a.ipv6 == b.ipv6 && a.input == b.input && a.priority == b.priority;
}
bool exact(const PolicyRule& a, const PolicyRule& b) {
    return key(a, b) && a.lookup && a.plain && a.table == b.table && a.protocol == b.protocol &&
        a.mark == b.mark && a.mask.value_or(0) == b.mask.value_or(0);
}
bool same_scope(const Json::Value& a, const Json::Value& b) {
    return a["boot"] == b["boot"] && a["namespace_device"].asUInt64() == b["namespace_device"].asUInt64() &&
        a["namespace_inode"].asUInt64() == b["namespace_inode"].asUInt64();
}
bool same_link(const Json::Value& a, const Json::Value& b) {
    return same_scope(a, b) && a["index"].asUInt() == b["index"].asUInt() && a["tag"] == b["tag"] &&
        a["owner"] == b["owner"] && a["name"] == b["name"];
}
PolicyRule from_record(const Json::Value& row) {
    PolicyRule rule; rule.ipv6 = row["ipv6"].asBool(); rule.lookup = rule.plain = true;
    rule.priority = row["priority"].asUInt(); rule.table = row["table"].asUInt();
    rule.protocol = OwnedRules::protocol; rule.input = row["link"]["name"].asString();
    // A nonzero mark with an explicitly ZERO mask matches all packet marks.
    // It gives DELRULE a nonzero ownership selector without changing routing.
    const auto tag = row["link"]["tag"].asString();
    uint32_t cookie = 0; std::from_chars(tag.data() + 8, tag.data() + 16, cookie, 16);
    rule.mark = cookie ? cookie : 1; rule.mask = 0;
    return rule;
}
}
std::vector<PolicyRule> policy_rules(bool ipv6) {
    NetlinkMessage<fib_rule_hdr> request;
    request.header.nlmsg_type = RTM_GETRULE;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.payload.family = ipv6 ? AF_INET6 : AF_INET;
    std::vector<PolicyRule> result;
    try {
        for (const auto& bytes : netlink_exchange(request.header, RTM_NEWRULE)) {
            const auto* header = reinterpret_cast<const nlmsghdr*>(bytes.data());
            if (header->nlmsg_len < NLMSG_LENGTH(sizeof(fib_rule_hdr))) invalid("short routing rule snapshot");
            const auto* row = reinterpret_cast<const fib_rule_hdr*>(NLMSG_DATA(header));
            if (row->family != request.payload.family) invalid("unexpected routing rule family");
            PolicyRule rule; rule.ipv6 = ipv6; rule.lookup = row->action == FR_ACT_TO_TBL;
            rule.table = row->table;
            rule.detached = row->flags & FIB_RULE_IIF_DETACHED;
            rule.plain = rule.lookup && !row->src_len && !row->dst_len && !row->tos &&
                !(row->flags & ~FIB_RULE_IIF_DETACHED);
            auto size = static_cast<int>(header->nlmsg_len - NLMSG_LENGTH(sizeof(*row)));
            std::set<uint16_t> seen;
            const auto* start = reinterpret_cast<const char*>(row) + NLMSG_ALIGN(sizeof(*row));
            for (const auto* a = reinterpret_cast<const rtattr*>(start); RTA_OK(a, size); a = RTA_NEXT(a, size)) {
                if (!seen.insert(a->rta_type).second) invalid("duplicate routing rule attribute");
                switch (a->rta_type) {
                    case FRA_PRIORITY: rule.priority = scalar<uint32_t>(a); break;
                    case FRA_TABLE: rule.table = scalar<uint32_t>(a); break;
                    case FRA_PROTOCOL: rule.protocol = scalar<uint8_t>(a); break;
                    case FRA_IIFNAME: {
                        const auto count = RTA_PAYLOAD(a);
                        const auto* text = reinterpret_cast<const char*>(RTA_DATA(a));
                        if (!count || count > IFNAMSIZ || text[count - 1] || strnlen(text, count) != count - 1)
                            invalid("invalid routing rule interface");
                        rule.input.assign(text, count - 1); break;
                    }
                    case FRA_FWMARK: rule.mark = scalar<uint32_t>(a); break;
                    case FRA_FWMASK: rule.mask = scalar<uint32_t>(a); if (*rule.mask) rule.plain = false; break;
                    case FRA_SUPPRESS_PREFIXLEN:
                    case FRA_SUPPRESS_IFGROUP: if (scalar<uint32_t>(a) != UINT32_MAX) rule.plain = false; break;
                    case FRA_PAD: if (RTA_PAYLOAD(a)) rule.plain = false; break;
                    default: rule.plain = false; break;
                }
            }
            if (size) invalid("malformed routing rule attributes");
            result.push_back(std::move(rule));
        }
    } catch (const std::system_error& error) { throw ServiceError(ErrorCode::io_error, error.what()); }
    return result;
}
std::vector<uint32_t> local_app_tables(const std::vector<PolicyRule>& rules) {
    std::vector<uint32_t> result;
    std::set<uint32_t> seen;
    for (const auto& rule : rules)
        if (rule.lookup && rule.input == "lo" && rule.mask && rule.mark.value_or(0) == 0 && rule.table && seen.insert(rule.table).second)
            result.push_back(rule.table);
    return result;
}
void change_policy_rule(const PolicyRule& rule, bool add) {
    Netbox::interface_name(rule.input);
    if (!rule.table || !rule.priority || !rule.protocol || !rule.lookup || !rule.plain || !rule.mark.value_or(0) || rule.mask.value_or(0))
        throw ServiceError(ErrorCode::invalid_argument, "missing policy rule identity");
    NetlinkMessage<fib_rule_hdr> message;
    message.header.nlmsg_type = add ? RTM_NEWRULE : RTM_DELRULE;
    if (add) message.header.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
    message.payload.family = rule.ipv6 ? AF_INET6 : AF_INET;
    message.payload.action = FR_ACT_TO_TBL;
    message.attribute(FRA_IIFNAME, rule.input.c_str(), rule.input.size() + 1);
    message.attribute(FRA_TABLE, &rule.table, sizeof(rule.table));
    message.attribute(FRA_PRIORITY, &rule.priority, sizeof(rule.priority));
    message.attribute(FRA_PROTOCOL, &rule.protocol, sizeof(rule.protocol));
    const uint32_t zero = 0, cookie = *rule.mark;
    message.attribute(FRA_FWMARK, &cookie, sizeof(cookie));
    message.attribute(FRA_FWMASK, &zero, sizeof(zero));
    if (!add) {
        // Zero mark is a DELRULE wildcard on supported kernels. The nonzero
        // cookie above is essential; sending explicit zero would be unsafe.
        const char empty = 0;
        message.attribute(FRA_OIFNAME, &empty, sizeof(empty));
    }
    try { netlink_exchange(message.header); }
    catch (const std::system_error& error) {
        if (!add && error.code().value() == ENOENT) return;
        throw ServiceError(error.code().value() == EEXIST ? ErrorCode::conflict : ErrorCode::io_error, error.what());
    }
}
OwnedRules::OwnedRules(int directory, uid_t uid, OwnedLinks& links, Observer observer,
                       config::JsonFile::Observer file_observer)
    : links_(links), file_(directory, "network-rules.json", uid, std::move(file_observer)), observer_(std::move(observer)) {
    const auto loaded = file_.load();
    if (loaded && loaded->recovered) invalid("network rule primary is damaged; recovery requires the latest inventory");
    document_ = loaded ? loaded->value : Json::Value(Json::objectValue);
    if (!loaded) { document_["schema"] = 1; document_["rules"] = Json::Value(Json::arrayValue); }
    if (document_["schema"] != 1 || !document_["rules"].isArray() || document_["rules"].size() > 4096)
        invalid("invalid network rule inventory");
    std::set<std::string> keys;
    for (const auto& row : document_["rules"]) {
        const auto& link = row["link"];
        if (!row.isObject() || !row["ipv6"].isBool() || !row["table"].isUInt() || !row["table"].asUInt() ||
            !row["priority"].isUInt() || row["priority"].asUInt() < priority_base || row["priority"].asUInt() >= 10000 ||
            (row["stage"] != "pending" && row["stage"] != "owned") || !link.isObject() ||
            !link["owner"].isString() || link["owner"].asString().empty() || !link["name"].isString() ||
            !link["index"].isUInt() || !link["index"].asUInt() || !link["tag"].isString() ||
            !link["boot"].isString() || !link["namespace_device"].isUInt64() || !link["namespace_inode"].isUInt64())
            invalid("invalid network rule record");
        Netbox::interface_name(link["name"].asString());
        const auto tag = link["tag"].asString();
        if (tag.size() != 40 || !tag.starts_with("droidvm:") || tag.substr(8).find_first_not_of("0123456789abcdef") != std::string::npos)
            invalid("invalid network rule link identity");
        if (!keys.insert(link["name"].asString() + ":" + std::to_string(row["ipv6"].asBool()) + ":" + std::to_string(row["priority"].asUInt())).second)
            invalid("duplicate network rule record");
    }
}
void OwnedRules::save(Json::Value next) {
    try { file_.save(next); }
    catch (const config::CommitError& error) { if (error.installed) document_ = std::move(next); throw; }
    document_ = std::move(next);
}
void OwnedRules::check_identity(const Json::Value& row, bool detached) const {
    const auto& link = row["link"];
    const auto scope = links_.scope();
    if (!same_scope(link, scope))
        conflict("policy rule network namespace changed");
    const auto name = link["name"].asString();
    if (!if_nametoindex(name.c_str())) {
        if (errno != ENODEV && errno != ENXIO) invalid("cannot resolve policy rule interface identity");
        if (detached) return;
        conflict("policy rule interface disappeared without detaching");
    }
    const auto live = links_.identity(link["owner"].asString(), name);
    if (!same_link(live, link))
        conflict("policy rule interface identity changed");
}
void OwnedRules::remove_at(Json::ArrayIndex index) {
    const auto record = document_["rules"][index];
    const auto rule = from_record(record);
    if (record["link"]["boot"] == links_.scope()["boot"]) {
        const auto scope = links_.scope();
        if (!same_scope(record["link"], scope))
            conflict("policy rule network namespace changed");
        const auto rows = policy_rules(rule.ipv6);
        size_t count = 0;
        bool detached = false;
        for (const auto& current : rows) if (key(current, rule)) {
            if (!exact(current, rule)) conflict("policy rule was replaced or has a foreign selector");
            ++count; detached = current.detached;
        }
        if (count > 1) conflict("ambiguous duplicate policy rule");
        if (count) {
            check_identity(record, detached);
            point("before_rule_delete");
            change_policy_rule(rule, false);
            point("rule_deleted");
            for (const auto& current : policy_rules(rule.ipv6)) if (exact(current, rule)) conflict("policy rule removal did not converge");
        }
    }
    auto next = document_; next["rules"].removeIndex(index, nullptr); save(std::move(next));
    point("rule_record_removed");
}
void OwnedRules::reconcile(const std::string& owner, const std::string& input, bool ipv6,
                           const std::vector<uint32_t>& tables) {
    Netbox::interface_name(input);
    if (tables.size() > 1000 || std::set<uint32_t>(tables.begin(), tables.end()).size() != tables.size() ||
        std::find(tables.begin(), tables.end(), 0) != tables.end())
        throw ServiceError(ErrorCode::invalid_argument, "invalid policy routing table chain");
    std::lock_guard guard(mutex_);
    const auto identity = tables.empty() ? Json::Value() : links_.identity(owner, input);
    const auto snapshot = policy_rules(ipv6);
    std::vector<Json::ArrayIndex> registered;
    for (Json::ArrayIndex i = 0; i < document_["rules"].size(); ++i) {
        const auto& row = document_["rules"][i];
        if (row["link"]["name"] == input && row["ipv6"] == ipv6) {
            if (row["link"]["owner"] != owner) conflict("policy chain belongs to another owner");
            registered.push_back(i);
        }
    }
    bool correct = registered.size() == tables.size();
    for (size_t i = 0; i < registered.size() && correct; ++i) {
        const auto& row = document_["rules"][registered[i]];
        const auto expected = from_record(row);
        size_t matches = 0;
        for (const auto& current : snapshot) if (key(current, expected)) {
            if (!exact(current, expected) || current.detached) { correct = false; break; }
            ++matches;
        }
        correct = correct && row["stage"] == "owned" && same_link(row["link"], identity) &&
            expected.priority == priority_base + i && expected.table == tables[i] && matches == 1;
    }
    if (correct) return;
    // Refuse unknown rules before tearing down the previous working chain.
    for (const auto& current : snapshot) if (current.input == input && current.priority >= priority_base && current.priority < priority_base + tables.size()) {
        bool ours = false;
        for (const auto i : registered) if (exact(current, from_record(document_["rules"][i]))) { ours = true; break; }
        if (!ours) conflict("foreign rule occupies policy chain priority");
    }
    for (auto i = registered.rbegin(); i != registered.rend(); ++i) remove_at(*i);
    for (size_t i = 0; i < tables.size(); ++i) {
        if (document_["rules"].size() >= 4096) throw ServiceError(ErrorCode::resource_exhausted, "policy rule inventory is full");
        if (!same_link(links_.identity(owner, input), identity)) conflict("policy rule interface changed during reconciliation");
        Json::Value record; record["link"] = identity; record["ipv6"] = ipv6;
        record["table"] = tables[i]; record["priority"] = priority_base + static_cast<uint32_t>(i); record["stage"] = "pending";
        const auto rule = from_record(record);
        for (const auto& current : policy_rules(ipv6)) if (key(current, rule)) conflict("policy rule already exists");
        auto next = document_; const auto index = next["rules"].size(); next["rules"].append(record);
        save(std::move(next)); point("rule_intent_saved");
        change_policy_rule(rule, true); point("rule_created");
        size_t count = 0;
        for (const auto& current : policy_rules(ipv6)) if (key(current, rule)) {
            if (!exact(current, rule) || current.detached) conflict("created policy rule identity differs");
            ++count;
        }
        if (count != 1) conflict("created policy rule is absent or ambiguous");
        check_identity(record, false);
        next = document_; next["rules"][index]["stage"] = "owned";
        save(std::move(next)); point("rule_identity_saved");
    }
}
Json::Value OwnedRules::cleanup_locked(const std::string* owner) {
    Json::Value errors(Json::arrayValue);
    for (auto i = document_["rules"].size(); i > 0; --i) {
        const auto record = document_["rules"][i - 1];
        if (owner && record["link"]["owner"] != *owner) continue;
        try { remove_at(i - 1); }
        catch (const std::exception& error) {
            Json::Value failure; failure["name"] = record["link"]["name"]; failure["error"] = error.what();
            errors.append(std::move(failure));
        }
    }
    return errors;
}
Json::Value OwnedRules::cleanup(const std::string& owner) { std::lock_guard guard(mutex_); return cleanup_locked(&owner); }
Json::Value OwnedRules::recover_all() { std::lock_guard guard(mutex_); return cleanup_locked(nullptr); }
Json::Value OwnedRules::inventory() const { std::lock_guard guard(mutex_); return document_; }
}
