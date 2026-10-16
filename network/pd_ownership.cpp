// SPDX-License-Identifier: GPL-3.0-or-later
#include "pd_ownership.h"
#include "links.h"
#include "netbox.h"
#include "netlink.h"
#include "services/context.h"
#include "common/fd.h"
#include "common/wire.h"
#include <linux/fib_rules.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <system_error>

namespace droidvm::network {
namespace {
[[noreturn]] void invalid(const char* detail) { throw ServiceError(ErrorCode::io_error, detail); }
[[noreturn]] void conflict(const std::string& detail) { throw ServiceError(ErrorCode::conflict, detail); }
uint32_t table_of(const char* body, size_t header, int size, uint32_t fallback, uint16_t attribute) {
    for (const auto* a = reinterpret_cast<const rtattr*>(body + NLMSG_ALIGN(header)); RTA_OK(a, size); a = RTA_NEXT(a, size))
        if (a->rta_type == attribute && RTA_PAYLOAD(a) == sizeof(uint32_t)) {
            uint32_t value; memcpy(&value, RTA_DATA(a), sizeof(value)); return value;
        }
    return fallback;
}
// Dumped objects of one family that select the table, as raw messages.
std::vector<std::vector<char>> table_objects(uint32_t table, bool rules, bool ipv6) {
    std::vector<std::vector<char>> result;
    if (rules) {
        NetlinkMessage<fib_rule_hdr> request;
        request.header.nlmsg_type = RTM_GETRULE; request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        request.payload.family = ipv6 ? AF_INET6 : AF_INET;
        for (auto& bytes : netlink_exchange(request.header, RTM_NEWRULE)) {
            const auto* header = reinterpret_cast<const nlmsghdr*>(bytes.data());
            if (header->nlmsg_len < NLMSG_LENGTH(sizeof(fib_rule_hdr))) invalid("short routing rule snapshot");
            const auto* row = reinterpret_cast<const fib_rule_hdr*>(NLMSG_DATA(header));
            const auto size = static_cast<int>(header->nlmsg_len - NLMSG_LENGTH(sizeof(*row)));
            if (table_of(reinterpret_cast<const char*>(row), sizeof(*row), size, row->table, FRA_TABLE) == table)
                result.push_back(std::move(bytes));
        }
    } else {
        NetlinkMessage<rtmsg> request;
        request.header.nlmsg_type = RTM_GETROUTE; request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        request.payload.rtm_family = ipv6 ? AF_INET6 : AF_INET;
        for (auto& bytes : netlink_exchange(request.header, RTM_NEWROUTE)) {
            const auto* header = reinterpret_cast<const nlmsghdr*>(bytes.data());
            if (header->nlmsg_len < NLMSG_LENGTH(sizeof(rtmsg))) invalid("short route snapshot");
            const auto* row = reinterpret_cast<const rtmsg*>(NLMSG_DATA(header));
            if (row->rtm_flags & RTM_F_CLONED) continue;
            const auto size = static_cast<int>(header->nlmsg_len - NLMSG_LENGTH(sizeof(*row)));
            if (table_of(reinterpret_cast<const char*>(row), sizeof(*row), size, row->rtm_table, RTA_TABLE) == table)
                result.push_back(std::move(bytes));
        }
    }
    return result;
}
// accept_ra 1 -> 2 and forwarding 0 -> 1, exactly as the helper changes them.
const char* target(const char* key, const std::string& original) {
    if (std::string_view(key) == "accept_ra") return original == "1" ? "2" : nullptr;
    return original == "0" ? "1" : nullptr;
}
constexpr const char* sysctl_keys[] = {"accept_ra", "forwarding"};
}
size_t pd_table_users(uint32_t table) {
    size_t count = 0;
    for (const bool rules : {true, false}) for (const bool ipv6 : {false, true}) count += table_objects(table, rules, ipv6).size();
    return count;
}
void flush_pd_table(uint32_t table) {
    // Rules first: no packet may select a half-emptied table.
    for (const bool rules : {true, false}) for (auto& bytes : table_objects(table, rules, true)) {
        auto* header = reinterpret_cast<nlmsghdr*>(bytes.data());
        header->nlmsg_type = rules ? RTM_DELRULE : RTM_DELROUTE;
        header->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK; header->nlmsg_seq = 1; header->nlmsg_pid = 0;
        try { netlink_exchange(*header); }
        catch (const std::system_error& error) {
            if (error.code().value() != ENOENT && error.code().value() != ESRCH) throw;
        }
    }
}
PdOwnership::PdOwnership(int directory, uid_t uid, Observer observer, std::string sysctl_root)
    : file_(directory, "network-pd.json", uid), observer_(std::move(observer)), sysctl_root_(std::move(sysctl_root)) {
    const auto loaded = file_.load();
    if (loaded && loaded->recovered) invalid("PD ownership primary is damaged; recovery requires latest inventory");
    document_ = loaded ? loaded->value : Json::Value(Json::objectValue);
    if (!loaded) {
        document_["schema"] = 1; document_["entries"] = Json::Value(Json::arrayValue);
        document_["uplinks"] = Json::Value(Json::objectValue);
    }
    if (document_["schema"] != 1 || !document_["entries"].isArray() || document_["entries"].size() > 4096 ||
        !document_["uplinks"].isObject() || document_["uplinks"].size() > 4096) invalid("invalid PD ownership inventory");
    for (const auto& row : document_["entries"])
        if (!row.isObject() || !row["owner"].isString() || row["owner"].asString().empty() || !row["vlan"].isInt() ||
            !row["table"].isUInt() || !row["table"].asUInt() || !row["uplink"].isString() || !row["scope"].isObject())
            invalid("invalid PD ownership record");
    for (const auto& name : document_["uplinks"].getMemberNames()) {
        const auto& row = document_["uplinks"][name];
        if (!row.isObject() || !row["scope"].isObject() || !row["accept_ra"].isString() || !row["forwarding"].isString())
            invalid("invalid PD uplink record");
    }
}
void PdOwnership::save(Json::Value next) {
    try { file_.save(next); }
    catch (const config::CommitError& error) { if (error.installed) document_ = std::move(next); throw; }
    document_ = std::move(next);
}
std::string PdOwnership::sysctl(const std::string& uplink, const char* key) const {
    const auto path = sysctl_root_ + "/" + uplink + "/" + key;
    Fd file(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (file.get() < 0) throw std::system_error(errno, std::generic_category(), "read PD uplink sysctl");
    char buffer[32]; ssize_t count;
    do { count = read(file.get(), buffer, sizeof(buffer)); } while (count < 0 && errno == EINTR);
    if (count <= 0) throw std::system_error(count < 0 ? errno : EIO, std::generic_category(), "read PD uplink sysctl");
    std::string value(buffer, static_cast<size_t>(count));
    while (!value.empty() && (value.back() == '\n' || value.back() == ' ')) value.pop_back();
    return value;
}
void PdOwnership::write_sysctl(const std::string& uplink, const char* key, const std::string& value) const {
    const auto path = sysctl_root_ + "/" + uplink + "/" + key;
    Fd file(open(path.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
    if (file.get() < 0) throw std::system_error(errno, std::generic_category(), "open PD uplink sysctl");
    const auto text = value + "\n"; ssize_t count;
    do { count = write(file.get(), text.data(), text.size()); } while (count < 0 && errno == EINTR);
    if (count < 0) throw std::system_error(errno, std::generic_category(), "write PD uplink sysctl");
    // IPv6 forwarding's handler reports 1 byte for a complete write; trust
    // only the read-back value.
    if (sysctl(uplink, key) != value) throw std::system_error(EIO, std::generic_category(), "PD uplink sysctl did not take effect");
}
void PdOwnership::acquire(const std::string& owner, int vlan, uint32_t table, const std::string& uplink) {
    Netbox::interface_name(uplink);
    if (owner.empty() || vlan < 0 || vlan > 4094 || !table) throw ServiceError(ErrorCode::invalid_argument, "invalid PD ownership request");
    std::lock_guard guard(mutex_);
    for (const auto& row : document_["entries"]) {
        if (row["owner"] == owner && row["vlan"].asInt() == vlan) {
            if (row["table"].asUInt() == table && row["uplink"] == uplink) return;
            conflict("PD delegation is already registered with different resources");
        }
        if (row["table"].asUInt() == table) conflict("PD route table is registered by another delegation");
    }
    if (pd_table_users(table)) conflict("PD route table " + std::to_string(table) + " is already in use");
    auto next = document_;
    const auto scope = network_scope();
    if (!next["uplinks"].isMember(uplink)) {
        Json::Value row; row["scope"] = scope;
        try { for (const auto* key : sysctl_keys) row[key] = sysctl(uplink, key); }
        catch (const std::system_error&) { throw ServiceError(ErrorCode::unavailable, "PD uplink " + uplink + " is not available"); }
        next["uplinks"][uplink] = std::move(row);
    } else if (!same_scope(next["uplinks"][uplink]["scope"], scope)) conflict("PD uplink record belongs to another network scope");
    Json::Value row; row["owner"] = owner; row["vlan"] = vlan; row["table"] = table; row["uplink"] = uplink; row["scope"] = scope;
    next["entries"].append(std::move(row));
    save(std::move(next)); // durable before the helper can touch the host
    point("pd_acquired");
}
void PdOwnership::release_locked(const std::string* owner) {
    const auto scope = network_scope();
    auto next = document_;
    Json::Value kept(Json::arrayValue);
    std::set<std::string> touched;
    for (const auto& row : document_["entries"]) {
        if (owner && row["owner"] != *owner) { kept.append(row); continue; }
        touched.insert(row["uplink"].asString());
        if (row["scope"]["boot"] != scope["boot"]) continue; // the kernel state died with that boot
        if (!same_scope(row["scope"], scope)) conflict("PD ownership record belongs to another network namespace");
        const auto table = row["table"].asUInt();
        flush_pd_table(table); point("pd_table_flushed");
        if (pd_table_users(table)) conflict("PD route table " + std::to_string(table) + " still has users after flush");
    }
    if (kept.size() == document_["entries"].size()) return; // nothing owned: no journal write
    next["entries"] = kept;
    for (const auto& uplink : touched) {
        const auto record = document_["uplinks"][uplink];
        if (record.isNull()) continue;
        bool shared = false;
        for (const auto& row : kept) if (row["uplink"] == uplink) shared = true;
        if (record["scope"]["boot"] == scope["boot"]) {
            if (!same_scope(record["scope"], scope)) conflict("PD uplink record belongs to another network namespace");
            for (const auto* key : sysctl_keys) {
                const auto original = record[key].asString();
                const auto* value = target(key, original);
                if (!value) continue;
                std::string current;
                try { current = sysctl(uplink, key); }
                catch (const std::system_error& error) { if (error.code().value() == ENOENT) break; throw; }
                // A clean helper stop may have restored a value a remaining
                // network still needs; any third-party value always wins.
                if (shared && current == original) write_sysctl(uplink, key, value);
                if (!shared && current == value) write_sysctl(uplink, key, original);
            }
        }
        if (!shared) next["uplinks"].removeMember(uplink);
    }
    save(std::move(next));
    point("pd_released");
}
void PdOwnership::release(const std::string& owner) { std::lock_guard guard(mutex_); release_locked(&owner); }
Json::Value PdOwnership::recover_all() {
    std::lock_guard guard(mutex_);
    Json::Value failures(Json::arrayValue);
    try { release_locked(nullptr); }
    catch (const std::exception& error) { Json::Value row; row["error"] = error.what(); failures.append(std::move(row)); }
    return failures;
}
std::set<uint32_t> PdOwnership::tables() const {
    std::lock_guard guard(mutex_);
    std::set<uint32_t> result;
    for (const auto& row : document_["entries"]) result.insert(row["table"].asUInt());
    return result;
}
Json::Value PdOwnership::inventory() const { std::lock_guard guard(mutex_); return document_; }
}
