// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "store/json_file.h"
#include "runtime/child.h"
#include <mutex>
#include <map>

namespace droidvm::network {
// Typed rule grammar: configuration never supplies an iptables operation,
// module name, shell expression or executable. Only built-in hooks are used.
struct FirewallRule {
    bool ipv6 = false, negate_output = false, established = false;
    bool input_prefix = false, output_prefix = false; // typed suffix '+'; names remain literal stems
    std::string table = "filter", chain = "FORWARD";
    std::string input, output, source, destination, protocol;
    uint16_t port_first = 0, port_last = 0;
    std::string target = "ACCEPT", translated_address;
    uint16_t translated_first = 0, translated_last = 0;
    Json::Value json() const;
    static FirewallRule from(const Json::Value& value);
    std::vector<std::string> arguments() const; // validates and normalizes CIDRs
};
class Iptables {
public:
    struct TaggedRule { FirewallRule rule; std::string tag; };
    Iptables(std::string ipv4 = "/system/bin/iptables", std::string ipv6 = "/system/bin/ip6tables",
        std::string restore4 = "/system/bin/iptables-restore", std::string restore6 = "/system/bin/ip6tables-restore");
    size_t tagged(const FirewallRule& rule, const std::string& tag) const;
    std::map<std::string, size_t> tags(const FirewallRule& scope) const;
    bool contains(const FirewallRule& rule, const std::string& tag) const;
    bool contains_all(const std::vector<TaggedRule>& rules) const;
    void insert(const FirewallRule& rule, const std::string& tag, int barrier = -1) const;
    void erase(const FirewallRule& rule, const std::string& tag, int barrier = -1) const;
    // One family/table, one COMMIT. Complete-spec deletions then head insertions
    // in caller order. No chain declarations, policy changes, flush or shell.
    void replace(const std::vector<TaggedRule>& before, const std::vector<TaggedRule>& after, int barrier = -1) const;
    bool at_head(const std::vector<TaggedRule>& rules) const;
    bool in_order(const std::vector<TaggedRule>& rules) const;
private:
    std::array<std::string, 2> executable_, restore_;
    ChildOutput run(const FirewallRule& rule, const std::string& operation, const std::string& tag = {}, int barrier = -1) const;
    ChildOutput transaction(const std::vector<TaggedRule>& before, const std::vector<TaggedRule>& after, int barrier, bool check_only) const;
    std::vector<std::vector<std::string>> snapshot(const FirewallRule& rule) const;
    bool ordered(const std::vector<TaggedRule>& rules, bool require_head) const;
};
// Durable rule ownership and single-table revision, not a policy planner.
// Caller holds the daemon instance lock and serializes intersecting policies.
// put() inserts at the head; replace_table() publishes one ordered table slice.
// Cross-family/table policy changes still need guards before publishing ready.
// Never adopt/flush existing chains or remove a rule based on its line number.
class OwnedFirewall {
public:
    using Observer = std::function<void(const char*)>;
    OwnedFirewall(int directory, uid_t owner, const Iptables& iptables, Observer observer = {},
                  config::JsonFile::Observer file_observer = {});
    void put(const std::string& owner, const std::string& key, const FirewallRule& rule);
    struct Rule { std::string key; FirewallRule rule; };
    // Reconcile this owner's entire family/table slice. Other owners/tables are
    // preserved. Updates insert at each hook's head, but unchanged rules may
    // follow/interleave foreign rules while retaining their own relative order.
    // require_head is reserved for transient cross-table protection. Journal both
    // generations before the atomic kernel update; retry/recovery handles either.
    void replace_table(const std::string& owner, bool ipv6, const std::string& table, const std::vector<Rule>& desired, bool require_head = false);
    // Read-only convergence check, including rule identity, hook order and
    // confirmed journal durability. Ownership conflicts still throw.
    bool matches_table(const std::string& owner, bool ipv6, const std::string& table, const std::vector<Rule>& desired, bool require_head = false) const;
    void remove(const std::string& owner, const std::string& key);
    Json::Value cleanup(const std::string& owner);
    Json::Value recover_all(); // startup, after helpers and before link cleanup
    Json::Value inventory() const;
private:
    const Iptables& iptables_;
    Fd directory_;
    config::JsonFile file_;
    Observer observer_;
    Json::Value scope_, document_;
    bool uncertain_ = false;
    mutable std::mutex mutex_;
    struct TableState {
        Json::Value retained, present;
        std::vector<Iptables::TaggedRule> before;
        std::map<std::string, size_t> tags;
        bool matched;
    };
    TableState inspect_table(const std::string& owner, bool ipv6, const std::string& table, const std::vector<Rule>& desired, bool require_head) const;
    void save(Json::Value next);
    Fd barrier() const;
    void remove_at(Json::ArrayIndex index, int barrier);
    Json::Value cleanup_locked(const std::string* owner);
    void point(const char* stage) { if (observer_) observer_(stage); }
};
}
