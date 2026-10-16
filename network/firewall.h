// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "store/json_file.h"
#include "runtime/child.h"
#include <mutex>

namespace droidvm::network {
// Typed rule grammar: configuration never supplies an iptables operation,
// module name, shell expression or executable. Only built-in hooks are used.
struct FirewallRule {
    bool ipv6 = false, negate_output = false, established = false;
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
    Iptables(std::string ipv4 = "/system/bin/iptables", std::string ipv6 = "/system/bin/ip6tables");
    size_t tagged(const FirewallRule& rule, const std::string& tag) const;
    bool contains(const FirewallRule& rule, const std::string& tag) const;
    void insert(const FirewallRule& rule, const std::string& tag) const;
    void erase(const FirewallRule& rule, const std::string& tag) const;
private:
    std::array<std::string, 2> executable_;
    ChildOutput run(const FirewallRule& rule, const std::string& operation, const std::string& tag = {}) const;
};
// Durable individual rule ownership, not a complete firewall policy planner.
// Caller holds the daemon instance lock. Insertion is at the hook's head; a
// policy builder must arrange order and stage guards before publishing ready.
// Never adopt/flush existing chains or remove a rule based on its line number.
class OwnedFirewall {
public:
    using Observer = std::function<void(const char*)>;
    OwnedFirewall(int directory, uid_t owner, const Iptables& iptables, Observer observer = {},
                  config::JsonFile::Observer file_observer = {});
    void put(const std::string& owner, const std::string& key, const FirewallRule& rule);
    void remove(const std::string& owner, const std::string& key);
    Json::Value cleanup(const std::string& owner);
    Json::Value recover_all(); // startup, after helpers and before link cleanup
    Json::Value inventory() const;
private:
    const Iptables& iptables_;
    config::JsonFile file_;
    Observer observer_;
    Json::Value scope_, document_;
    mutable std::mutex mutex_;
    void save(Json::Value next);
    void remove_at(Json::ArrayIndex index);
    Json::Value cleanup_locked(const std::string* owner);
    void point(const char* stage) { if (observer_) observer_(stage); }
};
}
