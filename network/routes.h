// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "links.h"
#include "policy_rules.h"

namespace droidvm::network {
struct Route {
    bool ipv6 = false, simple = false, preferred_source = false;
    uint32_t table = 0, output = 0, metric = 0;
    uint8_t protocol = 0, scope = 0, type = 0;
    std::string prefix; // canonical network/prefixlen
};
std::vector<Route> routes(bool ipv6);
std::vector<uint32_t> referenced_route_tables(const std::vector<PolicyRule>& rules);
// Exact create/delete for a plain direct subnet route. Never uses REPLACE.
void change_route(const Route& route, bool add);

class OwnedRoutes {
public:
    using Observer = std::function<void(const char*)>;
    static constexpr uint8_t protocol = 186;
    OwnedRoutes(int directory, uid_t uid, OwnedLinks& links, Observer observer = {},
                config::JsonFile::Observer file_observer = {});
    // Reflect the given subnets into the supplied policy tables for this one
    // owned output interface. Kernel-created connected/local routes on the
    // same owned interface are reused, never recorded as ours or removed.
    void reconcile(const std::string& owner, const std::string& output, bool ipv6,
                   const std::vector<std::string>& prefixes, const std::vector<uint32_t>& tables);
    Json::Value cleanup(const std::string& owner);
    Json::Value recover_all(); // after helpers/rules, before links
    Json::Value inventory() const;
private:
    OwnedLinks& links_;
    config::JsonFile file_;
    Observer observer_;
    mutable std::mutex mutex_;
    Json::Value document_;
    void save(Json::Value next);
    void remove_at(Json::ArrayIndex index);
    void check_identity(const Json::Value& row) const;
    Json::Value cleanup_locked(const std::string* owner);
    void point(const char* stage) { if (observer_) observer_(stage); }
};
}
