// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "links.h"
#include <optional>

namespace droidvm::network {
// The bundle's rule CLI cannot distinguish ownership protocol or all selectors.
// Use the shared Linux UAPI adapter for exact, bounded rule snapshots/mutations.
struct PolicyRule {
    // plain means no traffic selector apart from a possible mark with mask 0.
    bool ipv6 = false, lookup = false, plain = false, detached = false;
    uint32_t priority = 0, table = 0;
    uint8_t protocol = 0;
    std::string input;
    std::optional<uint32_t> mark, mask;
};
std::vector<PolicyRule> policy_rules(bool ipv6);
// Same netd table selection as DefaultRouterWatcher, preserving kernel order.
std::vector<uint32_t> local_app_tables(const std::vector<PolicyRule>& rules);
// Low-level primitive: nonzero ownership mark + zero mask is mandatory.
// Used only behind the inventory or in isolated tests.
void change_policy_rule(const PolicyRule& rule, bool add);

class OwnedRules {
public:
    using Observer = std::function<void(const char*)>;
    static constexpr uint8_t protocol = 186;
    static constexpr uint32_t priority_base = 9000;
    OwnedRules(int directory, uid_t uid, OwnedLinks& links, Observer observer = {},
               config::JsonFile::Observer file_observer = {});
    // Caller serializes network operations, retains its configuration lease,
    // and stops DHCP/PD before removing this chain, then releases the links.
    // Empty tables removes just this registered chain. Foreign rules survive.
    void reconcile(const std::string& owner, const std::string& input, bool ipv6,
                   const std::vector<uint32_t>& tables);
    Json::Value cleanup(const std::string& owner);
    Json::Value recover_all(); // before OwnedLinks::recover_all at startup
    Json::Value inventory() const;
private:
    OwnedLinks& links_;
    config::JsonFile file_;
    Observer observer_;
    mutable std::mutex mutex_;
    Json::Value document_;
    void save(Json::Value next);
    void remove_at(Json::ArrayIndex index);
    Json::Value cleanup_locked(const std::string* owner);
    void check_identity(const Json::Value& row, bool detached) const;
    void point(const char* stage) { if (observer_) observer_(stage); }
};
}
