// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "linux_plan.h"
#include "routes.h"
#include <map>

namespace droidvm::network {
using PdAddresses = std::map<int, std::string>; // only authoritative live host CIDRs
struct RoutingTables {
    std::array<std::vector<uint32_t>, 2> upstream, returns;
    static RoutingTables from(const std::vector<PolicyRule>& ipv4, const std::vector<PolicyRule>& ipv6);
};
struct VlanRoutes {
    std::string device;
    std::array<std::vector<std::string>, 2> prefixes;
};
std::vector<VlanRoutes> linux_route_plan(const LinuxPlan& plan, const PdAddresses& pd);
// Serialized by the Linux backend worker under its config runtime lease.
// No private timer/thread: the shared service watcher supplies refresh calls.
class LinuxRouting {
public:
    LinuxRouting(Json::Value config, OwnedRules& rules, OwnedRoutes& routes);
    void refresh(const PdAddresses& pd); // live netd policy, including VPN ordering
    void reconcile(const PdAddresses& pd, const RoutingTables& tables); // shared watcher snapshot
    void stop(); // rejects late refreshes, keeps failed cleanup retryable
private:
    LinuxPlan plan_;
    OwnedRules& rules_;
    OwnedRoutes& routes_;
    bool stopped_ = false;
    void apply_rules(const RoutingTables& tables);
    void apply_routes(const std::vector<VlanRoutes>& desired, const RoutingTables& tables);
};
}
