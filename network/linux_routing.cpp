// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_routing.h"
#include "store/network_config.h"
#include "services/context.h"
#include "common/wire.h"
#include <set>

namespace droidvm::network {
RoutingTables RoutingTables::from(const std::vector<PolicyRule>& ipv4, const std::vector<PolicyRule>& ipv6) {
    RoutingTables result;
    for (const bool family : {false, true}) {
        const auto& rows = family ? ipv6 : ipv4;
        result.upstream[family] = local_app_tables(rows); result.returns[family] = referenced_route_tables(rows);
    }
    return result;
}
std::vector<VlanRoutes> linux_route_plan(const LinuxPlan& plan, const PdAddresses& pd) {
    for (const auto& [id, address] : pd) {
        bool found = false;
        for (const auto& vlan : plan.vlans) if (vlan.id == id && vlan.pd) found = true;
        if (!found || address.empty()) throw ServiceError(ErrorCode::invalid_argument, "live PD address is not for a configured PD VLAN");
        config::NetworkPrefix::parse(address, true);
    }
    std::vector<VlanRoutes> result;
    for (const auto& vlan : plan.vlans) {
        VlanRoutes row; row.device = vlan.device;
        for (const bool ipv6 : {false, true}) {
            std::set<std::string> unique;
            auto add = [&](const std::string& address) {
                const auto prefix = config::NetworkPrefix::parse(address, ipv6).network();
                if (unique.insert(prefix).second) row.prefixes[ipv6].push_back(prefix);
            };
            for (const auto& address : vlan.addresses[ipv6]) add(address);
            if (ipv6 && vlan.pd) if (const auto at = pd.find(vlan.id); at != pd.end()) add(at->second);
        }
        result.push_back(std::move(row));
    }
    return result;
}
namespace {
void validate_tables(const RoutingTables& tables) {
    for (const bool family : {false, true}) {
        for (const auto* values : {&tables.upstream[family], &tables.returns[family]}) {
            const std::set<uint32_t> unique(values->begin(), values->end());
            if (unique.contains(0) || unique.size() != values->size() || values->size() > (values == &tables.upstream[family] ? 1000u : 4096u))
                throw ServiceError(ErrorCode::invalid_argument, "invalid routing table snapshot");
        }
    }
}
}
LinuxRouting::LinuxRouting(Json::Value config, OwnedRules& rules, OwnedRoutes& routes)
    : plan_(linux_plan(std::move(config))), rules_(rules), routes_(routes) {}
void LinuxRouting::apply_rules(const RoutingTables& tables) {
    for (const auto& vlan : plan_.vlans) for (const bool family : {false, true})
        rules_.reconcile(plan_.owner, vlan.device, family, tables.upstream[family]);
}
void LinuxRouting::apply_routes(const std::vector<VlanRoutes>& desired, const RoutingTables& tables) {
    for (const auto& vlan : desired) for (const bool family : {false, true})
        routes_.reconcile(plan_.owner, vlan.device, family, vlan.prefixes[family], tables.returns[family]);
}
void LinuxRouting::reconcile(const PdAddresses& pd, const RoutingTables& tables) {
    if (stopped_) throw ServiceError(ErrorCode::conflict, "Linux routing is stopped");
    const auto desired = linux_route_plan(plan_, pd); validate_tables(tables);
    apply_rules(tables); apply_routes(desired, tables);
}
void LinuxRouting::refresh(const PdAddresses& pd) {
    if (stopped_) throw ServiceError(ErrorCode::conflict, "Linux routing is stopped");
    const auto desired = linux_route_plan(plan_, pd);
    auto tables = RoutingTables::from(policy_rules(false), policy_rules(true));
    validate_tables(tables); apply_rules(tables);
    // Our previous chain may itself have referenced a now-departed netd table.
    // Re-read after updating egress before deciding which return routes remain.
    tables = RoutingTables::from(policy_rules(false), policy_rules(true));
    validate_tables(tables); apply_routes(desired, tables);
}
void LinuxRouting::stop() {
    stopped_ = true;
    auto failures = rules_.cleanup(plan_.owner);
    for (const auto& failure : routes_.cleanup(plan_.owner)) failures.append(failure);
    if (!failures.empty()) throw ServiceError(ErrorCode::io_error, "Linux routing cleanup incomplete: " + wire::stringify(failures));
}
}
