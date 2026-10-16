// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_firewall.h"
#include "store/network_config.h"
#include "services/context.h"
#include "common/wire.h"
#include <set>

namespace droidvm::network {
LinuxFirewallPlan linux_firewall_plan(Json::Value config, const PdAddresses& pd) {
    const auto plan = linux_plan(std::move(config));
    const auto live = linux_live_plan(plan, pd);
    LinuxFirewallPlan result; result.owner = plan.owner; result.bridge = plan.bridge; result.l3 = plan.l3;
    auto append = [&](FirewallRule rule) {
        auto& rows = rule.table == "nat" ? result.nat4 : rule.table == "mangle" ? result.mangle4 : result.filter[rule.ipv6];
        rule.arguments();
        const auto key = std::string(rule.ipv6 ? "v6/" : "v4/") + rule.table + "/" + std::to_string(rows.size());
        rows.push_back({key, std::move(rule)});
    };
    if (!plan.l3) {
        FirewallRule rule; rule.input = rule.output = plan.bridge;
        append(rule); return result; // L2 bridge netfilter: exact IPv4 bridge pair
    }
    auto subnet = [&](const LinuxVlan& vlan, const std::string& cidr, bool ipv6, std::set<std::string>& seen) {
        const auto parsed = config::NetworkPrefix::parse(cidr, ipv6);
        const auto prefix = parsed.network();
        if (ipv6) {
            FirewallRule input; input.ipv6 = true; input.chain = "INPUT"; input.input = vlan.device;
            input.source = prefix; input.destination = parsed.address() + "/128"; append(input);
        }
        // The legacy IPv4 network INPUT chain is empty. Falling through is
        // intentional: ACCEPT or built-in RETURN would bypass Android rules.
        if (!seen.insert(prefix).second) return;
        for (const bool outbound : {true, false}) {
            FirewallRule rule; rule.ipv6 = ipv6;
            if (outbound) { rule.input = vlan.device; rule.source = prefix; rule.output_prefix = true; }
            else { rule.output = vlan.device; rule.destination = prefix; rule.input_prefix = true; }
            // Keep precisely the existing firewall allowlist. Host discovery
            // has additional prefixes; those must not broaden forwarding.
            for (const auto* external : {"wlan", "eth", "rmnet", "tun"}) {
                if (outbound) rule.output = external; else rule.input = external;
                append(rule);
            }
            if (outbound) { rule.output.clear(); rule.output_prefix = false; }
            else { rule.input.clear(); rule.input_prefix = false; }
            rule.target = "DROP"; append(rule); // terminal external-chain verdict
        }
        if (!ipv6 && vlan.snat4) {
            FirewallRule nat; nat.table = "nat"; nat.chain = "POSTROUTING"; nat.source = prefix;
            nat.output = plan.bridge; nat.output_prefix = true; nat.negate_output = true; nat.target = "MASQUERADE";
            append(nat);
        }
    };
    for (const bool ipv6 : {false, true}) {
        for (const bool ingress : {true, false}) {
            FirewallRule established; established.ipv6 = ipv6; established.established = true;
            if (ingress) { established.input = plan.bridge; established.input_prefix = true; }
            else { established.output = plan.bridge; established.output_prefix = true; }
            append(established);
        }
    }
    // Java inserts acquired PD rules ahead of the static/inter-VLAN rules.
    // Retain that precedence; an established flow is handled above as before.
    for (const auto& vlan : live.vlans) if (const auto at = pd.find(vlan.id); at != pd.end()) {
        std::set<std::string> seen;
        subnet(vlan, at->second, true, seen);
    }
    for (const bool ipv6 : {false, true}) {
        FirewallRule inter; inter.ipv6 = ipv6; inter.input = inter.output = plan.bridge;
        inter.input_prefix = inter.output_prefix = true; append(inter);
        FirewallRule output; output.ipv6 = ipv6; output.chain = "OUTPUT"; output.output = plan.bridge; output.output_prefix = true;
        append(output);
    }
    for (const auto& vlan : plan.vlans) for (const bool ipv6 : {false, true}) {
        std::set<std::string> seen;
        for (const auto& address : vlan.addresses[ipv6]) subnet(vlan, address, ipv6, seen);
    }
    FirewallRule mangle; mangle.table = "mangle"; mangle.chain = "PREROUTING"; mangle.input = plan.bridge; mangle.input_prefix = true;
    append(mangle);
    for (const bool ipv6 : {false, true}) for (const bool ingress : {true, false}) {
        FirewallRule drop; drop.ipv6 = ipv6; drop.target = "DROP";
        if (ingress) { drop.input = plan.bridge; drop.input_prefix = true; }
        else { drop.output = plan.bridge; drop.output_prefix = true; }
        append(drop);
    }
    return result;
}
LinuxFirewall::LinuxFirewall(OwnedFirewall& firewall, Observer observer)
    : firewall_(firewall), observer_(std::move(observer)) {
    const auto inventory = firewall_.inventory();
    for (const auto& row : inventory["rules"]) if (row["owner"] == owner_key)
        throw ServiceError(ErrorCode::conflict, "Linux firewall ownership must be recovered before constructing its coordinator");
}
LinuxFirewallPlan LinuxFirewall::compose() const {
    LinuxFirewallPlan combined; combined.owner = owner_key;
    auto append = [](auto& destination, const std::string& owner, const auto& row) {
        destination.push_back(OwnedFirewall::Rule{owner + "/" + row.key, row.rule});
    };
    // The old global state rule precedes every per-network chain, including
    // packets involving two bridges. Preserve that order in the shared slice.
    for (const bool established : {true, false}) for (const auto& [owner, plan] : desired_)
        for (const bool ipv6 : {false, true}) for (const auto& row : plan.filter[ipv6])
            if (row.rule.established == established) append(combined.filter[ipv6], owner, row);
    for (const auto& [owner, plan] : desired_) {
        for (const auto& row : plan.nat4) append(combined.nat4, owner, row);
        for (const auto& row : plan.mangle4) append(combined.mangle4, owner, row);
    }
    return combined;
}
void LinuxFirewall::protect(const LinuxFirewallPlan& plan) {
    auto add = [&](FirewallRule rule) {
        rule.table = "filter"; rule.target = "DROP";
        guards_.emplace(wire::stringify(rule.json()), std::move(rule));
    };
    if (!plan.l3) {
        FirewallRule rule; rule.input = rule.output = plan.bridge; add(rule); return;
    }
    for (const bool ipv6 : {false, true}) {
        FirewallRule input; input.ipv6 = ipv6; input.input = plan.bridge; input.input_prefix = true;
        input.chain = "INPUT"; add(input); input.chain = "FORWARD"; add(input);
        FirewallRule output; output.ipv6 = ipv6; output.output = plan.bridge; output.output_prefix = true;
        output.chain = "OUTPUT"; add(output); output.chain = "FORWARD"; add(output);
    }
    // Legacy MASQUERADE matches the source subnet without an ingress check.
    // Protect its full match domain, including locally generated traffic,
    // before replacing NAT; bridge-interface guards alone are insufficient.
    for (const auto& row : plan.nat4) {
        auto rule = row.rule; rule.chain = "FORWARD"; add(rule);
        rule.chain = "OUTPUT"; add(rule);
    }
}
bool LinuxFirewall::matches(const LinuxFirewallPlan& plan) const {
    bool result = true;
    for (const bool ipv6 : {false, true}) result = firewall_.matches_table(owner_key, ipv6, "filter", plan.filter[ipv6]) && result;
    result = firewall_.matches_table(owner_key, false, "nat", plan.nat4) && result;
    return firewall_.matches_table(owner_key, false, "mangle", plan.mangle4) && result;
}
void LinuxFirewall::refresh_locked() {
    try {
        const auto plan = compose();
        if (matches(plan)) { guards_.clear(); ready_ = !stopped_; return; }
        ready_ = false;
        for (const auto& [owner, desired] : desired_) protect(desired);
        std::array<std::vector<OwnedFirewall::Rule>, 2> guarded;
        for (const auto& [key, rule] : guards_) {
            auto& rows = guarded[rule.ipv6];
            rows.push_back({std::string("guard/") + (rule.ipv6 ? "v6/" : "v4/") + std::to_string(rows.size()), rule});
        }
        for (const bool ipv6 : {false, true}) {
            auto& rows = guarded[ipv6]; rows.insert(rows.end(), plan.filter[ipv6].begin(), plan.filter[ipv6].end());
            firewall_.replace_table(owner_key, ipv6, "filter", rows);
            point(ipv6 ? "linux_firewall_guard6" : "linux_firewall_guard4");
        }
        for (const bool ipv6 : {false, true}) if (!firewall_.matches_table(owner_key, ipv6, "filter", guarded[ipv6]))
            throw ServiceError(ErrorCode::conflict, "Linux firewall protection changed before dependency update");
        firewall_.replace_table(owner_key, false, "nat", plan.nat4); point("linux_firewall_nat4");
        firewall_.replace_table(owner_key, false, "mangle", plan.mangle4); point("linux_firewall_mangle4");
        if (!firewall_.matches_table(owner_key, false, "nat", plan.nat4) ||
            !firewall_.matches_table(owner_key, false, "mangle", plan.mangle4))
            throw ServiceError(ErrorCode::conflict, "Linux firewall dependencies changed before publication");
        for (const bool ipv6 : {false, true}) {
            firewall_.replace_table(owner_key, ipv6, "filter", plan.filter[ipv6]);
            point(ipv6 ? "linux_firewall_filter6" : "linux_firewall_filter4");
        }
        if (!matches(plan)) throw ServiceError(ErrorCode::conflict, "Linux firewall publication did not converge");
        guards_.clear(); ready_ = !stopped_;
    } catch (...) { ready_ = false; throw; }
}
void LinuxFirewall::set(Json::Value config, const PdAddresses& pd) {
    auto plan = linux_firewall_plan(std::move(config), pd);
    std::lock_guard lock(mutex_);
    if (stopped_) throw ServiceError(ErrorCode::conflict, "Linux firewall coordinator is stopped");
    if (const auto before = desired_.find(plan.owner); before != desired_.end()) protect(before->second);
    protect(plan); ready_ = false;
    const auto owner = plan.owner; desired_[owner] = std::move(plan); refresh_locked();
}
void LinuxFirewall::remove(const std::string& network) {
    std::lock_guard lock(mutex_);
    if (stopped_) throw ServiceError(ErrorCode::conflict, "Linux firewall coordinator is stopped");
    if (const auto before = desired_.find(network); before != desired_.end()) { protect(before->second); desired_.erase(before); }
    ready_ = false; refresh_locked();
}
void LinuxFirewall::refresh() {
    std::lock_guard lock(mutex_);
    if (stopped_) throw ServiceError(ErrorCode::conflict, "Linux firewall coordinator is stopped");
    refresh_locked();
}
void LinuxFirewall::stop() {
    std::lock_guard lock(mutex_); stopped_ = true; ready_ = false;
    for (const auto& [owner, plan] : desired_) protect(plan);
    desired_.clear(); refresh_locked();
}
}
