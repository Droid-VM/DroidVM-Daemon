// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_firewall.h"
#include "store/network_config.h"
#include <set>

namespace droidvm::network {
LinuxFirewallPlan linux_firewall_plan(Json::Value config, const PdAddresses& pd) {
    const auto plan = linux_plan(std::move(config));
    const auto live = linux_live_plan(plan, pd);
    LinuxFirewallPlan result; result.owner = plan.owner; result.bridge = plan.bridge;
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
}
