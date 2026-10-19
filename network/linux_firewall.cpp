// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_firewall.h"
#include "store/network_config.h"
#include "services/context.h"
#include "common/wire.h"
#include "netbox.h"
#include <algorithm>
#include <arpa/inet.h>
#include <set>

namespace droidvm::network {
namespace {
std::vector<std::string> host_addresses4(const std::vector<std::string>& addresses) {
    if (addresses.size() > 256) throw ServiceError(ErrorCode::resource_exhausted, "too many firewall host addresses");
    std::set<std::string> unique;
    for (const auto& address : addresses) {
        in_addr value{}; char text[INET_ADDRSTRLEN]{};
        if (inet_pton(AF_INET, address.c_str(), &value) != 1 || !value.s_addr || address.find('\0') != std::string::npos)
            throw ServiceError(ErrorCode::invalid_argument, "firewall host address must be a specific numeric IPv4 address");
        inet_ntop(AF_INET, &value, text, sizeof(text)); unique.insert(text);
    }
    return {unique.begin(), unique.end()};
}
void append_forwards(LinuxFirewallPlan& result, const Json::Value& config,
        const std::vector<LinuxPortForward>& forwards, const std::vector<std::string>& hosts) {
    if (forwards.size() > 256) throw ServiceError(ErrorCode::resource_exhausted, "too many Linux port forwards");
    std::vector<OwnedFirewall::Rule> accepts;
    for (size_t i = 0; i < forwards.size(); ++i) {
        const auto& forward = forwards[i];
        Netbox::interface_name(forward.attachment);
        if (!result.l3 || forward.vlan < 0 || forward.vlan > 4094 || forward.offset <= 0 ||
            !forward.host_first || forward.host_last < forward.host_first || !forward.guest_first ||
            forward.guest_last < forward.guest_first || forward.host_last - forward.host_first != forward.guest_last - forward.guest_first ||
            (forward.protocol != "tcp" && forward.protocol != "udp" && forward.protocol != "any"))
            throw ServiceError(ErrorCode::invalid_argument, "invalid Linux port forward");
        const Json::Value* vlan = nullptr;
        for (const auto& row : config::member(config::member(config, "l3"), "vlans"))
            if (row.isObject() && config::integer(row, "vlan_id") == forward.vlan) { vlan = &row; break; }
        const auto& ipv4 = config::member(vlan ? *vlan : Json::Value::nullSingleton(), "ipv4");
        const auto cidr = config::string(ipv4, "cidr");
        if (cidr.empty() || !config::boolean(ipv4, "snat") || !config::boolean(config::member(ipv4, "dhcp"), "enabled"))
            throw ServiceError(ErrorCode::invalid_argument, "Linux port forward requires a DHCPv4 and SNAT VLAN");
        const auto subnet = config::NetworkPrefix::parse(cidr, false);
        const auto guest = subnet.address_at(forward.offset);
        for (const std::string protocol : {"tcp", "udp"}) {
            if (forward.protocol != "any" && forward.protocol != protocol) continue;
            const auto key = "forward/" + forward.attachment + "/" + std::to_string(i) + "/" + protocol;
            if (result.nat4.size() + 1 + hosts.size() > 4096)
                throw ServiceError(ErrorCode::resource_exhausted, "Linux forward plan exceeds rule budget");
            FirewallRule accept; accept.output = result.bridge; accept.output_prefix = true;
            accept.destination = guest + "/32"; accept.protocol = protocol;
            accept.port_first = forward.guest_first; accept.port_last = forward.guest_last;
            accept.arguments(); accepts.push_back({key + "/accept", accept});
            FirewallRule hairpin = accept; hairpin.output.clear(); hairpin.output_prefix = false;
            hairpin.table = "nat"; hairpin.chain = "POSTROUTING"; hairpin.source = subnet.network(); hairpin.target = "MASQUERADE";
            hairpin.arguments(); result.nat4.push_back({key + "/hairpin", hairpin});
            for (const auto& host : hosts) {
                FirewallRule dnat; dnat.table = "nat"; dnat.chain = "PREROUTING";
                dnat.destination = host + "/32"; dnat.protocol = protocol;
                dnat.port_first = forward.host_first; dnat.port_last = forward.host_last;
                dnat.target = "DNAT"; dnat.translated_address = guest;
                dnat.translated_first = forward.guest_first; dnat.translated_last = forward.guest_last;
                dnat.arguments(); result.nat4.push_back({key + "/dnat/" + host, dnat});
            }
        }
    }
    auto& filter = result.filter[0];
    const auto at = std::find_if(filter.begin(), filter.end(), [](const auto& row) { return !row.rule.established; });
    filter.insert(at, accepts.begin(), accepts.end());
    if (result.nat4.size() > 4096 || filter.size() > 4096)
        throw ServiceError(ErrorCode::resource_exhausted, "Linux forward plan exceeds rule budget");
}
}
LinuxFirewallPlan linux_firewall_plan(Json::Value config, const PdAddresses& pd,
        const std::vector<LinuxPortForward>& forwards, const std::vector<std::string>& host_ipv4) {
    const auto plan = linux_plan(config);
    const auto hosts = host_addresses4(host_ipv4);
    const auto live = linux_live_plan(plan, pd);
    LinuxFirewallPlan result; result.owner = plan.owner; result.bridge = plan.bridge; result.l3 = plan.l3;
    auto append = [&](FirewallRule rule) {
        auto& rows = rule.table == "nat" ? result.nat4 : rule.table == "mangle" ? result.mangle4 : result.filter[rule.ipv6];
        rule.arguments();
        const auto key = std::string(rule.ipv6 ? "v6/" : "v4/") + rule.table + "/" + std::to_string(rows.size());
        rows.push_back({key, std::move(rule)});
    };
    if (!plan.l3) {
        if (!forwards.empty()) throw ServiceError(ErrorCode::invalid_argument, "Linux L2 networks do not support port forwards");
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
    append_forwards(result, config, forwards, hosts);
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
        auto rule = row.rule;
        if (rule.target == "DNAT") {
            // filter sees the translated address/port when NAT is installed,
            // and the host address/port when it is absent. Guard both forms,
            // including local delivery if the target's route changes.
            rule.translated_address.clear(); rule.translated_first = rule.translated_last = 0;
            rule.chain = "FORWARD"; add(rule); rule.chain = "INPUT"; add(rule);
            rule.destination = row.rule.translated_address + "/32";
            rule.port_first = row.rule.translated_first; rule.port_last = row.rule.translated_last;
            rule.chain = "FORWARD"; add(rule); rule.chain = "INPUT"; add(rule);
        } else {
            rule.chain = "FORWARD"; add(rule);
            rule.chain = "OUTPUT"; add(rule);
        }
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
            firewall_.replace_table(owner_key, ipv6, "filter", rows, true);
            point(ipv6 ? "linux_firewall_guard6" : "linux_firewall_guard4");
        }
        for (const bool ipv6 : {false, true}) if (!firewall_.matches_table(owner_key, ipv6, "filter", guarded[ipv6], true))
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
    std::lock_guard lock(mutex_);
    if (stopped_) throw ServiceError(ErrorCode::conflict, "Linux firewall coordinator is stopped");
    const auto owner = config::uuid(config);
    const auto at = forwards_.find(owner);
    auto plan = linux_firewall_plan(config, pd, at == forwards_.end() ? std::vector<LinuxPortForward>{} : at->second, host_ipv4_);
    if (const auto before = desired_.find(plan.owner); before != desired_.end()) protect(before->second);
    protect(plan); ready_ = false;
    configurations_[owner] = std::move(config); pd_[owner] = pd;
    desired_[owner] = std::move(plan); refresh_locked();
}
void LinuxFirewall::set_forwards(const std::string& network, std::vector<LinuxPortForward> forwards) {
    std::lock_guard lock(mutex_);
    if (stopped_) throw ServiceError(ErrorCode::conflict, "Linux firewall coordinator is stopped");
    const auto at = configurations_.find(network);
    if (at == configurations_.end()) throw ServiceError(ErrorCode::not_found, "Linux firewall network is not registered");
    auto plan = linux_firewall_plan(at->second, pd_.at(network), forwards, host_ipv4_);
    protect(desired_.at(network)); protect(plan); ready_ = false;
    forwards_[network] = std::move(forwards); desired_[network] = std::move(plan); refresh_locked();
}
void LinuxFirewall::set_host_ipv4(std::vector<std::string> addresses) {
    addresses = host_addresses4(addresses);
    std::lock_guard lock(mutex_);
    if (stopped_) throw ServiceError(ErrorCode::conflict, "Linux firewall coordinator is stopped");
    auto next = desired_;
    for (auto& [owner, plan] : next) {
        const auto at = forwards_.find(owner);
        plan = linux_firewall_plan(configurations_.at(owner), pd_.at(owner),
            at == forwards_.end() ? std::vector<LinuxPortForward>{} : at->second, addresses);
    }
    for (const auto& [owner, plan] : desired_) protect(plan);
    for (const auto& [owner, plan] : next) protect(plan);
    ready_ = false; host_ipv4_ = std::move(addresses); desired_ = std::move(next); refresh_locked();
}
void LinuxFirewall::remove(const std::string& network) {
    std::lock_guard lock(mutex_);
    if (stopped_) throw ServiceError(ErrorCode::conflict, "Linux firewall coordinator is stopped");
    if (const auto before = desired_.find(network); before != desired_.end()) { protect(before->second); desired_.erase(before); }
    configurations_.erase(network); pd_.erase(network); forwards_.erase(network);
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
    desired_.clear(); configurations_.clear(); pd_.clear(); forwards_.clear(); refresh_locked();
}
}
