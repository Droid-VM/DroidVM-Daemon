// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_plan.h"
#include "links.h"
#include "store/network_config.h"
#include "services/context.h"
#include <bit>
#include <set>

namespace droidvm::network {
LinuxPlan linux_plan(Json::Value network) {
    config::validate_network(network);
    if (config::string(network, "bridge_type") == "gvisor")
        throw ServiceError(ErrorCode::invalid_argument, "Linux network plan requires a Linux bridge");
    LinuxPlan plan;
    plan.owner = config::uuid(network); plan.bridge = config::string(network, "bridge_name");
    Netbox::interface_name(plan.bridge);
    plan.l3 = config::string(network, "uplink_mode") != "l2"; plan.stp = config::boolean(network, "stp");
    const auto& rows = config::member(config::member(network, "l3"), "vlans");
    if (plan.l3 && rows.isArray()) for (const auto& row : rows) {
        if (!row.isObject()) continue;
        LinuxVlan vlan;
        vlan.id = std::bit_cast<int32_t>(static_cast<uint32_t>(config::integer(row, "vlan_id")));
        vlan.device = OwnedLinks::vlan_device(plan.bridge, vlan.id);
        if (vlan.id) vlan.leg = OwnedLinks::vlan_leg(plan.bridge, vlan.id);
        vlan.pd = config::string(config::member(row, "ipv6"), "source") == "dhcp_pd";
        for (const bool ipv6 : {false, true}) {
            std::set<std::string> unique;
            auto add = [&](const std::string& cidr) {
                if (cidr.empty()) return;
                const auto prefix = config::NetworkPrefix::parse(cidr, ipv6);
                const auto address = prefix.address() + "/" + std::to_string(prefix.prefix());
                if (unique.insert(address).second) vlan.addresses[ipv6].push_back(address);
            };
            if (!ipv6 || !vlan.pd) add(config::string(config::member(row, ipv6 ? "ipv6" : "ipv4"), "cidr"));
            const auto& secondary = config::member(row, ipv6 ? "ipv6_secondary" : "ipv4_secondary");
            if (secondary.isArray()) for (const auto& cidr : secondary) if (cidr.isString()) add(cidr.asString());
        }
        plan.vlans.push_back(std::move(vlan));
    }
    return plan;
}
}
