// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "network/host_discovery.h"
#include <array>
#include <string_view>

namespace droidvm::web {
enum class ListenScope { lan, all };
ListenScope listen_scope(std::string_view value); // Unknown values never widen access.

struct PeerPrefix {
    std::array<unsigned char, 16> bytes{};
    unsigned family = 4, bits = 32;
    bool contains(std::string_view peer) const;
    bool operator==(const PeerPrefix&) const = default;
};
struct ListenEndpoint {
    std::string address;
    std::string interface_name; // Empty for loopback/wildcards.
    std::vector<PeerPrefix> sources;
    bool unrestricted = false;
    bool allows(std::string_view peer) const;
    bool operator==(const ListenEndpoint&) const = default;
};
struct ListenPlan {
    ListenScope scope = ListenScope::lan;
    std::vector<ListenEndpoint> endpoints;
    std::vector<std::string> access_addresses;
    bool operator==(const ListenPlan&) const = default;
};

// Pure policy over a trusted host scan: no sockets, sysfs reads or service calls.
// Each specific listener only accepts its own direct prefixes plus loopback.
// Scan errors must propagate; never substitute an all-network plan for errors.
ListenPlan make_listen_plan(const network::HostNetworkSnapshot& snapshot,
                           ListenScope scope = ListenScope::lan, bool ipv6 = true);
// Auto-login requires both the actual local socket endpoint and a direct LAN
// peer. Loopback/proxies and arbitrary private ranges are not LAN authority.
bool direct_lan_peer(const ListenPlan& plan, std::string_view peer, std::string_view local);
}
