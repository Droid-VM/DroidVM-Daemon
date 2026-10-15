// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <map>
#include <string>
#include <vector>

namespace droidvm::network {
// Inputs use the existing persisted network schema. Builders validate a copy,
// never allocate identities or write config as a side effect. Run on a worker:
// the shared legacy-compatible IP parser can resolve IPv6 hostnames.
Json::Value gvswitch_config(Json::Value network);
struct DhcpPaths { std::string socket, key, state; };
struct DhcpStatics { Json::Value ipv4{Json::arrayValue}, ipv6{Json::arrayValue}; };
struct BridgeDhcpPlan {
    Json::Value config;
    bool needed = false;
    std::vector<int> unresolved_pd;
};
// resolved_uplinks is a snapshot from UplinkResolver, keyed by VLAN ID. Missing
// PD uplinks are reported explicitly; a resolved PD interface requires its
// DUID/table already persisted by the owning service. Per-VM static entries
// retain the helper's existing id/mac/offset schema.
BridgeDhcpPlan bridgedhcp_config(Json::Value network, const DhcpPaths& paths,
    const std::map<int, std::string>& resolved_uplinks = {},
    const std::map<int, DhcpStatics>& statics = {});
}
