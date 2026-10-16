// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <string>
#include <vector>

namespace droidvm::vm {
// lib/store/vm/VMNicConfig. The network is a validated network config.
struct PortForwardSpec {
    std::string proto, host, guest; // host/guest: "N" or "N-M"
    std::vector<std::string> protocols() const; // "any" means tcp then udp
};
// PortForward.parsePort: throws invalid_argument with the legacy text.
int forward_port(const std::string& spec, bool start);
void validate_forward(const PortForwardSpec& forward);
// Like VMNicConfig's lease() accessors, reading creates an empty lease object.
std::vector<PortForwardSpec> nic_forwards(Json::Value& nic, const char* lease);
// resolveDhcpVlan: the L3 VLAN serving this NIC's DHCP, or null.
const Json::Value* nic_dhcp_vlan(const Json::Value& nic, const Json::Value& network);
void validate_nic(Json::Value& nic, const Json::Value& network);
// sanitizedFor: an independent copy without the L3 options this network
// cannot honour; each removal is described in dropped.
Json::Value sanitize_nic(const Json::Value& nic, const Json::Value& network, std::vector<std::string>& dropped);
}
