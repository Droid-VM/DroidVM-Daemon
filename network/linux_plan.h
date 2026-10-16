// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <array>
#include <map>
#include <string>
#include <vector>

namespace droidvm::network {
struct LinuxVlan {
    int id = 0;
    std::string device, leg;
    std::array<std::vector<std::string>, 2> addresses; // normalized host CIDRs
    bool pd = false, snat4 = false;
};
struct LinuxPlan {
    std::string owner, bridge;
    bool l3 = true, stp = false;
    std::vector<LinuxVlan> vlans;
};
// Shared static interpretation. PD's configured CIDR is not a live delegation.
LinuxPlan linux_plan(Json::Value network);
using PdAddresses = std::map<int, std::string>; // authoritative live router host CIDRs only
// Resolve live delegations once for routing/firewall consumers; never use the
// configured PD placeholder as a current lease. Static secondary IPs remain.
LinuxPlan linux_live_plan(const LinuxPlan& plan, const PdAddresses& pd);
}
