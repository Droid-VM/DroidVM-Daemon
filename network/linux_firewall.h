// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "firewall.h"
#include "linux_plan.h"

namespace droidvm::network {
// Complete base policy for one Linux network; VM forwards are composed later.
// Each list is in evaluation order within its built-in hooks. Applying the
// lists across tables/families requires the backend's guarded coordinator.
struct LinuxFirewallPlan {
    std::string owner, bridge;
    std::array<std::vector<OwnedFirewall::Rule>, 2> filter;
    std::vector<OwnedFirewall::Rule> nat4, mangle4;
};
LinuxFirewallPlan linux_firewall_plan(Json::Value config, const PdAddresses& pd = {});
}
