// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <array>
#include <string>
#include <vector>

namespace droidvm::network {
struct LinuxVlan {
    int id = 0;
    std::string device, leg;
    std::array<std::vector<std::string>, 2> addresses; // normalized host CIDRs
    bool pd = false;
};
struct LinuxPlan {
    std::string owner, bridge;
    bool l3 = true, stp = false;
    std::vector<LinuxVlan> vlans;
};
// Shared static interpretation. PD's configured CIDR is not a live delegation.
LinuxPlan linux_plan(Json::Value network);
}
