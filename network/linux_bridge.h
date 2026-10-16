// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "backend.h"
#include "bridgedhcp.h"
#include "linux_firewall.h"
#include "linux_routing.h"
#include "linux_topology.h"
#include <memory>

namespace droidvm::network {
// Linux L3 data path composed from owned topology, the shared firewall
// coordinator, policy routing and bridgedhcp. L2 uplinks and DHCPv6-PD are
// rejected until their host resource ownership exists; VM attachment and
// port forwards are supplied later by the VM integration.
class LinuxBridge final : public Backend {
public:
    struct Resources {
        const Netbox& netbox;
        OwnedLinks& links;
        OwnedRules& rules;
        OwnedRoutes& routes;
        LinuxFirewall& firewall;
        SwitchRuntime& runtime;
        std::string dhcp_executable;
        int dhcp_state_directory;
    };
    explicit LinuxBridge(Resources resources);
    void start(const Json::Value& config) override;
    bool healthy() const override;
    void refresh() override;
    void recover(const Json::Value& config) override;
    // Keeps firewall guards while any guest-facing link remains.
    void stop() override;
    Json::Value tools() const override;
    Json::Value tool_log(const std::string& key) const override;
private:
    Resources resources_;
    LinuxTopology topology_;
    BridgeDhcp dhcp_;
    std::unique_ptr<LinuxRouting> routing_;
    std::string firewall_owner_; // registered until removal succeeds
    bool running_ = false, dhcp_needed_ = false, rebuild_ = false;
};
}
