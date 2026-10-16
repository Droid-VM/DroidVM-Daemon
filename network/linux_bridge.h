// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "backend.h"
#include "bridgedhcp.h"
#include "linux_firewall.h"
#include "linux_routing.h"
#include "linux_topology.h"
#include "pd_ownership.h"
#include "ports.h"
#include "pbridge.h"
#include <memory>

namespace droidvm::network {
// Linux L3 data path composed from owned topology, the shared firewall
// coordinator, policy routing and bridgedhcp, with PdOwnership covering the
// helper's own PD host changes. L2 enslaves a bridgeable uplink through
// OwnedPorts, or pseudo-bridges a non-bridgeable uplink through pbridge with
// PbridgeOwnership. VM attachment and forwards come from the VM integration.
class LinuxBridge final : public Backend {
public:
    struct Resources {
        const Netbox& netbox;
        OwnedLinks& links;
        OwnedRules& rules;
        OwnedRoutes& routes;
        LinuxFirewall& firewall;
        PdOwnership& pd;
        OwnedPorts& ports;
        PbridgeOwnership& pbridge;
        SwitchRuntime& runtime;
        std::string dhcp_executable;
        std::string pbridge_executable;
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
    Pbridge pbridge_;
    std::unique_ptr<LinuxRouting> routing_;
    std::string firewall_owner_; // registered until removal succeeds
    Json::Value config_;
    std::map<int, std::string> uplinks_; // PD uplinks given to the helper
    PdAddresses pd_; // last authoritative helper delegation snapshot
    bool running_ = false, dhcp_needed_ = false, rebuild_ = false, pd_registered_ = false, l3_ = true;
    bool pseudo_ = false, pbridge_registered_ = false;
    std::string uplink_; // resolved L2 uplink
    void start_pbridge();
    void start_dhcp(std::map<int, std::string> uplinks);
};
}
