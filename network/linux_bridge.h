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
#include <functional>
#include <memory>
#include <set>

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
        // BridgeDhcp.buildStatics: leases of every known VM NIC on this network.
        std::function<std::map<int, DhcpStatics>(const Json::Value&)> statics = {};
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
    void attach(const Json::Value& nic, const std::string& tap) override;
    void detach(const Json::Value& nic, const std::string& tap) override;
    Json::Value forward_failures() const override;
    void live_details(Json::Value& data) const override;
    bool pd_action(int vlan, bool release) override;
    bool manual_address(const std::string& cidr, bool add) override;
    bool manual_port(const std::string& name, bool add) override;
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
    std::map<std::string, Json::Value> attached_; // TAP -> sanitized NIC
    std::map<std::string, std::vector<std::string>> failures_; // legacy forward_failures
    std::map<std::string, bool> mac_security_; // TAP -> locked port active
    std::set<std::string> manual_ports_; // network_add_interface ports
    std::string manual_owner(const std::string& name) const { return firewall_owner_ + "/manual/" + name; }
    bool retain_taps_ = false; // recover keeps VM TAPs (crosvm holds them open)
    std::string tap_owner(const std::string& tap) const { return firewall_owner_ + "/" + tap; }
    void plug(const std::string& tap, const Json::Value& nic);
    void publish_leases();
    void release_tap(const std::string& tap);
    void start_pbridge();
    void start_dhcp(std::map<int, std::string> uplinks);
};
}
