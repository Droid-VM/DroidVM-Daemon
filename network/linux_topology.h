// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "links.h"
#include <functional>
#include <vector>

namespace droidvm::network {
// Link/address portion of LinuxBridgeBackend, not a complete network backend.
// The caller holds the configuration runtime lease and serializes operations.
// Firewall, uplinks and DHCP must be ready before publishing network RUNNING.
class LinuxTopology {
public:
    using Observer = std::function<void(const char*)>;
    LinuxTopology(const Netbox& netbox, OwnedLinks& links, Observer observer = {});
    // mac is the identity already persisted by prepare_runtime. No allocation
    // of config identities, host interface adoption or uplink mutation here.
    void start(Json::Value config, const std::string& mac);
    void stop(); // throws and keeps ownership if any cleanup is incomplete
    void verify() const;
    // An access VLAN missing from the config, created as an L2-only segment.
    std::string ensure_vlan(int vid);
    const std::vector<std::string>& devices() const { return devices_; }
    const std::vector<int>& extra_vlans() const { return extra_vlans_; } // created by ensure_vlan
    const std::string& bridge() const { return bridge_; }
private:
    std::vector<int> extra_vlans_;
    const Netbox& netbox_;
    OwnedLinks& links_;
    Observer observer_;
    std::string owner_, bridge_;
    std::vector<std::string> devices_;
    void disable_ra(const std::string& name);
    void point(const char* stage) { if (observer_) observer_(stage); }
};
}
