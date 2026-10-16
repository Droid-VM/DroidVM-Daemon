// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "firewall.h"
#include "linux_plan.h"
#include <atomic>

namespace droidvm::network {
// Complete base policy for one Linux network; VM forwards are composed later.
// Each list is in evaluation order within its built-in hooks. Applying the
// lists across tables/families requires the backend's guarded coordinator.
struct LinuxFirewallPlan {
    std::string owner, bridge;
    bool l3 = true;
    std::array<std::vector<OwnedFirewall::Rule>, 2> filter;
    std::vector<OwnedFirewall::Rule> nat4, mangle4;
};
LinuxFirewallPlan linux_firewall_plan(Json::Value config, const PdAddresses& pd = {});
// One shared coordinator for all Linux networks. Methods serialize across
// per-network workers. Failed set/remove retains desired state for refresh.
// Construct only after startup ownership recovery. No destructor-side writes.
class LinuxFirewall {
public:
    static constexpr const char* owner_key = "linux-firewall";
    using Observer = std::function<void(const char*)>;
    explicit LinuxFirewall(OwnedFirewall& firewall, Observer observer = {});
    void set(Json::Value config, const PdAddresses& pd = {});
    // Caller must quiesce the departing network's links/VMs before removal;
    // removing its firewall cannot itself keep a live unmanaged link isolated.
    void remove(const std::string& network);
    void refresh();
    void stop(); // all managed links must already be quiescent; retryable
    bool ready() const { return ready_.load(); }
private:
    OwnedFirewall& firewall_;
    Observer observer_;
    std::mutex mutex_;
    std::atomic<bool> ready_{true};
    bool stopped_ = false;
    std::map<std::string, LinuxFirewallPlan> desired_;
    std::map<std::string, FirewallRule> guards_; // old/new scopes survive errors
    LinuxFirewallPlan compose() const;
    void protect(const LinuxFirewallPlan& plan);
    bool matches(const LinuxFirewallPlan& plan) const;
    void refresh_locked();
    void point(const char* stage) { if (observer_) observer_(stage); }
};
}
