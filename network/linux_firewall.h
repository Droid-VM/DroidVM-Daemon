// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "firewall.h"
#include "linux_plan.h"
#include <atomic>

namespace droidvm::network {
// Resolved VM attachment intent. The VM service supplies persisted lease
// offsets and validated numeric port ranges; no runtime IP is guessed here.
struct LinuxPortForward {
    std::string attachment;
    int vlan = 0;
    int64_t offset = 0;
    std::string protocol = "tcp"; // tcp, udp, or legacy any (both)
    uint16_t host_first = 0, host_last = 0, guest_first = 0, guest_last = 0;
};
// Policy for one Linux network, including ordered VM attachment forwards.
// Each list is in evaluation order within its built-in hooks. Applying the
// lists across tables/families requires the backend's guarded coordinator.
struct LinuxFirewallPlan {
    std::string owner, bridge;
    bool l3 = true;
    std::array<std::vector<OwnedFirewall::Rule>, 2> filter;
    std::vector<OwnedFirewall::Rule> nat4, mangle4;
};
LinuxFirewallPlan linux_firewall_plan(Json::Value config, const PdAddresses& pd = {},
    const std::vector<LinuxPortForward>& forwards = {}, const std::vector<std::string>& host_ipv4 = {});
// One shared coordinator for all Linux networks. Methods serialize across
// per-network workers. Failed set/remove retains desired state for refresh.
// Construct only after startup ownership recovery. No destructor-side writes.
class LinuxFirewall {
public:
    static constexpr const char* owner_key = "linux-firewall";
    using Observer = std::function<void(const char*)>;
    explicit LinuxFirewall(OwnedFirewall& firewall, Observer observer = {});
    void set(Json::Value config, const PdAddresses& pd = {});
    // Complete ordered attachment snapshot for this network. Failures retain
    // validated desired state for refresh; invalid input leaves it unchanged.
    // Any invalid entry rejects the whole snapshot, so callers keep legacy
    // semantics by skipping ineligible NICs and recording per-forward errors.
    void set_forwards(const std::string& network, std::vector<LinuxPortForward> forwards);
    // Shared HostAddressScan IPv4 snapshot. Empty removes DNAT, never widens
    // it to a wildcard. No local OUTPUT DNAT: retain legacy PREROUTING scope.
    void set_host_ipv4(std::vector<std::string> addresses);
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
    std::map<std::string, Json::Value> configurations_;
    std::map<std::string, PdAddresses> pd_;
    std::map<std::string, std::vector<LinuxPortForward>> forwards_;
    std::vector<std::string> host_ipv4_;
    std::map<std::string, FirewallRule> guards_; // old/new scopes survive errors
    LinuxFirewallPlan compose() const;
    void protect(const LinuxFirewallPlan& plan);
    bool matches(const LinuxFirewallPlan& plan) const;
    void refresh_locked();
    void point(const char* stage) { if (observer_) observer_(stage); }
};
}
