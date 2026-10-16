// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <string>
namespace droidvm::test {
enum class FirewallSuite { ownership, plan, coordinator, forwards, orphan };
void firewall_namespace_contract(const std::string& netbox, const std::string& work, const std::string& daemon, FirewallSuite suite = FirewallSuite::ownership);
int firewall_namespace_child(const std::string& netbox, const std::string& work, const std::string& daemon, FirewallSuite suite = FirewallSuite::ownership);
int firewall_crash_child(const std::string& work, bool ipv6, const std::string& stage);
int firewall_delayed_restore(const std::string& executable, bool check_only);
void firewall_packet_contract(const std::string& netbox, const std::string& work);
void linux_firewall_packet_contract(const std::string& netbox, const std::string& work);
void linux_firewall_coordinator_packets(const std::string& netbox, const std::string& work);
void linux_firewall_forward_packets(const std::string& netbox, const std::string& work);
}
