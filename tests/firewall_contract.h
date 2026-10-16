// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <string>
namespace droidvm::test {
void firewall_namespace_contract(const std::string& netbox, const std::string& work, const std::string& daemon);
int firewall_namespace_child(const std::string& netbox, const std::string& work, const std::string& daemon);
int firewall_crash_child(const std::string& work, bool ipv6, const std::string& stage);
void firewall_packet_contract(const std::string& netbox, const std::string& work);
}
