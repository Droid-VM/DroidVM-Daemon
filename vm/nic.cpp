// SPDX-License-Identifier: GPL-3.0-or-later
// Port of lib/store/vm/VMNicConfig with the VlanConfig accessors it reads.
#include "nic.h"
#include "store/network_config.h"
#include <bit>
#include <climits>
#include <optional>
#include <regex>
#include <stdexcept>

namespace droidvm::vm {
namespace {
[[noreturn]] void invalid(const std::string& text) { throw std::invalid_argument(text); }
std::string trim(const std::string& text) {
    size_t first = 0, last = text.size();
    while (first < last && static_cast<unsigned char>(text[first]) <= ' ') ++first;
    while (last > first && static_cast<unsigned char>(text[last - 1]) <= ' ') --last;
    return text.substr(first, last - first);
}
int narrow(int64_t value) { return std::bit_cast<int32_t>(static_cast<uint32_t>(value)); }
Json::Value& lease(Json::Value& nic, const char* key) {
    if (!nic[key].isObject()) nic[key] = Json::Value(Json::objectValue);
    return nic[key];
}
std::string optional_text(const Json::Value& nic, const char* key) { return config::string(nic, key); }
bool has_offset(const Json::Value& nic, const char* key) {
    const auto& value = config::member(nic, key);
    if (!value.isObject() || !value.isMember("offset")) return false;
    const auto& offset = value["offset"];
    return (offset.type() == Json::intValue || offset.type() == Json::uintValue) && offset.isInt64() && offset.asInt64() > 0;
}
const Json::Value& section(const Json::Value& vlan, const char* key) { return config::member(vlan, key); }
std::string ipv4_cidr(const Json::Value& vlan) { return config::string(section(vlan, "ipv4"), "cidr"); }
std::string ipv6_cidr(const Json::Value& vlan) { return config::string(section(vlan, "ipv6"), "cidr"); }
bool pd_source(const Json::Value& vlan) { return config::string(section(vlan, "ipv6"), "source", "static") == "dhcp_pd"; }
bool dhcp4(const Json::Value& vlan) { return !ipv4_cidr(vlan).empty() && config::boolean(config::member(section(vlan, "ipv4"), "dhcp"), "enabled"); }
bool dhcp6(const Json::Value& vlan) {
    return (pd_source(vlan) || !ipv6_cidr(vlan).empty()) && config::boolean(config::member(section(vlan, "ipv6"), "dhcp"), "enabled");
}
bool snat(const Json::Value& vlan, const char* family) { return config::boolean(section(vlan, family), "snat"); }
std::string bridge_type(const Json::Value& network) {
    auto copy = network;
    return config::network_view(copy)["bridge_type"].asString();
}
std::optional<int> vlan_id(const Json::Value& nic) {
    const auto& value = config::member(nic, "vlan_id");
    if (!((value.type() == Json::intValue || value.type() == Json::uintValue) && value.isInt64())) return {};
    return narrow(value.asInt64());
}
// IPv4/IPv6Network.addressAtOffset bounds on a parsable static prefix.
void check_offset(const std::string& cidr, bool ipv6, int64_t offset) {
    std::optional<config::NetworkPrefix> prefix;
    try { prefix = config::NetworkPrefix::parse(cidr, ipv6); } catch (const std::exception&) { return; }
    const int host_bits = (ipv6 ? 128 : 32) - prefix->prefix();
    if (!ipv6) {
        const int64_t total = int64_t(1) << host_bits;
        if (offset <= 0 || offset >= total - 1)
            invalid("Offset " + std::to_string(offset) + " out of range for /" + std::to_string(prefix->prefix()) +
                    " network (1.." + std::to_string(total - 2) + ")");
    } else if (offset <= 0 || (host_bits < 63 && offset >= (int64_t(1) << host_bits))) {
        invalid("Offset " + std::to_string(offset) + " out of range for /" + std::to_string(prefix->prefix()) + " network");
    }
}
}
std::vector<std::string> PortForwardSpec::protocols() const {
    if (proto == "any") return {"tcp", "udp"};
    return {proto};
}
int forward_port(const std::string& spec, bool start) {
    const auto text = trim(spec);
    const auto dash = text.find('-');
    const auto part = dash == std::string::npos ? text : start ? text.substr(0, dash) : text.substr(dash + 1);
    int64_t port;
    try { port = config::java_long(trim(part)); } catch (const std::invalid_argument&) { invalid("Invalid port: " + spec); }
    if (port < INT_MIN || port > INT_MAX) invalid("Invalid port: " + spec); // Integer.parseInt overflow
    if (port < 1 || port > 65535) invalid("Port out of range: " + spec);
    return static_cast<int>(port);
}
void validate_forward(const PortForwardSpec& forward) {
    if (forward.proto != "tcp" && forward.proto != "udp" && forward.proto != "any") invalid("Invalid forward protocol: " + forward.proto);
    const int hs = forward_port(forward.host, true), he = forward_port(forward.host, false);
    const int gs = forward_port(forward.guest, true), ge = forward_port(forward.guest, false);
    if (he < hs || ge < gs) invalid("Invalid port range in forward " + forward.host + " -> " + forward.guest);
    if (he - hs != ge - gs) invalid("Forward port ranges differ in size: " + forward.host + " -> " + forward.guest);
}
std::vector<PortForwardSpec> nic_forwards(Json::Value& nic, const char* key) {
    std::vector<PortForwardSpec> result;
    const auto& rows = config::member(lease(nic, key), "forwards");
    if (!rows.isArray()) return result;
    for (const auto& row : rows) {
        if (!row.isObject()) continue;
        result.push_back({config::string(row, "proto", "tcp"), config::string(row, "host"), config::string(row, "guest")});
    }
    return result;
}
const Json::Value* nic_dhcp_vlan(const Json::Value& nic, const Json::Value& network) {
    auto copy = network;
    if (config::network_view(copy)["uplink_mode"] != "l3") return nullptr;
    auto id = vlan_id(nic).value_or(0);
    if (id == 4095) id = 0;
    const auto& rows = config::member(config::member(network, "l3"), "vlans");
    if (!rows.isArray()) return nullptr;
    for (const auto& vlan : rows)
        if (vlan.isObject() && narrow(config::integer(vlan, "vlan_id")) == id) return &vlan;
    return nullptr;
}
void validate_nic(Json::Value& nic, const Json::Value& network) {
    const auto mac = optional_text(nic, "mac_address");
    static const std::regex mac_pattern("([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}");
    if (!mac.empty() && !std::regex_match(mac, mac_pattern)) invalid("Invalid NIC MAC address: " + mac);
    if (config::boolean(nic, "mac_security") && mac.empty()) invalid("MAC security requires a configured MAC address");
    if (const auto id = vlan_id(nic)) {
        // 0 = untagged-only, 4095 = trunk marker, 1..4094 = tagged access.
        if (*id < 0 || *id > 4095) invalid("Invalid NIC VLAN id: " + std::to_string(*id));
        if (*id == 0 && bridge_type(network) == "linux")
            invalid("Untagged-only (VLAN 0) ports are not supported on a Linux bridge; use trunk or a tagged VLAN");
    }
    const auto* vlan = nic_dhcp_vlan(nic, network);
    if (config::boolean(lease(nic, "dhcp4_lease"), "enabled")) {
        if (!vlan || !dhcp4(*vlan)) invalid("DHCPv4 static lease requires an L3 network with DHCPv4 enabled");
        if (mac.empty()) invalid("DHCPv4 static lease requires a MAC address");
        if (!has_offset(nic, "dhcp4_lease")) invalid("DHCPv4 static lease has no assigned offset");
        if (!ipv4_cidr(*vlan).empty()) check_offset(ipv4_cidr(*vlan), false, config::integer(lease(nic, "dhcp4_lease"), "offset", 64));
        for (const auto& forward : nic_forwards(nic, "dhcp4_lease")) {
            validate_forward(forward);
            if (!snat(*vlan, "ipv4")) invalid("IPv4 port forwards require IPv4 SNAT on the network");
        }
    }
    if (config::boolean(lease(nic, "dhcp6_lease"), "enabled")) {
        if (!vlan || !dhcp6(*vlan)) invalid("DHCPv6 static lease requires an L3 network with DHCPv6 enabled");
        if (!has_offset(nic, "dhcp6_lease")) invalid("DHCPv6 static lease has no assigned offset");
        if (!pd_source(*vlan) && !ipv6_cidr(*vlan).empty()) check_offset(ipv6_cidr(*vlan), true, config::integer(lease(nic, "dhcp6_lease"), "offset", 64));
        for (const auto& forward : nic_forwards(nic, "dhcp6_lease")) {
            validate_forward(forward);
            if (!snat(*vlan, "ipv6") || bridge_type(network) != "gvisor") invalid("IPv6 port forwards require IPv6 SNAT on a gVisor network");
        }
    }
}
Json::Value sanitize_nic(const Json::Value& nic, const Json::Value& network, std::vector<std::string>& dropped) {
    auto copy = nic.isObject() ? nic : Json::Value(Json::objectValue);
    const auto* vlan = nic_dhcp_vlan(copy, network);
    auto enabled = [&](const char* key) { return config::boolean(lease(copy, key), "enabled"); };
    if (enabled("dhcp4_lease") && (!vlan || !dhcp4(*vlan))) {
        copy.removeMember("dhcp4_lease");
        dropped.push_back("DHCPv4 static lease");
    } else if (enabled("dhcp4_lease") && !nic_forwards(copy, "dhcp4_lease").empty() && !snat(*vlan, "ipv4")) {
        copy["dhcp4_lease"].removeMember("forwards");
        dropped.push_back("IPv4 port forwards (network has no IPv4 SNAT)");
    }
    if (enabled("dhcp6_lease") && (!vlan || !dhcp6(*vlan))) {
        copy.removeMember("dhcp6_lease");
        dropped.push_back("DHCPv6 static lease");
    } else if (enabled("dhcp6_lease") && !nic_forwards(copy, "dhcp6_lease").empty() && (!snat(*vlan, "ipv6") || bridge_type(network) != "gvisor")) {
        copy["dhcp6_lease"].removeMember("forwards");
        dropped.push_back("IPv6 port forwards (require a gVisor network)");
    }
    return copy;
}
}
