// SPDX-License-Identifier: GPL-3.0-or-later
#include "helper_config.h"
#include "network/links.h"
#include "store/network_config.h"
#include "common/wire.h"
#include <bit>
#include <regex>

namespace droidvm::network {
using config::member;
using config::string;
using config::boolean;
using config::integer;
namespace {
int vlan_id(const Json::Value& vlan) { return std::bit_cast<int32_t>(static_cast<uint32_t>(integer(vlan, "vlan_id"))); }
Json::Value dns(const Json::Value& vlan, bool ipv6) {
    Json::Value out(Json::arrayValue);
    const auto& entries = member(vlan, "dns_servers");
    if (entries.isArray()) for (const auto& entry : entries) if (entry.isString()) {
        const auto text = entry.asString();
        if (!text.empty() && (text.find(':') != std::string::npos) == ipv6) out.append(text);
    }
    return out;
}
const Json::Value& vlans(const Json::Value& network) { return member(member(network, "l3"), "vlans"); }
bool pd_source(const Json::Value& v6) { return string(v6, "source") == "dhcp_pd"; }
bool enabled(const Json::Value& ip, const char* field) { return boolean(member(ip, field), "enabled"); }
void bounded(const Json::Value& config) { wire::stringify_bounded(config, 1u << 20); }
uint32_t iaid(const std::string& uuid, int vlan) {
    // java.util.zip.CRC32.update(int) consumes only the low byte. Preserve it
    // even for VLAN IDs >255 and retain uint32 values above INT32_MAX.
    uint32_t crc = UINT32_MAX;
    auto update = [&](uint8_t byte) {
        crc ^= byte;
        for (int bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ ((0u - (crc & 1)) & 0xedb88320u);
    };
    for (unsigned char byte : uuid) update(byte);
    update(static_cast<uint8_t>(vlan));
    return ~crc;
}
void static_entries(const Json::Value& entries) {
    if (!entries.isArray() || entries.size() > 4096) throw std::invalid_argument("Invalid static DHCP bindings");
    for (const auto& entry : entries) {
        if (!entry.isObject() || string(entry, "id").empty() || integer(entry, "offset") <= 0 ||
            !std::regex_match(string(entry, "mac"), std::regex("([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")))
            throw std::invalid_argument("Invalid static DHCP binding");
    }
}
}
Json::Value gvswitch_config(Json::Value network) {
    config::validate_network(network);
    Json::Value root(Json::objectValue);
    if (string(network, "uplink_mode") == "l2") return root;
    const auto& rows = vlans(network);
    if (!rows.isArray()) return root;
    const auto mac = string(member(network, "l3"), "mac_address");
    for (const auto& vlan : rows) {
        if (!vlan.isObject()) continue;
        const auto& v4 = member(vlan, "ipv4");
        const auto& v6 = member(vlan, "ipv6");
        const auto cidr4 = string(v4, "cidr"), cidr6 = pd_source(v6) ? "" : string(v6, "cidr");
        if (cidr4.empty() && cidr6.empty()) continue;
        Json::Value gateway(Json::objectValue);
        gateway["vlan"] = vlan_id(vlan);
        if (vlan_id(vlan) == 0 && !mac.empty()) gateway["mac"] = mac;
        const bool snat4 = !cidr4.empty() && boolean(v4, "snat"), snat6 = !cidr6.empty() && boolean(v6, "snat");
        gateway["enable_internet_routing"] = snat4 || snat6;
        if (snat4 || snat6) {
            if (!snat4) gateway["deny"].append("0.0.0.0/0");
            if (!snat6) gateway["deny"].append("[::]/0");
        }
        if (dns(vlan, false).empty() && dns(vlan, true).empty()) gateway["dns_proxy"] = true;
        for (const bool ipv6 : {false, true}) {
            const auto& cidr = ipv6 ? cidr6 : cidr4;
            if (cidr.empty()) continue;
            const auto prefix = config::NetworkPrefix::parse(cidr, ipv6);
            const auto& ip = ipv6 ? v6 : v4;
            auto& address = gateway[ipv6 ? "ipv6" : "ipv4"];
            address["address"] = prefix.address(); address["prefix_len"] = prefix.prefix();
            if (enabled(ip, "dhcp")) {
                auto& dhcp = gateway[ipv6 ? "dhcp6" : "dhcp4"];
                dhcp["enabled"] = true;
                dhcp["pool_start"] = prefix.address_at(integer(member(ip, "dhcp"), "offset_start", 128));
                dhcp["pool_end"] = prefix.address_at(integer(member(ip, "dhcp"), "offset_end", 192));
                const auto servers = dns(vlan, ipv6);
                if (!servers.empty()) dhcp["dns"] = servers;
            }
            if (ipv6 && enabled(ip, "slaac")) {
                auto& slaac = gateway["slaac"];
                slaac["enabled"] = true;
                slaac["managed"] = enabled(ip, "dhcp"); slaac["other"] = enabled(ip, "dhcp");
                Json::Value entry;
                entry["prefix"] = prefix.network(); entry["on_link"] = true; entry["autonomous"] = true;
                slaac["prefixes"].append(entry);
            }
        }
        root["gateways"].append(std::move(gateway));
    }
    bounded(root); return root;
}
BridgeDhcpPlan bridgedhcp_config(Json::Value network, const DhcpPaths& paths,
        const std::map<int, std::string>& resolved_uplinks, const std::map<int, DhcpStatics>& statics) {
    config::validate_network(network);
    for (const auto& path : {paths.socket, paths.key, paths.state})
        if (path.empty() || path.front() != '/' || path.find('\0') != std::string::npos)
            throw std::invalid_argument("Invalid DHCP helper path");
    BridgeDhcpPlan plan;
    auto& root = plan.config;
    root["api_socket"] = paths.socket; root["api_key_file"] = paths.key; root["state_file"] = paths.state;
    root["interfaces"] = Json::Value(Json::arrayValue);
    if (string(network, "uplink_mode") == "l2") return plan;
    const auto& rows = vlans(network);
    if (!rows.isArray()) return plan;
    const auto bridge = string(network, "bridge_name");
    for (const auto& vlan : rows) {
        if (!vlan.isObject()) continue;
        const auto vid = vlan_id(vlan);
        const auto& v4 = member(vlan, "ipv4");
        const auto& v6 = member(vlan, "ipv6");
        const bool pd = pd_source(v6);
        const auto cidr4 = string(v4, "cidr"), cidr6 = string(v6, "cidr");
        const bool has6 = pd || !cidr6.empty();
        Json::Value iface;
        iface["name"] = OwnedLinks::vlan_device(bridge, vid); iface["tag"] = std::to_string(vid);
        if (!cidr4.empty()) iface["prefix4"] = cidr4;
        if (!pd && !cidr6.empty()) iface["prefix6"] = cidr6;
        for (const bool ipv6 : {false, true}) {
            const auto& ip = ipv6 ? v6 : v4;
            if (!(ipv6 ? has6 : !cidr4.empty()) || !enabled(ip, "dhcp")) continue;
            plan.needed = true;
            auto& dhcp = iface[ipv6 ? "dhcp6" : "dhcp4"];
            dhcp["pool_offset_start"] = Json::Int64(integer(member(ip, "dhcp"), "offset_start", 128));
            dhcp["pool_offset_end"] = Json::Int64(integer(member(ip, "dhcp"), "offset_end", 192));
            dhcp["lease_time"] = "12h";
            auto servers = dns(vlan, ipv6);
            if (servers.empty()) {
                if (ipv6) servers.append("2001:4860:4860::8888");
                else { servers.append("8.8.8.8"); servers.append("1.1.1.1"); }
            }
            dhcp["dns"] = std::move(servers);
        }
        if (has6 && enabled(v6, "slaac")) { iface["slaac"] = true; plan.needed = true; }
        if (pd) {
            plan.needed = true;
            const auto resolved = resolved_uplinks.find(vid);
            if (resolved == resolved_uplinks.end() || resolved->second.empty()) plan.unresolved_pd.push_back(vid);
            else {
                Netbox::interface_name(resolved->second);
                const auto& stored = member(v6, "pd");
                auto duid = string(stored, "duid");
                const auto table = integer(stored, "route_table");
                if (duid.empty() || table <= 0 || table > UINT32_MAX)
                    throw std::invalid_argument("PD DUID and route table must be persisted before helper startup");
                for (auto& c : duid) if (c >= 'A' && c <= 'F') c += 'a' - 'A';
                auto& target = iface["pd"];
                target["uplink"] = resolved->second; target["duid"] = duid;
                target["iaid"] = Json::UInt(iaid(config::uuid(network), vid));
                target["suffix"] = "::1"; target["route_table"] = Json::Int64(table);
            }
        }
        if (const auto bindings = statics.find(vid); bindings != statics.end()) {
            static_entries(bindings->second.ipv4); static_entries(bindings->second.ipv6);
            if (!bindings->second.ipv4.empty()) iface["statics4"] = bindings->second.ipv4;
            if (!bindings->second.ipv6.empty()) iface["statics6"] = bindings->second.ipv6;
        }
        root["interfaces"].append(std::move(iface));
    }
    bounded(root); return plan;
}
}
