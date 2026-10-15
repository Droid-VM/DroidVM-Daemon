// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "network/helper_config.h"
#include "store/network_config.h"

using namespace droidvm;
using namespace droidvm::network;
using namespace droidvm::test;
namespace {
const DhcpPaths paths{"/run/s", "/run/key", "/state/dhcp"};
Json::Value network() {
    return wire::parse(R"({"schema":2,"id":"12345678-1234-1234-ABCD-123456789ABC","name":"helper","bridge_name":"brtest","l3":{"vlans":[]}})");
}
template<class F> void invalid(F&& function) {
    try { function(); } catch (const std::invalid_argument&) { return; }
    throw std::runtime_error("expected invalid helper configuration");
}
void prefix_boundaries() {
    using config::NetworkPrefix;
    check(NetworkPrefix::parse("192.0.2.129/25", false).address_at(1) == "192.0.2.129", "pool offset uses network base, not gateway");
    check(NetworkPrefix::parse("192.0.2.1/0", false).address_at(4294967294LL) == "255.255.255.254", "full IPv4 unsigned range");
    invalid([] { NetworkPrefix::parse("192.0.2.1/24", false).address_at(255); });
    invalid([] { NetworkPrefix::parse("2001:db8::1/126", true).address_at(4); });
    check(NetworkPrefix::parse("2001:db8::1/126", true).address_at(3) == "2001:db8::3", "IPv6 last address valid unlike IPv4 broadcast");
    check(NetworkPrefix::parse("ffff:ffff:ffff:ffff::1/64", true).address_at(INT64_MAX) == "ffff:ffff:ffff:ffff:7fff:ffff:ffff:ffff", "128-bit base and 63-bit positive offset");
    invalid([] { NetworkPrefix::parse("::1/0", true).address_at(0); });
    invalid([] { NetworkPrefix::parse("::1/0", true).address_at(-1); });
}
void dhcp_families_and_defaults() {
    auto cfg = network();
    check(!bridgedhcp_config(cfg, paths).needed, "no VLANs need no helper");
    cfg["l3"]["vlans"].append(config::default_vlan(257));
    auto& vlan = cfg["l3"]["vlans"][0];
    check(!bridgedhcp_config(cfg, paths).needed, "enabled toggles without networks need no helper");
    vlan["ipv4"]["cidr"] = "192.0.2.17/24"; vlan["ipv6"]["cidr"] = "2001:db8::17/64";
    auto plan = bridgedhcp_config(cfg, paths);
    auto iface = plan.config["interfaces"][0];
    check(plan.needed && iface["name"] == "brtestvEB" && iface["tag"] == "257", "Java tagged VLAN device naming");
    check(iface["prefix4"] == "192.0.2.17/24" && iface["prefix6"] == "2001:db8::17/64", "configured gateway retained");
    check(iface["dhcp4"]["dns"] == wire::parse(R"(["8.8.8.8","1.1.1.1"])") &&
        iface["dhcp6"]["dns"] == wire::parse(R"(["2001:4860:4860::8888"])") && iface["slaac"].asBool(), "legacy DNS fallback and SLAAC");
    vlan["dns_servers"] = wire::parse(R"(["9.9.9.9","2001:db8::53",null,""])");
    iface = bridgedhcp_config(cfg, paths).config["interfaces"][0];
    check(iface["dhcp4"]["dns"] == wire::parse(R"(["9.9.9.9"])") && iface["dhcp6"]["dns"] == wire::parse(R"(["2001:db8::53"])") , "DNS split by family");
    vlan["ipv4"]["dhcp"]["enabled"] = false; vlan["ipv6"]["dhcp"]["enabled"] = false;
    plan = bridgedhcp_config(cfg, paths);
    check(plan.needed && !plan.config["interfaces"][0].isMember("dhcp4"), "SLAAC alone needs helper");
    vlan["ipv6"]["slaac"]["enabled"] = false;
    check(!bridgedhcp_config(cfg, paths).needed, "all services disabled");
}
void pd_identity_and_unresolved() {
    auto cfg = network();
    auto vlan = config::default_vlan(2);
    vlan["ipv6"]["source"] = "dhcp_pd"; vlan["ipv6"]["cidr"] = "2001:db8::1/64";
    vlan["ipv6"]["pd"]["uplink"] = "configured-identity";
    cfg["l3"]["vlans"].append(vlan);
    auto plan = bridgedhcp_config(cfg, paths);
    check(plan.needed && plan.unresolved_pd == std::vector<int>{2} && !plan.config["interfaces"][0].isMember("pd"), "unresolved PD reported");
    check(!plan.config["interfaces"][0].isMember("prefix6"), "stale static CIDR suppressed for PD");
    invalid([&] { bridgedhcp_config(cfg, paths, {{2, "wlan0"}}); });
    cfg["l3"]["vlans"][0]["ipv6"]["pd"]["duid"] = "00:03:00:01:02:AA:BB:CC:DD:EE";
    cfg["l3"]["vlans"][0]["ipv6"]["pd"]["route_table"] = Json::Int64(4000000000LL);
    const auto original = cfg;
    plan = bridgedhcp_config(cfg, paths, {{2, "wlan0"}});
    const auto pd = plan.config["interfaces"][0]["pd"];
    check(plan.unresolved_pd.empty() && pd["iaid"].asUInt64() == 2784412843ULL, "unsigned CRC32 IAID known vector");
    check(pd["duid"] == "00:03:00:01:02:aa:bb:cc:dd:ee" && pd["route_table"].asInt64() == 4000000000LL && pd["suffix"] == "::1", "persisted identity retained");
    check(cfg == original, "builder never mutates stored identity");
    cfg["l3"]["vlans"][0]["vlan_id"] = 258;
    check(bridgedhcp_config(cfg, paths, {{258, "wlan0"}}).config["interfaces"][0]["pd"]["iaid"] == pd["iaid"], "Java CRC update uses low VLAN byte");
    cfg["l3"]["vlans"][0]["ipv6"]["pd"]["route_table"] = Json::Int64(4294967296LL);
    invalid([&] { bridgedhcp_config(cfg, paths, {{258, "wlan0"}}); });
}
void statics_and_limits() {
    auto cfg = network(); auto vlan = config::default_vlan(0);
    vlan["ipv4"]["cidr"] = "192.0.2.1/24"; vlan["ipv6"]["cidr"] = "2001:db8::1/64";
    cfg["l3"]["vlans"].append(vlan);
    DhcpStatics entries;
    entries.ipv4 = wire::parse(R"([{"id":"vm-0","mac":"02:00:00:12:34:56","offset":42}])");
    entries.ipv6 = wire::parse(R"([{"id":"vm-0","mac":"02:00:00:12:34:56","offset":9223372036854775807}])");
    auto plan = bridgedhcp_config(cfg, paths, {}, {{0, entries}});
    check(plan.config["interfaces"][0]["statics4"] == entries.ipv4 && plan.config["interfaces"][0]["statics6"] == entries.ipv6,
        "VM binding identifiers and exact int64 offsets preserved");
    entries.ipv4[0]["offset"] = 0;
    invalid([&] { bridgedhcp_config(cfg, paths, {}, {{0, entries}}); });
    invalid([&] { bridgedhcp_config(cfg, {"relative", "/key", "/state"}); });
    cfg["l3"]["vlans"][0]["dns_servers"].append(std::string(1u << 20, 'x'));
    bool bounded = false;
    try { bridgedhcp_config(cfg, paths); } catch (const std::exception&) { bounded = true; }
    check(bounded, "generated helper config bounded before file write");
}
}
int main() { return run({{"prefix_boundaries", prefix_boundaries}, {"dhcp_families_and_defaults", dhcp_families_and_defaults},
    {"pd_identity_and_unresolved", pd_identity_and_unresolved}, {"statics_and_limits", statics_and_limits}}); }
