// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/listen_plan.h"
#include <iostream>
#include <stdexcept>

using namespace droidvm;
using namespace droidvm::web;
namespace {
void require(bool value) { if (!value) throw std::runtime_error("listen plan assertion failed"); }
template<class Function> void invalid(Function run) {
    try { run(); } catch (const std::invalid_argument&) { return; }
    throw std::runtime_error("invalid policy was accepted");
}
unsigned count = 0;
template<class Function> void test(const char* name, Function run) {
    run(); ++count; std::cout << "PASS " << name << '\n';
}
struct Fixture {
    network::HostNetworkSnapshot snapshot;
    void iface(std::string name, bool wifi = true) {
        network::HostInterface item; item.name = name; item.index = static_cast<uint32_t>(snapshot.interfaces.size() + 2);
        item.up = item.ethernet = item.leaf = true; item.wireless = wifi; item.physical = !wifi;
        snapshot.interfaces.push_back(item);
        Json::Value row; row["ifname"] = name; row["kind"] = ""; row["master"] = ""; snapshot.links.append(row);
    }
    void address(const char* iface, const char* value, unsigned bits = 24, unsigned family = 4) {
        Json::Value row; row["ifname"] = iface; row["local"] = value; row["prefixlen"] = bits;
        row["family"] = family; row["scope"] = "global"; snapshot.addresses.append(row);
    }
    Fixture() { iface("radio7"); address("radio7", "192.168.5.4"); }
    ListenPlan plan(bool ipv6 = true) { return make_listen_plan(snapshot, ListenScope::lan, ipv6); }
};
const ListenEndpoint& endpoint(const ListenPlan& plan, const char* address) {
    for (const auto& value : plan.endpoints) if (value.address == address) return value;
    throw std::runtime_error("missing endpoint");
}
}
int main() {
    try {
        test("LAN is default and empty discovery retains loopback only", [] {
            const auto plan = make_listen_plan({}); require(plan.scope == ListenScope::lan && plan.endpoints.size() == 2);
            require(endpoint(plan, "127.0.0.1").allows("127.2.3.4"));
            require(!endpoint(plan, "127.0.0.1").allows("192.168.1.1"));
            require(endpoint(plan, "::1").allows("::1"));
            require(make_listen_plan({}, ListenScope::lan, false).endpoints.size() == 1);
        });
        test("only explicit all creates wildcards and unknown scopes fail", [] {
            require(listen_scope("lan") == ListenScope::lan && listen_scope("all") == ListenScope::all);
            for (const auto* value : {"", "ALL", "LAN", "remote", "all "}) invalid([&] { listen_scope(value); });
            invalid([] { make_listen_plan({}, static_cast<ListenScope>(99)); });
            const auto plan = make_listen_plan({}, ListenScope::all);
            require(plan.endpoints.size() == 2 && endpoint(plan, "0.0.0.0").allows("203.0.113.9"));
            require(endpoint(plan, "::").allows("2001:db8::7"));
            require(make_listen_plan({}, ListenScope::all, false).endpoints.size() == 1);
        });
        test("LAN selection uses interface properties rather than name or private space", [] {
            Fixture f; f.snapshot.addresses.clear(); f.address("radio7", "203.0.113.17", 27);
            const auto plan = f.plan(); require(plan.endpoints.size() == 3);
            const auto& lan = endpoint(plan, "203.0.113.17");
            require(lan.allows("203.0.113.31") && !lan.allows("203.0.113.32"));
            require(lan.allows("127.0.0.1") && !lan.allows("192.168.5.4"));
        });
        test("multiple LAN interfaces do not share their source prefixes", [] {
            Fixture f; f.iface("wired9", false); f.address("wired9", "10.2.3.4");
            const auto plan = f.plan(); require(plan.endpoints.size() == 4);
            const auto& wifi = endpoint(plan, "192.168.5.4"); const auto& wired = endpoint(plan, "10.2.3.4");
            require(wifi.allows("192.168.5.7") && !wifi.allows("10.2.3.7"));
            require(wired.allows("10.2.3.7") && !wired.allows("192.168.5.7"));
        });
        test("IPv6 global and ULA prefixes compare every bit and normalize literals", [] {
            Fixture f; f.address("radio7", "2001:0db8:0000:0000:8000::4", 65, 6);
            f.address("radio7", "fd23::4", 64, 6);
            const auto plan = f.plan();
            const auto& v6 = endpoint(plan, "2001:db8::8000:0:0:4");
            require(v6.allows("2001:db8::ffff:abcd") == false);
            require(v6.allows("2001:db8:0:0:ffff::7") && !v6.allows("2001:db8:0:0:7fff::7"));
            require(endpoint(plan, "fd23::4").allows("fd23::5"));
            require(f.plan(false).endpoints.size() == 2);
        });
        test("IPv4-mapped peers use IPv4 prefixes and cannot bypass LAN limits", [] {
            Fixture f; const auto plan = f.plan(); const auto& lan = endpoint(plan, "192.168.5.4");
            require(lan.allows("::ffff:192.168.5.9") && lan.allows("::ffff:c0a8:0509"));
            require(lan.allows("::ffff:127.0.0.1") && !lan.allows("::ffff:10.0.0.1"));
            require(!lan.allows("::192.168.5.9"));
        });
        test("down virtual tunnel bridge cellular and unidentified interfaces are excluded", [] {
            for (unsigned mode = 0; mode < 10; ++mode) {
                Fixture f; auto& iface = f.snapshot.interfaces[0];
                switch (mode) {
                    case 0: iface.up = false; break;
                    case 1: iface.virtual_device = true; break;
                    case 2: iface.tun = true; break;
                    case 3: iface.bridge = true; break;
                    case 4: iface.cellular = true; break;
                    case 5: iface.ethernet = false; break;
                    case 6: iface.leaf = false; break;
                    case 7: iface.wireless = iface.physical = false; break;
                    case 8: iface.index = 0; break;
                    case 9: f.snapshot.links.clear(); break;
                }
                require(f.plan().endpoints.size() == 2);
            }
            for (const auto* kind : {"bridge", "tun", "veth", "vlan", "rmnet", "wwan", "unknown"}) {
                Fixture f; f.snapshot.links[0]["kind"] = kind; require(f.plan().endpoints.size() == 2);
            }
            Fixture slave; slave.snapshot.links[0]["master"] = "br-vm"; require(slave.plan().endpoints.size() == 2);
        });
        test("unstable offloaded or non-direct addresses never widen source access", [] {
            for (const auto* name : {"temporary", "tentative", "dadfailed", "deprecated", "noprefixroute"}) {
                Fixture f; f.snapshot.addresses[0][name] = true; require(f.plan().endpoints.size() == 2);
                f.snapshot.addresses[0][name] = "false"; require(f.plan().endpoints.size() == 2);
            }
            Fixture offload; offload.snapshot.addresses[0]["metric"] = network::pbridge_offload_metric;
            require(offload.plan().endpoints.size() == 2);
            Fixture wrong; wrong.snapshot.addresses[0]["prefixlen"] = 0; require(wrong.plan().endpoints.size() == 2);
            wrong.snapshot.addresses[0]["prefixlen"] = 33; require(wrong.plan().endpoints.size() == 2);
            wrong.snapshot.addresses[0]["prefixlen"] = -1; require(wrong.plan().endpoints.size() == 2);
        });
        test("invalid unspecified multicast and scoped addresses are rejected", [] {
            Fixture f; const auto plan = f.plan(); const auto& lan = endpoint(plan, "192.168.5.4");
            const auto all = make_listen_plan({}, ListenScope::all);
            for (const auto& value : std::vector<std::string>{"", "localhost", "192.168.5.7:80", "192.168.5.7/24",
                "192.168.5.7 ", "192.168.5.999", "fe80::1%7", "0.0.0.0", "::", "ff02::1", "239.1.1.1",
                "255.255.255.255", std::string("192.168.5.7") + '\0' + "evil"}) {
                require(!lan.allows(value) && !all.endpoints[0].allows(value));
            }
            f.address("radio7", "fe80::1", 64, 6); require(f.plan().endpoints.size() == 3);
        });
        test("duplicate address ownership and malformed snapshots fail closed", [] {
            Fixture f; f.iface("wired9", false); f.address("wired9", "192.168.5.4"); invalid([&] { f.plan(); });
            Fixture duplicate; duplicate.snapshot.links.append(duplicate.snapshot.links[0]); invalid([&] { duplicate.plan(); });
            Fixture bad; bad.snapshot.addresses = Json::objectValue; invalid([&] { bad.plan(); });
            bad.snapshot.addresses = Json::arrayValue; bad.snapshot.links = Json::nullValue; invalid([&] { bad.plan(); });
        });
        test("immutable old plans do not inherit a later network or scope change", [] {
            Fixture f; const auto old = f.plan(); f.snapshot.addresses[0]["local"] = "10.9.8.4";
            const auto next = f.plan(); require(!endpoint(next, "10.9.8.4").allows("192.168.5.9"));
            require(!endpoint(old, "192.168.5.4").allows("10.9.8.9"));
            const auto all = make_listen_plan({}, ListenScope::all); require(all.endpoints[0].allows("198.51.100.9"));
            require(!endpoint(next, "10.9.8.4").allows("198.51.100.9"));
        });
        test("host-only prefixes and duplicate prefixes retain exact matching", [] {
            Fixture f; f.snapshot.addresses[0]["prefixlen"] = 32;
            f.address("radio7", "2001:db8::4", 128, 6); f.address("radio7", "2001:db8::4", 128, 6);
            const auto plan = f.plan(); require(plan.endpoints.size() == 4);
            require(endpoint(plan, "192.168.5.4").allows("192.168.5.4"));
            require(!endpoint(plan, "192.168.5.4").allows("192.168.5.5"));
            require(endpoint(plan, "2001:db8::4").allows("2001:db8::4"));
            require(!endpoint(plan, "2001:db8::4").allows("2001:db8::5"));
        });
        test("automatic login requires a direct peer and its actual LAN endpoint", [] {
            Fixture f; const auto plan = f.plan();
            require(direct_lan_peer(plan, "192.168.5.9", "192.168.5.4"));
            require(direct_lan_peer(plan, "::ffff:192.168.5.9", "::ffff:192.168.5.4"));
            require(!direct_lan_peer(plan, "10.0.0.9", "192.168.5.4"));
            require(!direct_lan_peer(plan, "192.168.5.9", "10.0.0.4"));
            require(!direct_lan_peer(plan, "127.0.0.1", "192.168.5.4"));
            require(!direct_lan_peer(plan, "192.168.5.9", "127.0.0.1"));
            require(!direct_lan_peer(make_listen_plan(f.snapshot, ListenScope::all), "192.168.5.9", "192.168.5.4"));
        });
        std::cout << count << " listen plan contract checks passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
