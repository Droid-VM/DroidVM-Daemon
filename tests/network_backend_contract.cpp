// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "network/links.h"
#include "network/linux_topology.h"
#include "network/policy_rules.h"
#include "network/netlink.h"
#include <linux/fib_rules.h>
#include <arpa/inet.h>
#include "store/network_config.h"
#include "common/identity.h"
#include "services/network_host.h"
#include "runtime/managed_process.h"
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <fstream>
#include <signal.h>
#include <poll.h>
#include <set>
#include <sys/stat.h>

using namespace droidvm;
using namespace droidvm::network;
using namespace droidvm::test;
namespace {
std::string executable, work, daemon_executable;
struct Case {
    std::string name = "dt" + random_id(false).substr(0, 8);
    std::string path = work + "/" + name;
    Fd directory;
    Netbox netbox{executable};
    Case() {
        check(mkdir(path.c_str(), 0700) == 0, "create case directory");
        directory = Fd(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        check(directory.get() >= 0, "open case directory");
    }
    // Preserve the journal on failure so the host can collect it and a later
    // invocation can retry only verifiably owned resources.
    void finish() {
        OwnedLinks links(directory.get(), getuid(), netbox);
        OwnedRules rules(directory.get(), getuid(), links);
        check(rules.recover_all().empty() && rules.inventory()["rules"].empty(), "cleanup registered policy rules before links");
        check(links.cleanup("test").empty(), "cleanup test-owned links");
        check(links.inventory()["links"].empty(), "no unresolved resource records");
        for (const char* file : {"network-links.json", "network-links.json.bak", "network-links.json.corrupt",
                                "network-rules.json", "network-rules.json.bak", "network-rules.json.corrupt"})
            unlinkat(directory.get(), file, 0);
        check(rmdir(path.c_str()) == 0, "remove empty test directory");
    }
};
bool exists(const std::string& name) {
    struct stat info{};
    return stat(("/sys/class/net/" + name).c_str(), &info) == 0;
}
Json::Value row(const Netbox& netbox, const std::string& name) {
    for (const auto& item : netbox.links()) if (item["ifname"] == name) return item;
    throw std::runtime_error("missing link row: " + name);
}
std::string kernel_text(const std::string& name, const std::string& property) {
    std::ifstream file("/sys/class/net/" + name + "/" + property);
    std::string value;
    check(static_cast<bool>(file >> value), "read kernel bridge property");
    return value;
}
bool kernel_locked(const std::string& name) {
    // Independent AF_BRIDGE dump reads back the real kernel port flag; ACK of
    // a SETLINK alone would not prove the kernel interpreted its attributes.
    Fd fd(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE));
    check(fd.get() >= 0, "open bridge dump");
    timeval timeout{2, 0};
    check(setsockopt(fd.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "bound dump wait");
    struct { nlmsghdr header; ifinfomsg link; } request{};
    request.header.nlmsg_len = sizeof(request); request.header.nlmsg_type = RTM_GETLINK;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP; request.header.nlmsg_seq = 91;
    request.link.ifi_family = AF_BRIDGE;
    sockaddr_nl kernel{}; kernel.nl_family = AF_NETLINK;
    check(sendto(fd.get(), &request, sizeof(request), 0, reinterpret_cast<sockaddr*>(&kernel), sizeof(kernel)) == sizeof(request), "request bridge dump");
    const auto index = if_nametoindex(name.c_str());
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (std::chrono::steady_clock::now() < deadline) {
        alignas(nlmsghdr) char bytes[65536];
        auto length = recv(fd.get(), bytes, sizeof(bytes), 0);
        check(length > 0, "receive bridge dump");
        for (auto* h = reinterpret_cast<nlmsghdr*>(bytes); NLMSG_OK(h, length); h = NLMSG_NEXT(h, length)) {
            check(h->nlmsg_type != NLMSG_DONE && h->nlmsg_type != NLMSG_ERROR, "locked flag present in dump");
            if (h->nlmsg_type != RTM_NEWLINK) continue;
            auto* link = reinterpret_cast<ifinfomsg*>(NLMSG_DATA(h));
            if (link->ifi_index != static_cast<int>(index)) continue;
            auto size = IFLA_PAYLOAD(h);
            for (auto* a = IFLA_RTA(link); RTA_OK(a, size); a = RTA_NEXT(a, size)) if ((a->rta_type & NLA_TYPE_MASK) == IFLA_PROTINFO) {
                auto nested = RTA_PAYLOAD(a);
                for (auto* flag = reinterpret_cast<rtattr*>(RTA_DATA(a)); RTA_OK(flag, nested); flag = RTA_NEXT(flag, nested))
                    if ((flag->rta_type & NLA_TYPE_MASK) == IFLA_BRPORT_LOCKED && RTA_PAYLOAD(flag) == 1)
                        return *reinterpret_cast<const uint8_t*>(RTA_DATA(flag)) != 0;
            }
        }
    }
    throw std::runtime_error("bridge dump deadline");
}
void adapter_failures() {
    NetworkHostService absent("/does/not/exist");
    error(ErrorCode::unauthenticated, [&] { absent.available_interfaces({}); });
    error(ErrorCode::permission_denied, [&] { absent.available_interfaces(owner); });
    error(ErrorCode::io_error, [&] { absent.available_interfaces(admin); });
    error(ErrorCode::unauthenticated, [&] { absent.uplinks({}); });
    error(ErrorCode::permission_denied, [&] { absent.uplinks(owner); });
    error(ErrorCode::unauthenticated, [&] { absent.addresses({}); });
    error(ErrorCode::permission_denied, [&] { absent.addresses(owner); });
    error(ErrorCode::io_error, [&] { absent.addresses(admin); });
    Netbox fake("/proc/self/exe", 80ms, 1024);
    setenv("DROIDVM_NETBOX_TEST", "failure", 1);
    error(ErrorCode::io_error, [&] { fake.links(); });
    setenv("DROIDVM_NETBOX_TEST", "invalid", 1);
    error(ErrorCode::io_error, [&] { fake.links(); });
    setenv("DROIDVM_NETBOX_TEST", "shape", 1);
    error(ErrorCode::io_error, [&] { fake.links(); });
    setenv("DROIDVM_NETBOX_TEST", "oversize", 1);
    error(ErrorCode::resource_exhausted, [&] { fake.links(); });
    setenv("DROIDVM_NETBOX_TEST", "timeout", 1);
    auto start = std::chrono::steady_clock::now();
    error(ErrorCode::unavailable, [&] { fake.links(); });
    check(std::chrono::steady_clock::now() - start < 2s, "tool timeout bounded");
    setenv("DROIDVM_NETBOX_TEST", "literal", 1);
    fake.address("dtliteral", "192.0.2.1/24;$(touch /unexpected)", true);
    unsetenv("DROIDVM_NETBOX_TEST");
    error(ErrorCode::io_error, [&] { Netbox("/does/not/exist").links(); });
    for (const std::string name : {"../wlan0", "--help", "a/b", "a b", "abcdefghijklmnop"})
        error(ErrorCode::invalid_argument, [&] { fake.add_bridge(name); });
    error(ErrorCode::invalid_argument, [&] { fake.add_tap(std::string("bad\0name", 8)); });
    check(OwnedLinks::vlan_code(1) == "AB" && OwnedLinks::vlan_code(4094) == "_-", "Java VLAN base64 naming");
    check(OwnedLinks::vlan_device("dtbridge", 0) == "dtbridge", "untagged VLAN stays on main bridge");
}
void host_address_filtering() {
    const auto links = wire::parse(R"([{"ifname":"wlanbridge","kind":"bridge"},{"ifname":"eth0","kind":"ether"}])");
    auto rows = wire::parse(R"([
        {"local":"192.0.2.1","ifname":"wlan0","family":4,"scope":"global","prefixlen":24},
        {"local":"192.0.2.2","ifname":"wlan0","family":4,"scope":"global","prefixlen":24,"metric":4243672773},
        {"local":"192.0.2.3","ifname":"wlan0","family":4,"scope":"global","prefixlen":32,"noprefixroute":true},
        {"local":"192.0.2.4","ifname":"rmnet_data0","family":4,"scope":"global","prefixlen":32},
        {"local":"192.0.2.5","ifname":"eth0","family":4,"scope":"global","prefixlen":24,"noprefixroute":true},
        {"local":"192.0.2.6","ifname":"wlanbridge","family":4,"scope":"global","prefixlen":24},
        {"local":"192.0.2.7","ifname":"ccmni0","family":4,"scope":"global","prefixlen":24},
        {"local":"fe80::1","ifname":"wlan0","family":6,"scope":"link","prefixlen":64},
        {"local":"2001:db8::1","ifname":"wlan0","family":6,"scope":"global","prefixlen":64,"temporary":true},
        {"local":"2001:db8::2","ifname":"wlan0","family":6,"scope":"global","prefixlen":64},
        {"local":"2001:db8::3","ifname":"wlan0","family":6,"scope":"global","prefixlen":128,"noprefixroute":true},
        {"local":"192.0.2.8","ifname":"tun0","family":4,"scope":"global","prefixlen":32,"temporary":false},
        {"local":"192.0.2.9","ifname":"wlan0","family":4,"scope":"global","prefixlen":24,"temporary":false,"secondary":true},
        {"local":"192.0.2.10","ifname":"wlan0","family":99,"scope":"global","prefixlen":24}
    ])");
    const auto filtered = host_addresses(links, rows);
    check(filtered.size() == 6, "host address exclusions retain exact expected set");
    Json::ArrayIndex at = 0;
    for (const auto* address : {"192.0.2.1", "192.0.2.4", "192.0.2.5", "2001:db8::2", "192.0.2.8", "192.0.2.9"}) {
        check(filtered[at]["addr"] == address && filtered[at].size() == 3, "legacy host address order and fields preserved"); ++at;
    }
    error(ErrorCode::io_error, [&] { host_addresses(Json::Value(), rows); });
    for (const auto& prefix : host_interface_prefixes()) {
        auto row = rows[0]; row["ifname"] = prefix + "123";
        Json::Value input(Json::arrayValue); input.append(row);
        check(host_addresses(Json::Value(Json::arrayValue), input).size() == 1, "shared host prefix set accepted");
    }
}
void uplink_snapshot_policy() {
    Case test;
    const auto root = test.path + "/sys";
    check(mkdir(root.c_str(), 0700) == 0, "create sysfs fixture root");
    std::vector<std::string> files, directories;
    auto write_property = [&](const std::string& name, const std::string& value) {
        std::ofstream stream(root + "/" + name); stream << value << '\n'; check(stream.good(), "write sysfs property fixture");
    };
    auto device = [&](const std::string& name, int index, int parent, int type, const std::string& state,
                      std::initializer_list<const char*> markers, const std::string& devtype = "") {
        check(mkdir((root + "/" + name).c_str(), 0700) == 0, "create interface fixture"); directories.push_back(name);
        for (const auto& [key, value] : std::vector<std::pair<std::string, std::string>>{
            {"ifindex", std::to_string(index)}, {"iflink", std::to_string(parent)}, {"type", std::to_string(type)},
            {"operstate", state}, {"uevent", "INTERFACE=" + name + (devtype.empty() ? "" : "\nDEVTYPE=" + devtype)}}) {
            write_property(name + "/" + key, value); files.push_back(name + "/" + key);
        }
        for (const auto* marker : markers) {
            check(mkdir((root + "/" + name + "/" + marker).c_str(), 0700) == 0, "create interface marker");
            directories.push_back(name + "/" + marker);
        }
    };
    device("wlan0", 1, 1, 1, "down", {"wireless", "device"});
    device("wlan1", 2, 2, 1, "up", {"phy80211", "device"});
    device("ap0", 3, 3, 1, "up", {"wireless"});
    device("eth0", 4, 4, 1, "down", {"device"});
    device("eth1", 5, 5, 1, "up", {"device"});
    device("eth2", 6, 5, 1, "up", {}, "vlan");
    device("eth3", 0, 0, 1, "up", {}); // missing/invalid identity must not imply leaf
    device("eth4", 7, 7, 1, "up", {}, "vxlan");
    device("tun0", 8, 8, 65534, "up", {"tun_flags"});
    device("wlanbridge", 9, 9, 1, "up", {"bridge"});
    device("lo", 10, 10, 772, "up", {});
    const auto first = UplinkSnapshot::scan(root);
    check(first.resolve("wIfI") == "wlan1" && first.resolve("Ethernet") == "eth1" && first.resolve("Tethering") == "ap0", "logical identifiers prefer live matching interfaces");
    check(first.resolve("tun0") == "tun0" && first.resolve("lo") == "lo" && !first.resolve("absent"), "literal interface pinned regardless of picker category");
    check(first.assume_dont_bridge("wlan1") && first.assume_dont_bridge("tun0") && !first.assume_dont_bridge("eth1"), "WiFi and raw IP require pseudo bridging");
    error(ErrorCode::invalid_argument, [&] { first.resolve("../wlan1"); });
    error(ErrorCode::not_found, [&] { first.assume_dont_bridge("absent"); });
    const auto picker = first.picker();
    std::set<std::string> visible;
    for (const auto& row : picker["devices"]) visible.insert(row["name"].asString());
    check(visible == std::set<std::string>{"wlan1", "eth1", "ap0"}, "picker excludes down, stacked, virtual, invalid identity, bridge and tun devices");
    check(picker["identifiers"].size() == 3 && picker["identifiers"][0]["id"] == "WiFi" && picker["identifiers"][0]["bridgeable"] == false, "legacy logical picker descriptors");
    write_property("wlan1/operstate", "down"); write_property("wlan0/operstate", "up");
    check(UplinkSnapshot::scan(root).resolve("WiFi") == "wlan0" && first.resolve("WiFi") == "wlan1", "fresh snapshot re-resolves changed host state");
    check(unlink((root + "/wlan0/uevent").c_str()) == 0, "simulate unplug during discovery");
    check(UplinkSnapshot::scan(root).resolve("WiFi") == "wlan1", "down wireless fallback remains when active interface disappears");
    write_property("eth1/operstate", "down");
    const auto ethernet = UplinkSnapshot::scan(root).resolve("Ethernet");
    check(ethernet == "eth0" || ethernet == "eth1", "unplugged physical ethernet remains fallback");
    error(ErrorCode::io_error, [&] { UplinkSnapshot::scan(root + "/absent"); });
    for (const auto& file : files) unlink((root + "/" + file).c_str());
    for (auto at = directories.rbegin(); at != directories.rend(); ++at) check(rmdir((root + "/" + *at).c_str()) == 0, "remove fixture interface directory");
    check(rmdir(root.c_str()) == 0, "remove sysfs fixture root"); test.finish();
}
void real_host_discovery() {
    NetworkHostService service(executable);
    const auto picker = service.uplinks(admin), addresses = service.addresses(admin);
    check(picker["identifiers"].size() == 3 && picker["devices"].isArray() && addresses.isArray(), "real host discovery schema");
    for (const auto& row : picker["devices"]) check(exists(row["name"].asString()), "real picker only includes present kernel links");
    const auto snapshot = UplinkSnapshot::scan();
    check(snapshot.resolve("lo") == "lo" && snapshot.assume_dont_bridge("lo"), "real literal lookup supports non-picker interfaces");
}
void real_datapath() {
    Case test;
    OwnedLinks links(test.directory.get(), getuid(), test.netbox);
    const auto per = OwnedLinks::vlan_device(test.name, 123), leg = OwnedLinks::vlan_leg(test.name, 123), tap = test.name + "t";
    links.bridge("test", test.name);
    links.bridge("test", per);
    links.vlan("test", test.name, leg, 123);
    check(row(test.netbox, leg)["address"] == row(test.netbox, test.name)["address"], "VLAN restores inherited parent MAC");
    check(kernel_text(test.name, "netdev_group") == "0" && kernel_text(leg, "netdev_group") == "0", "temporary creation groups cleared");
    links.tap("test", tap);
    error(ErrorCode::conflict, [&] { open_transient_tap(tap); });
    test.netbox.mac(test.name, "02:de:ad:12:34:56");
    test.netbox.stp(test.name, true);
    const auto stp = kernel_text(test.name, "bridge/stp_state");
    check(stp == "1" || stp == "2", "kernel STP enabled (kernel or userspace mode)");
    test.netbox.stp(test.name, false);
    check(kernel_text(test.name, "bridge/stp_state") == "0", "kernel STP disabled");
    test.netbox.master(leg, per);
    test.netbox.master(tap, per);
    for (const auto& name : {test.name, per, leg, tap}) test.netbox.state(name, true);
    check(row(test.netbox, leg)["address"] == "02:de:ad:12:34:56", "VLAN synchronizes parent MAC on activation");
    test.netbox.isolated(tap, true);
    check(kernel_text(tap, "brport/isolated") == "1", "kernel port isolation enabled");
    test.netbox.isolated(tap, false);
    check(kernel_text(tap, "brport/isolated") == "0", "kernel port isolation disabled");
    test.netbox.isolated(tap, true);
    test.netbox.locked(tap, true);
    check(kernel_locked(tap), "kernel MAC locking enabled");
    test.netbox.locked(tap, false);
    check(!kernel_locked(tap), "kernel MAC locking disabled");
    test.netbox.locked(tap, true);
    test.netbox.fdb(tap, "02:de:ad:12:34:57");
    test.netbox.address(per, "198.18.123.1/30", true);
    auto addresses = test.netbox.addresses(per);
    bool found = false;
    for (const auto& item : addresses) if (item["local"] == "198.18.123.1" && item["prefixlen"] == 30) found = true;
    check(found, "real bridge IPv4 assignment");
    check(row(test.netbox, test.name)["address"] == "02:de:ad:12:34:56", "stable bridge MAC");
    check(row(test.netbox, leg)["master"] == per && row(test.netbox, tap)["master"] == per, "real VLAN and TAP membership");
    check(test.netbox.neighbors(per).isArray() && test.netbox.rules(false).isArray() && test.netbox.rules(true).isArray(), "netlink queries");
    check(test.netbox.host_ips({"wlan", "rmnet"})["v4"].isArray(), "host IP query");
    NetworkHostService service(executable);
    auto interfaces = service.available_interfaces(admin);
    bool tap_found = false;
    for (const auto& iface : interfaces) {
        check(iface["name"] != test.name && iface["name"] != per && iface["name"] != "lo", "host enumeration excludes bridges and loopback");
        if (iface["name"] == tap) { tap_found = true; check(iface["master"] == per && iface.isMember("state"), "legacy host interface fields"); }
    }
    check(tap_found, "host enumeration includes real TAP");
    test.netbox.address(per, "198.18.123.1/30", false);
    for (const auto& item : test.netbox.addresses(per)) check(item["local"] != "198.18.123.1", "address removed");
    test.netbox.nomaster(tap);
    // Reconstruct the service: cleanup relies on durable identities, not memory.
    OwnedLinks restart(test.directory.get(), getuid(), test.netbox);
    check(restart.cleanup("test").empty(), "restart cleans real bridge/VLAN/TAP in reverse order");
    for (const auto& name : {test.name, per, leg, tap}) check(!exists(name), "created device removed");
    test.finish();
}
void collision_and_replacement() {
    Case test;
    OwnedLinks links(test.directory.get(), getuid(), test.netbox);
    links.bridge("test", test.name);
    auto before = row(test.netbox, test.name);
    error(ErrorCode::conflict, [&] { links.bridge("other", test.name); });
    error(ErrorCode::conflict, [&] { links.remove("other", test.name); });
    check(row(test.netbox, test.name) == before, "collision leaves original link unchanged");
    // Same name, different kernel object: cleanup must not adopt it.
    test.netbox.delete_link(test.name);
    test.netbox.add_bridge(test.name);
    check(links.cleanup("test").size() == 1 && exists(test.name), "replacement preserved");
    error(ErrorCode::conflict, [&] { links.require_owned("test", test.name); });
    // This process explicitly created the replacement above; remove that test
    // object, then allow the inventory to discard its now-absent original.
    test.netbox.delete_link(test.name);
    check(links.cleanup("test").empty(), "absent original clears stale record");
    test.netbox.add_bridge(test.name);
    error(ErrorCode::conflict, [&] { links.bridge("test", test.name); });
    check(links.inventory()["links"].empty() && exists(test.name), "pre-existing interface never reserved or deleted");
    test.netbox.delete_link(test.name);
    test.finish();
}
void dependencies_and_partial_cleanup() {
    Case test;
    OwnedLinks links(test.directory.get(), getuid(), test.netbox);
    const auto independent = test.name + "i", external = test.name + "x";
    links.bridge("test", test.name);
    links.bridge("test", independent);
    test.netbox.add_vlan(test.name, external, 321);
    auto failures = links.cleanup("test");
    check(failures.size() == 1 && exists(test.name) && exists(external) && !exists(independent), "foreign VLAN preserved; independent cleanup continues");
    test.netbox.delete_link(external);
    test.netbox.add_tap(external);
    test.netbox.master(external, test.name);
    check(links.cleanup("test").size() == 1 && exists(external), "foreign attached TAP preserved");
    test.netbox.delete_link(external);
    check(links.cleanup("test").empty(), "cleanup resumes after dependencies removed");
    test.finish();
}
void failures_and_journal() {
    Case test;
    bool fail = true;
    OwnedLinks links(test.directory.get(), getuid(), test.netbox, [&](const char* stage) {
        if (fail && std::string_view(stage) == "alias_written") throw std::runtime_error("injected setup failure");
    });
    try { links.bridge("test", test.name); throw std::logic_error("expected setup failure"); }
    catch (const std::runtime_error& error) { check(std::string_view(error.what()) == "injected setup failure", "original failure retained"); }
    check(!exists(test.name) && links.inventory()["links"].empty(), "failed setup removes tagged link");
    fail = false;
    links.bridge("test", test.name);
    bool reject_save = true;
    OwnedLinks failing(test.directory.get(), getuid(), test.netbox, {}, [&](const char* stage) {
        if (reject_save && std::string_view(stage) == "before_write") throw std::runtime_error("injected disk failure");
    });
    check(failing.cleanup("test").size() == 1 && !exists(test.name), "failed journal update retains recoverable inventory");
    reject_save = false;
    check(failing.cleanup("test").empty(), "cleanup retries idempotently after journal failure");
    test.finish();
}
void crash_recovery() {
    for (const char* kind : {"bridge", "vlan", "tap"})
    for (const char* stage : {"intent_saved", "link_created", "alias_written", "identity_saved", "link_renamed", "name_saved", "tap_persistent", "link_owned", "link_deleted"}) {
        if (std::string_view(stage) == "tap_persistent" && std::string_view(kind) != "tap") continue;
        Case test;
        ChildOptions options;
        options.argv = {"/proc/self/exe", "--crash", executable, test.path, test.name, stage, kind};
        auto result = Child(options).communicate({}, 10s);
        check(result.exit_code == -SIGKILL, "child reached SIGKILL boundary");
        bool remains = std::string_view(stage) != "intent_saved" && std::string_view(stage) != "link_deleted";
        if (std::string_view(kind) == "tap") remains = std::string_view(stage) == "tap_persistent" || std::string_view(stage) == "link_owned";
        OwnedLinks restart(test.directory.get(), getuid(), test.netbox);
        std::string staging;
        const auto inventory = restart.inventory();
        for (const auto& record : inventory["links"]) if (record["name"] == test.name)
            staging = record.get("staging_name", "").asString();
        check((exists(test.name) || (!staging.empty() && exists(staging))) == remains, "persistent vs transient link at crash boundary");
        auto failures = restart.cleanup("test");
        check(failures.empty() && !exists(test.name) && (staging.empty() || !exists(staging)), "automatic durable identity cleanup across crash");
        test.finish();
    }
}
void lifecycle_races() {
    Case test;
    bool replace = false;
    OwnedLinks links(test.directory.get(), getuid(), test.netbox, [&](const char* stage) {
        if (replace && std::string_view(stage) == "delete_identity_checked") {
            replace = false;
            test.netbox.delete_link(test.name);
            test.netbox.add_bridge(test.name);
        }
    });
    links.bridge("test", test.name);
    const auto old_index = if_nametoindex(test.name.c_str());
    replace = true;
    check(links.cleanup("test").size() == 1, "replacement after identity check reported");
    check(exists(test.name) && if_nametoindex(test.name.c_str()) != old_index, "index-based deletion preserves new same-name interface");
    test.netbox.delete_link(test.name);
    check(links.cleanup("test").empty(), "stale deletion record clears after replacement resolved");
    bool collide = true;
    OwnedLinks collision(test.directory.get(), getuid(), test.netbox, [&](const char* stage) {
        if (collide && std::string_view(stage) == "intent_saved") {
            collide = false;
            test.netbox.add_bridge(test.name);
        }
    });
    error(ErrorCode::conflict, [&] { collision.bridge("test", test.name); });
    check(exists(test.name) && collision.inventory()["links"].empty(), "rename conflict preserves destination and rolls back staging link");
    test.netbox.delete_link(test.name);
    check(collision.cleanup("test").empty(), "collision intent retained until identity resolved");
    test.finish();
}
Json::Value topology_config(const std::string& bridge) {
    auto value = wire::parse(R"({"schema":2,"name":"topology","bridge_type":"linux","l3":{"vlans":[
        {"vlan_id":0,"ipv4":{"cidr":"198.18.125.1/28"},"ipv6":{"cidr":"fd91:fe21:12::1/64"},
         "ipv4_secondary":["198.18.125.1/28","198.18.126.1/28"],"ipv6_secondary":["fd91:fe21:13::1/64"]},
        {"vlan_id":123,"ipv4":{"cidr":"198.18.127.1/28"}},
        {"vlan_id":4094,"ipv6":{"source":"dhcp_pd","cidr":"fd91:fe21:14::1/64","pd":{"uplink":"unresolved"}}}
    ]}})");
    value["id"] = random_id(true); value["bridge_name"] = bridge;
    return value;
}
void real_linux_topology() {
    Case test;
    OwnedLinks links(test.directory.get(), getuid(), test.netbox);
    LinuxTopology topology(test.netbox, links);
    const auto configuration = topology_config(test.name);
    topology.start(configuration, "02:de:ad:12:34:56");
    check(topology.devices().size() == 5, "VLAN zero has no separate bridge or leg");
    check(row(test.netbox, test.name)["address"] == "02:de:ad:12:34:56", "prepared main bridge MAC applied");
    check(kernel_text(test.name, "bridge/stp_state") == "0", "configured STP disabled");
    for (const auto& name : topology.devices()) {
        std::ifstream policy("/proc/sys/net/ipv6/conf/" + name + "/accept_ra");
        std::string value; check(static_cast<bool>(policy >> value) && value == "0", "all guest-facing links disable RA acceptance");
        const auto flags = std::stoul(kernel_text(name, "flags"), nullptr, 16);
        check(flags & IFF_UP, "configured topology links administratively up");
    }
    for (const int vid : {123, 4094}) {
        const auto leg = OwnedLinks::vlan_leg(test.name, vid), per = OwnedLinks::vlan_device(test.name, vid);
        check(row(test.netbox, leg)["master"] == per, "tagged trunk attached to its per-VLAN bridge");
        check(row(test.netbox, leg)["address"] == row(test.netbox, test.name)["address"], "trunk leg inherits stable main MAC");
    }
    auto addresses = [&](const std::string& device) {
        std::set<std::string> result;
        for (const auto& entry : test.netbox.addresses(device)) {
            const auto local = entry["local"].asString();
            const auto cidr = local + "/" + std::to_string(entry["prefixlen"].asInt());
            const auto prefix = config::NetworkPrefix::parse(cidr, local.find(':') != std::string::npos);
            result.insert(prefix.address() + "/" + std::to_string(prefix.prefix()));
        }
        return result;
    };
    const auto main = addresses(test.name);
    for (const auto* cidr : {"198.18.125.1/28", "198.18.126.1/28", "fd91:fe21:12::1/64", "fd91:fe21:13::1/64"}) {
        const auto prefix = config::NetworkPrefix::parse(cidr, std::string_view(cidr).find(':') != std::string_view::npos);
        check(main.contains(prefix.address() + "/" + std::to_string(prefix.prefix())), "primary/secondary address installed on VLAN zero");
    }
    check(addresses(OwnedLinks::vlan_device(test.name, 123)).contains("198.18.127.1/28"), "tagged VLAN gateway address");
    const auto pd = config::NetworkPrefix::parse("fd91:fe21:14::1/64", true);
    check(!addresses(OwnedLinks::vlan_device(test.name, 4094)).contains(pd.address() + "/64"), "PD ignores stale static primary address");
    topology.verify();
    error(ErrorCode::conflict, [&] { topology.start(configuration, "02:de:ad:12:34:56"); });
    topology.stop(); topology.stop();
    check(links.inventory()["links"].empty() && !exists(test.name), "topology normal cleanup reclaims every link");
    test.finish();
}
void linux_topology_failure_and_recovery() {
    Case test;
    OwnedLinks links(test.directory.get(), getuid(), test.netbox);
    for (const char* stage : {"main_configured", "vlan_attached", "address_added", "topology_ready"}) {
        LinuxTopology topology(test.netbox, links, [&](const char* reached) {
            if (std::string_view(reached) == stage) throw std::runtime_error("topology injection");
        });
        try { topology.start(topology_config(test.name), "02:de:ad:12:34:56"); throw std::logic_error("missing injected failure"); }
        catch (const std::runtime_error& failure) { check(std::string_view(failure.what()) == "topology injection", "injected topology failure retained"); }
        check(links.inventory()["links"].empty() && !exists(test.name), "partial topology automatically rolled back");
    }
    const auto per = OwnedLinks::vlan_device(test.name, 123);
    test.netbox.add_bridge(per);
    const auto foreign_index = if_nametoindex(per.c_str());
    LinuxTopology topology(test.netbox, links);
    error(ErrorCode::conflict, [&] { topology.start(topology_config(test.name), "02:de:ad:12:34:56"); });
    check(!exists(test.name) && links.inventory()["links"].empty() && if_nametoindex(per.c_str()) == foreign_index,
        "per-VLAN collision fails before main bridge creation and preserves foreign interface");
    test.netbox.delete_link(per);
    topology.start(topology_config(test.name), "02:de:ad:12:34:56");
    const auto foreign = test.name + "t";
    test.netbox.add_tap(foreign); test.netbox.master(foreign, test.name);
    error(ErrorCode::io_error, [&] { topology.stop(); });
    check(exists(foreign) && exists(test.name), "failed cleanup keeps bridge with foreign port");
    links.bridge("independent", test.name + "i");
    check(links.recover_all().size() == 1 && !exists(test.name + "i") && exists(foreign), "startup recovery continues independent owner after failure");
    test.netbox.delete_link(foreign);
    topology.stop();
    test.finish();
}
void linux_topology_crash_recovery() {
    for (const char* stage : {"main_configured", "vlan_attached", "address_added", "topology_ready"}) {
        Case test;
        ChildOptions options;
        options.argv = {"/proc/self/exe", "--topology-crash", executable, test.path, test.name, stage};
        check(Child(options).communicate({}, 20s).exit_code == -SIGKILL, "topology child reached real SIGKILL boundary");
        OwnedLinks restarted(test.directory.get(), getuid(), test.netbox);
        check(!restarted.inventory()["links"].empty() && exists(test.name), "crash leaves durable kernel link inventory");
        check(restarted.recover_all().empty() && restarted.inventory()["links"].empty() && !exists(test.name), "restart reclaims complete or partial topology");
        test.finish();
    }
}
void link_inventory_rejects_stale_backup() {
    Case test;
    OwnedLinks links(test.directory.get(), getuid(), test.netbox);
    links.bridge("test", test.name);
    const auto latest = links.inventory();
    { std::ofstream backup(test.path + "/network-links.json.bak", std::ios::trunc); backup << R"({"schema":1,"links":[]})"; }
    { std::ofstream broken(test.path + "/network-links.json", std::ios::trunc); broken << "{broken"; }
    error(ErrorCode::io_error, [&] { OwnedLinks rejected(test.directory.get(), getuid(), test.netbox); });
    check(exists(test.name), "damaged primary never treats stale empty backup as complete inventory");
    config::JsonFile(test.directory.get(), "network-links.json", getuid()).save(latest);
    check(links.recover_all().empty(), "restore known latest fixture inventory and recover");
    test.finish();
}
PolicyRule test_rule(const std::string& name, bool ipv6, uint32_t table = 123456) {
    PolicyRule result; result.input = name; result.ipv6 = ipv6; result.lookup = result.plain = true;
    result.table = table; result.priority = OwnedRules::priority_base; result.protocol = OwnedRules::protocol;
    result.mark = 12345; result.mask = 0;
    return result;
}
PolicyRule installed_rule(const std::string& name, bool ipv6) {
    for (const auto& rule : policy_rules(ipv6)) if (rule.input == name && rule.priority == OwnedRules::priority_base && rule.protocol == OwnedRules::protocol)
        return rule;
    throw std::runtime_error("missing installed policy fixture rule");
}
std::vector<std::pair<uint32_t, uint32_t>> observed_rules(Case& test, bool ipv6) {
    // The existing Rust tool independently decodes the kernel, rather than
    // trusting the new adapter's encoder and decoder to agree with each other.
    std::vector<std::pair<uint32_t, uint32_t>> result;
    for (const auto& row : test.netbox.rules(ipv6)) if (row["iif"] == test.name)
        result.emplace_back(row["priority"].asUInt(), row["table"].asUInt());
    return result;
}
void variant_rule(const PolicyRule& rule, bool marked, bool add) {
    NetlinkMessage<fib_rule_hdr> request;
    request.header.nlmsg_type = add ? RTM_NEWRULE : RTM_DELRULE;
    if (add) request.header.nlmsg_flags |= NLM_F_CREATE; // deliberately allow a duplicate fixture
    request.payload.family = rule.ipv6 ? AF_INET6 : AF_INET; request.payload.action = FR_ACT_TO_TBL;
    request.attribute(FRA_IIFNAME, rule.input.c_str(), rule.input.size() + 1);
    request.attribute(FRA_TABLE, &rule.table, sizeof(rule.table));
    request.attribute(FRA_PRIORITY, &rule.priority, sizeof(rule.priority));
    request.attribute(FRA_PROTOCOL, &rule.protocol, sizeof(rule.protocol));
    const uint32_t mark = marked ? (rule.mark.value_or(0) == 1 ? 2 : 1) : rule.mark.value_or(0), mask = marked ? 1 : 0;
    request.attribute(FRA_FWMARK, &mark, sizeof(mark));
    request.attribute(FRA_FWMASK, &mask, sizeof(mask));
    netlink_exchange(request.header);
}
void routing_table_policy() {
    std::vector<PolicyRule> input;
    auto row = test_rule("lo", false, 1001); row.mark.reset(); row.mask = 0x20000; input.push_back(row);
    row.table = 1002; row.mark = 0; row.mask = 0xffff; input.push_back(row);
    input.push_back(row); // stable first-occurrence deduplication
    row.table = 1003; row.mark = 0x10003; input.push_back(row);
    row.table = 1004; row.mark.reset(); row.mask.reset(); input.push_back(row); // oif-only rule
    row.table = 1005; row.mask = 0xffff; row.input = "wlan0"; input.push_back(row);
    row.table = 1006; row.input = "lo"; row.lookup = false; input.push_back(row);
    check(local_app_tables(input) == std::vector<uint32_t>({1001, 1002}), "VPN before default, marked and oif-only rules excluded");
    for (bool ipv6 : {false, true}) {
        const auto native = policy_rules(ipv6);
        Netbox netbox(executable);
        std::vector<uint32_t> expected; std::set<uint32_t> seen;
        for (const auto& item : netbox.rules(ipv6)) if (item["lookup"] == true && item["iif"] == "lo" &&
            !item["fwmask"].isNull() && (item["fwmark"].isNull() || item["fwmark"].asUInt() == 0)) {
            const auto table = item["table"].asUInt(); if (table && seen.insert(table).second) expected.push_back(table);
        }
        check(local_app_tables(native) == expected, "live default-app tables match independent netbox snapshot");
    }
}
void real_policy_chains() {
    Case test; OwnedLinks links(test.directory.get(), getuid(), test.netbox);
    links.bridge("test", test.name);
    size_t mutations = 0;
    OwnedRules rules(test.directory.get(), getuid(), links, [&](const char*) { ++mutations; });
    for (bool ipv6 : {false, true}) {
        rules.reconcile("test", test.name, ipv6, {123456, 123457});
        check(observed_rules(test, ipv6) == std::vector<std::pair<uint32_t, uint32_t>>({{9000, 123456}, {9001, 123457}}), "ordered dual-stack policy chain installed");
        const auto before = mutations;
        rules.reconcile("test", test.name, ipv6, {123456, 123457});
        check(mutations == before, "unchanged chain does not mutate kernel or inventory");
        OwnedRules reloaded(test.directory.get(), getuid(), links, [&](const char*) { ++mutations; });
        reloaded.reconcile("test", test.name, ipv6, {123456, 123457});
        check(mutations == before, "reloaded numeric identity compares by value without needless rewrites");
        rules.reconcile("test", test.name, ipv6, {123458});
        check(observed_rules(test, ipv6) == std::vector<std::pair<uint32_t, uint32_t>>({{9000, 123458}}), "upstream table change reconciles chain");
        rules.reconcile("test", test.name, ipv6, {});
        check(observed_rules(test, ipv6).empty(), "upstream loss removes only registered chain");
    }
    error(ErrorCode::invalid_argument, [&] { rules.reconcile("test", test.name, false, {1, 1}); });
    error(ErrorCode::invalid_argument, [&] { rules.reconcile("test", test.name, false, {0}); });
    error(ErrorCode::conflict, [&] { rules.reconcile("foreign", test.name, false, {1}); });
    // Rules survive interface deletion in the detached state. They must be
    // reclaimed even if the link journal has already been retired.
    rules.reconcile("test", test.name, false, {123456});
    rules.reconcile("test", test.name, true, {123456});
    links.remove("test", test.name);
    check(!observed_rules(test, false).empty() && !observed_rules(test, true).empty(), "kernel retains detached rules");
    check(rules.recover_all().empty() && rules.inventory()["rules"].empty(), "detached rules reclaimed after missing original link");
    test.finish();
}
void ownership_cookie_routing() {
    Case test; OwnedLinks links(test.directory.get(), getuid(), test.netbox);
    links.bridge("test", test.name); test.netbox.state(test.name, true);
    OwnedRules rules(test.directory.get(), getuid(), links);
    const uint32_t index = if_nametoindex(test.name.c_str()), table = 1700000000u + index;
    for (const bool ipv6 : {false, true}) {
        // Change forwarding only on our isolated bridge, never the phone's
        // global forwarding settings or a physical uplink.
        const auto sysctl = std::string("/proc/sys/net/") + (ipv6 ? "ipv6" : "ipv4") + "/conf/" + test.name + "/forwarding";
        { std::ofstream setting(sysctl); setting << "1"; setting.flush(); check(setting.good(), "enable fixture bridge forwarding"); }
        const auto family = ipv6 ? AF_INET6 : AF_INET;
        std::array<unsigned char, 16> network{}, source{}, destination{};
        check(inet_pton(family, ipv6 ? "fd91:fe21:ff00::" : "198.19.222.0", network.data()) == 1 &&
            inet_pton(family, ipv6 ? "fd91:fe21:ff00::2" : "198.19.222.2", source.data()) == 1 &&
            inet_pton(family, ipv6 ? "fd91:fe21:ff00::3" : "198.19.222.3", destination.data()) == 1, "parse route lookup fixture addresses");
        const size_t bytes = ipv6 ? 16 : 4;
        NetlinkMessage<rtmsg> route;
        route.header.nlmsg_type = RTM_NEWROUTE; route.header.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
        route.payload.rtm_family = family; route.payload.rtm_dst_len = ipv6 ? 64 : 24;
        route.payload.rtm_protocol = RTPROT_STATIC; route.payload.rtm_type = RTN_UNICAST; route.payload.rtm_scope = RT_SCOPE_LINK;
        route.attribute(RTA_DST, network.data(), bytes); route.attribute(RTA_TABLE, &table, sizeof(table));
        route.attribute(RTA_OIF, &index, sizeof(index)); netlink_exchange(route.header);
        rules.reconcile("test", test.name, ipv6, {table});
        const auto installed = installed_rule(test.name, ipv6);
        check(installed.mark.value_or(0) && installed.mask.value_or(0) == 0, "ownership cookie has an explicit match-all mask");
        for (const uint32_t mark : {0u, 1u, UINT32_MAX}) {
            NetlinkMessage<rtmsg> query;
            query.header.nlmsg_type = RTM_GETROUTE; query.header.nlmsg_flags = NLM_F_REQUEST;
            query.payload.rtm_family = family; query.payload.rtm_dst_len = query.payload.rtm_src_len = ipv6 ? 128 : 32;
            query.payload.rtm_flags = RTM_F_FIB_MATCH | RTM_F_LOOKUP_TABLE;
            query.attribute(RTA_DST, destination.data(), bytes); query.attribute(RTA_SRC, source.data(), bytes);
            query.attribute(RTA_IIF, &index, sizeof(index)); query.attribute(RTA_MARK, &mark, sizeof(mark));
            const auto responses = netlink_exchange(query.header, RTM_NEWROUTE);
            check(responses.size() == 1, "kernel returns one FIB result");
            const auto* header = reinterpret_cast<const nlmsghdr*>(responses[0].data());
            check(header->nlmsg_len >= NLMSG_LENGTH(sizeof(rtmsg)), "kernel FIB result has route header");
            const auto* result = reinterpret_cast<const rtmsg*>(NLMSG_DATA(header));
            uint32_t selected = result->rtm_table, output = 0;
            auto length = RTM_PAYLOAD(header);
            for (const auto* a = RTM_RTA(result); RTA_OK(a, length); a = RTA_NEXT(a, length)) {
                if (a->rta_type == RTA_TABLE && RTA_PAYLOAD(a) == sizeof(selected)) memcpy(&selected, RTA_DATA(a), sizeof(selected));
                if (a->rta_type == RTA_OIF && RTA_PAYLOAD(a) == sizeof(output)) memcpy(&output, RTA_DATA(a), sizeof(output));
            }
            if (selected != table || output != index) throw std::runtime_error("cookie FIB lookup family=" + std::to_string(family) +
                " mark=" + std::to_string(mark) + " table=" + std::to_string(selected) + "/" + std::to_string(table) +
                " oif=" + std::to_string(output) + "/" + std::to_string(index));
        }
        check(rules.cleanup("test").empty(), "cookie rule cleanup after real FIB queries");
    }
    // The private-table routes are kernel dependents of this owned bridge.
    // No broad table flush is needed or allowed.
    test.finish();
}
void policy_conflicts_and_races() {
    Case test; OwnedLinks links(test.directory.get(), getuid(), test.netbox);
    links.bridge("test", test.name);
    OwnedRules rules(test.directory.get(), getuid(), links);
    test.netbox.rule(test.name, 123456, 9000, false, true);
    error(ErrorCode::conflict, [&] { rules.reconcile("test", test.name, false, {123456}); });
    check(rules.inventory()["rules"].empty() && observed_rules(test, false).size() == 1, "preexisting unmarked rule is never adopted");
    test.netbox.rule(test.name, 123456, 9000, false, false);
    rules.reconcile("test", test.name, false, {123456});
    auto owned = installed_rule(test.name, false);
    change_policy_rule(owned, false);
    auto foreign = owned; foreign.protocol = 187;
    change_policy_rule(foreign, true);
    check(rules.cleanup("test").size() == 1 && rules.inventory()["rules"].size() == 1, "replacement refuses cleanup and retains evidence");
    links.bridge("independent", test.name + "i");
    rules.reconcile("independent", test.name + "i", false, {123457});
    check(rules.recover_all().size() == 1 && rules.inventory()["rules"].size() == 1, "recovery attempts independent chain after a conflict");
    links.remove("independent", test.name + "i");
    change_policy_rule(foreign, false);
    check(rules.cleanup("test").empty(), "absent rule permits retry");
    rules.reconcile("test", test.name, false, {123456});
    change_policy_rule(owned, false); variant_rule(owned, true, true);
    check(rules.cleanup("test").size() == 1 && observed_rules(test, false).size() == 1, "same-protocol rule with fwmark selector is not the registered rule");
    variant_rule(owned, true, false); check(rules.cleanup("test").empty(), "marked replacement fixture retired explicitly");
    rules.reconcile("test", test.name, false, {123456});
    variant_rule(owned, false, true);
    check(rules.cleanup("test").size() == 1 && observed_rules(test, false).size() == 2, "ambiguous identical duplicates are preserved");
    change_policy_rule(owned, false);
    check(rules.cleanup("test").empty(), "duplicate removal permits original registered rule recovery");
    // Unknown rows with our protocol are still not ours without a journal.
    foreign = owned; foreign.priority = 9050;
    change_policy_rule(foreign, true);
    rules.reconcile("test", test.name, false, {123456});
    check(rules.cleanup("test").empty() && observed_rules(test, false).size() == 1, "unregistered same-protocol rule survives cleanup");
    change_policy_rule(foreign, false);
    bool replace = false, marked_replacement = false;
    OwnedRules race(test.directory.get(), getuid(), links, [&](const char* stage) {
        if (replace && std::string_view(stage) == "before_rule_delete") {
            replace = false; change_policy_rule(owned, false);
            if (marked_replacement) variant_rule(owned, true, true);
            else { auto replacement = owned; replacement.protocol = 187; change_policy_rule(replacement, true); }
        }
    });
    race.reconcile("test", test.name, false, {123456});
    replace = true;
    check(race.cleanup("test").empty() && observed_rules(test, false).size() == 1, "kernel deletion protocol prevents replacement race deletion");
    foreign = owned; foreign.protocol = 187; change_policy_rule(foreign, false);
    race.reconcile("test", test.name, false, {123456});
    replace = marked_replacement = true;
    check(race.cleanup("test").empty() && observed_rules(test, false).size() == 1, "explicit delete selectors preserve same-protocol marked replacement race");
    variant_rule(owned, true, false);
    // A new same-name link must not authorize deletion of the previous link's
    // rules, whether this kernel reattaches them or leaves them detached.
    race.reconcile("test", test.name, false, {123456});
    links.remove("test", test.name); links.bridge("test", test.name);
    check(race.cleanup("test").size() == 1, "same-name recreated link is not original rule owner");
    change_policy_rule(owned, false);
    check(race.cleanup("test").empty(), "explicit fixture removal permits journal retirement");
    test.finish();
}
void policy_journal_failures() {
    Case test; OwnedLinks links(test.directory.get(), getuid(), test.netbox); links.bridge("test", test.name);
    bool fail = true;
    OwnedRules rules(test.directory.get(), getuid(), links, {}, [&](const char* stage) {
        if (fail && std::string_view(stage) == "before_install") throw std::runtime_error("policy write injection");
    });
    bool threw = false;
    try { rules.reconcile("test", test.name, false, {123456}); } catch (const config::CommitError&) { threw = true; }
    check(threw && observed_rules(test, false).empty(), "intent write failure has no kernel side effect");
    fail = false; rules.reconcile("test", test.name, false, {123456});
    const auto latest = rules.inventory();
    auto different = latest; different["rules"][0]["link"]["namespace_inode"] = Json::UInt64(1);
    config::JsonFile(test.directory.get(), "network-rules.json", getuid()).save(different);
    OwnedRules wrong_namespace(test.directory.get(), getuid(), links);
    check(wrong_namespace.recover_all().size() == 1 && observed_rules(test, false).size() == 1, "foreign namespace inventory never mutates current rules");
    config::JsonFile(test.directory.get(), "network-rules.json", getuid()).save(latest);
    { std::ofstream backup(test.path + "/network-rules.json.bak", std::ios::trunc); backup << R"({"schema":1,"rules":[]})"; }
    { std::ofstream primary(test.path + "/network-rules.json", std::ios::trunc); primary << "{broken"; }
    error(ErrorCode::io_error, [&] { OwnedRules rejected(test.directory.get(), getuid(), links); });
    check(observed_rules(test, false).size() == 1, "damaged primary never forgets live rules via stale backup");
    config::JsonFile(test.directory.get(), "network-rules.json", getuid()).save(latest);
    fail = true;
    check(rules.cleanup("test").size() == 1 && rules.inventory()["rules"].size() == 1 && observed_rules(test, false).empty(), "deletion journal failure retains retry evidence");
    fail = false; check(rules.recover_all().empty(), "deletion retry retires already absent rule");
    test.finish();
}
void policy_crash_recovery() {
    for (const bool ipv6 : {false, true}) for (const char* stage : {"rule_intent_saved", "rule_created", "rule_identity_saved",
            "before_rule_delete", "rule_deleted", "rule_record_removed"}) {
        Case test;
        ChildOptions child;
        child.argv = {"/proc/self/exe", "--rules-crash", executable, test.path, test.name, stage, ipv6 ? "6" : "4"};
        check(Child(child).communicate({}, 10s).exit_code == -SIGKILL, "policy rule child reached real SIGKILL boundary");
        OwnedLinks links(test.directory.get(), getuid(), test.netbox);
        OwnedRules recovered(test.directory.get(), getuid(), links);
        check(recovered.recover_all().empty() && recovered.inventory()["rules"].empty() && observed_rules(test, ipv6).empty(), "restart reclaims pending, installed or deleted rule");
        test.finish();
    }
}
void daemon_linux_topology_recovery() {
    for (const bool obstruct : {false, true}) {
        Case test;
        for (const char* name : {"run", "bin"}) check(mkdir((test.path + "/" + name).c_str(), 0700) == 0, "create daemon topology fixture directories");
        check(symlink(executable.c_str(), (test.path + "/bin/netbox").c_str()) == 0, "reuse existing netbox in isolated daemon data");
        { std::ofstream apk(test.path + "/fixture.apk"); apk << "isolated topology fixture"; }
        ChildOptions fixture;
        fixture.argv = {"/proc/self/exe", "--topology-crash", executable, test.path + "/run", test.name, "topology_ready"};
        check(Child(fixture).communicate({}, 20s).exit_code == -SIGKILL, "leave topology from killed owner for actual daemon recovery");
        {
            Fd run(open((test.path + "/run").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
            OwnedLinks links(run.get(), getuid(), test.netbox);
            OwnedRules rules(run.get(), getuid(), links);
            const auto id = links.inventory()["links"][0]["owner"].asString();
            rules.reconcile(id, test.name, false, {123456});
            rules.reconcile(id, test.name, true, {123456});
        }
        const auto foreign = test.name + "t";
        ChildOptions launch;
        launch.argv = {daemon_executable, "--data-dir", test.path, "--apk", test.path + "/fixture.apk"};
        if (obstruct) {
            const auto owned = installed_rule(test.name, false);
            auto replacement = owned; replacement.protocol = 187;
            change_policy_rule(owned, false); change_policy_rule(replacement, true);
            const auto rules_rejected = Child(launch).communicate({}, 15s);
            check(rules_rejected.exit_code == 1 && rules_rejected.error.find("Network rule recovery incomplete") != std::string::npos &&
                access((test.path + "/run/droidvmd-port.txt").c_str(), F_OK) < 0 && exists(test.name),
                "daemon refuses readiness and preserves topology after policy identity conflict");
            change_policy_rule(replacement, false); change_policy_rule(owned, true);
            test.netbox.add_tap(foreign); test.netbox.master(foreign, test.name);
            const auto rejected = Child(launch).communicate({}, 15s);
            check(rejected.exit_code == 1 && rejected.error.find("Network link recovery incomplete") != std::string::npos &&
                access((test.path + "/run/droidvmd-port.txt").c_str(), F_OK) < 0,
                "daemon refuses readiness when owned topology cleanup is incomplete");
            check(exists(test.name) && exists(foreign), "failed startup preserves foreign dependency");
            test.netbox.delete_link(foreign);
        }
        Child daemon(launch);
        const auto deadline = std::chrono::steady_clock::now() + 15s;
        while (access((test.path + "/run/droidvmd-port.txt").c_str(), F_OK) < 0 && !daemon.poll_exit() && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(10ms);
        if (daemon.poll_exit() || access((test.path + "/run/droidvmd-port.txt").c_str(), F_OK) < 0) {
            std::cerr << daemon.communicate({}, 1s).error << std::endl;
            throw std::runtime_error("daemon topology recovery did not reach readiness");
        }
        Fd run(open((test.path + "/run").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        check(!exists(test.name) && config::JsonFile(run.get(), "network-links.json", getuid()).load()->value["links"].empty(),
            "actual daemon reclaims topology before publishing readiness");
        check(config::JsonFile(run.get(), "network-rules.json", getuid()).load()->value["rules"].empty() &&
            observed_rules(test, false).empty() && observed_rules(test, true).empty(), "actual daemon reclaims both policy families before links and readiness");
        check(daemon.signal(SIGTERM) && daemon.communicate({}, 5s).exit_code == 128 + SIGTERM, "recovery daemon stops normally");
        for (const char* name : {"run/network-links.json", "run/network-links.json.bak", "run/network-rules.json", "run/network-rules.json.bak",
                                "run/droidvmd.lock", "cache/daemon.log", "bin/netbox", "fixture.apk"})
            unlink((test.path + "/" + name).c_str());
        for (const char* name : {"run", "bin", "cache", "files"}) check(rmdir((test.path + "/" + name).c_str()) == 0, "remove isolated daemon topology directory");
        test.finish();
    }
}
void real_address_monitor() {
    Case test;
    OwnedLinks links(test.directory.get(), getuid(), test.netbox);
    links.tap("test", test.name);
    test.netbox.state(test.name, true);
    ManagedProcess monitor;
    monitor.start(test.netbox.monitor({test.name}));
    auto observe = [&](bool present) {
        const auto deadline = std::chrono::steady_clock::now() + 5s;
        while (std::chrono::steady_clock::now() < deadline) {
            auto output = monitor.take_output();
            check(output.status.running && !output.resync_required, "real monitor healthy with complete events");
            for (const auto& line : output.lines) {
                if (line.stream != ProcessStream::output || line.text.empty() || line.text.front() != '{') continue;
                auto snapshot = wire::parse(line.text);
                if (!snapshot["v4"].isArray()) continue;
                bool found = false;
                for (const auto& address : snapshot["v4"]) if (address == "198.18.124.1") found = true;
                if (found == present) return;
            }
            pollfd fd{monitor.event_fd(), POLLIN, 0}; poll(&fd, 1, 100);
        }
        throw std::runtime_error("real address monitor deadline");
    };
    observe(false);
    test.netbox.address(test.name, "198.18.124.1/30", true);
    observe(true);
    test.netbox.address(test.name, "198.18.124.1/30", false);
    observe(false);
    monitor.stop(500ms);
    check(!monitor.status().running && !monitor.status().unexpected_exit && monitor.status().error.empty(), "real address monitor stopped and reaped");
    check(links.cleanup("test").empty(), "monitor test TAP reclaimed");
    test.finish();
}
int fake(int argc, char** argv) {
    const std::string mode = getenv("DROIDVM_NETBOX_TEST");
    if (mode == "failure") { std::cerr << "tool failure"; return 23; }
    if (mode == "invalid") { std::cout << "[broken"; return 0; }
    if (mode == "shape") { std::cout << "[42]"; return 0; }
    if (mode == "oversize") { std::cout << std::string(65536, 'x'); return 0; }
    if (mode == "timeout") { signal(SIGTERM, SIG_IGN); for (;;) pause(); }
    if (mode == "literal") return argc == 4 && std::string_view(argv[1]) == "addr-add" &&
        std::string_view(argv[2]) == "dtliteral" && std::string_view(argv[3]) == "192.0.2.1/24;$(touch /unexpected)" ? 0 : 23;
    return 99;
}
}
int main(int argc, char** argv) {
    if (getenv("DROIDVM_NETBOX_TEST")) return fake(argc, argv);
    if (argc == 5 && std::string_view(argv[1]) == "--policy-only") {
        executable = argv[2]; work = argv[3]; daemon_executable = argv[4];
        return run({{"routing_table_policy", routing_table_policy}, {"real_dual_stack_policy_chains", real_policy_chains},
            {"ownership_cookie_preserves_kernel_routing", ownership_cookie_routing},
            {"policy_conflicts_replacement_and_races", policy_conflicts_and_races}, {"policy_journal_failures", policy_journal_failures},
            {"twelve_policy_sigkill_boundaries", policy_crash_recovery}});
    }
    if (argc == 7 && std::string_view(argv[1]) == "--rules-crash") {
        Netbox netbox(argv[2]);
        Fd directory(open(argv[3], O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        OwnedLinks links(directory.get(), getuid(), netbox); links.bridge("test", argv[4]);
        OwnedRules rules(directory.get(), getuid(), links, [&](const char* stage) {
            if (std::string_view(stage) == argv[5]) { kill(getpid(), SIGKILL); _exit(73); }
        });
        rules.reconcile("test", argv[4], std::string_view(argv[6]) == "6", {123456});
        rules.cleanup("test"); return 74;
    }
    if (argc == 6 && std::string_view(argv[1]) == "--topology-crash") {
        Netbox netbox(argv[2]);
        Fd directory(open(argv[3], O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        OwnedLinks links(directory.get(), getuid(), netbox);
        LinuxTopology topology(netbox, links, [&](const char* stage) {
            if (std::string_view(stage) == argv[5]) { kill(getpid(), SIGKILL); _exit(73); }
        });
        topology.start(topology_config(argv[4]), "02:de:ad:12:34:56");
        topology.stop(); return 74;
    }
    if (argc == 3 && std::string_view(argv[1]) == "--query") {
        const auto start = std::chrono::steady_clock::now();
        Json::Value result;
        try { result["interfaces"] = NetworkHostService(argv[2]).available_interfaces(admin); }
        catch (const ServiceError& error) { result["error"] = error_code_name(error.code()); result["message"] = error.what(); }
        result["elapsed_ms"] = Json::Int64(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count());
        std::cout << wire::stringify(result) << std::endl;
        return 0;
    }
    if (argc == 4 && std::string_view(argv[1]) == "--cleanup") {
        Netbox netbox(argv[2]);
        Fd directory(open(argv[3], O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        OwnedLinks links(directory.get(), getuid(), netbox);
        OwnedRules rules(directory.get(), getuid(), links);
        const auto rule_errors = rules.recover_all();
        if (!rule_errors.empty()) { std::cout << wire::stringify(rule_errors) << std::endl; return 1; }
        const auto errors = links.cleanup("test");
        std::cout << wire::stringify(errors) << std::endl;
        return errors.empty() ? 0 : 1;
    }
    if (argc == 7 && std::string_view(argv[1]) == "--crash") {
        Netbox netbox(argv[2]);
        Fd directory(open(argv[3], O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        bool target = false;
        OwnedLinks links(directory.get(), getuid(), netbox, [&](const char* stage) {
            if (target && std::string_view(stage) == argv[5]) { kill(getpid(), SIGKILL); _exit(73); }
        });
        const std::string parent = std::string(argv[4]) + "p";
        if (std::string_view(argv[6]) == "vlan") links.bridge("test", parent);
        target = true;
        if (std::string_view(argv[6]) == "vlan") links.vlan("test", parent, argv[4], 321);
        else if (std::string_view(argv[6]) == "tap") links.tap("test", argv[4]);
        else links.bridge("test", argv[4]);
        links.remove("test", argv[4]);
        return 74;
    }
    if (argc != 4) return 64;
    executable = argv[1]; work = argv[2]; daemon_executable = argv[3];
    return run({{"bounded_tool_errors_and_literal_argv", adapter_failures}, {"real_bridge_vlan_tap_addresses", real_datapath},
        {"host_address_filtering", host_address_filtering}, {"uplink_snapshot_policy", uplink_snapshot_policy}, {"real_host_discovery", real_host_discovery},
        {"routing_table_policy", routing_table_policy}, {"real_dual_stack_policy_chains", real_policy_chains},
        {"ownership_cookie_preserves_kernel_routing", ownership_cookie_routing},
        {"policy_conflicts_replacement_and_races", policy_conflicts_and_races}, {"policy_journal_failures", policy_journal_failures},
        {"twelve_policy_sigkill_boundaries", policy_crash_recovery},
        {"conflicts_and_replaced_identity", collision_and_replacement}, {"dependencies_and_partial_cleanup", dependencies_and_partial_cleanup},
        {"setup_failure_and_journal_retry", failures_and_journal}, {"twenty_five_sigkill_boundaries", crash_recovery},
        {"exclusive_creation_and_index_deletion_races", lifecycle_races}, {"real_netbox_address_monitor", real_address_monitor},
        {"real_linux_topology", real_linux_topology}, {"linux_topology_failure_and_recovery", linux_topology_failure_and_recovery},
        {"linux_topology_sigkill_boundaries", linux_topology_crash_recovery}, {"link_inventory_rejects_stale_backup", link_inventory_rejects_stale_backup},
        {"actual_daemon_linux_topology_recovery", daemon_linux_topology_recovery}});
}
