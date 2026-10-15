// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "network/links.h"
#include "common/identity.h"
#include "services/network_host.h"
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <fstream>
#include <signal.h>
#include <sys/stat.h>

using namespace droidvm;
using namespace droidvm::network;
using namespace droidvm::test;
namespace {
std::string executable, work;
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
        check(links.cleanup("test").empty(), "cleanup test-owned links");
        check(links.inventory()["links"].empty(), "no unresolved resource records");
        for (const char* file : {"network-links.json", "network-links.json.bak", "network-links.json.corrupt"})
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
void real_datapath() {
    Case test;
    OwnedLinks links(test.directory.get(), getuid(), test.netbox);
    const auto per = OwnedLinks::vlan_device(test.name, 123), leg = OwnedLinks::vlan_leg(test.name, 123), tap = test.name + "t";
    links.bridge("test", test.name);
    links.bridge("test", per);
    links.vlan("test", test.name, leg, 123);
    links.tap("test", tap);
    test.netbox.mac(test.name, "02:de:ad:12:34:56");
    test.netbox.stp(test.name, true);
    const auto stp = kernel_text(test.name, "bridge/stp_state");
    check(stp == "1" || stp == "2", "kernel STP enabled (kernel or userspace mode)");
    test.netbox.stp(test.name, false);
    check(kernel_text(test.name, "bridge/stp_state") == "0", "kernel STP disabled");
    test.netbox.master(leg, per);
    test.netbox.master(tap, per);
    for (const auto& name : {test.name, per, leg, tap}) test.netbox.state(name, true);
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
    for (const char* stage : {"intent_saved", "link_created", "alias_written", "link_owned", "link_deleted"}) {
        Case test;
        ChildOptions options;
        options.argv = {"/proc/self/exe", "--crash", executable, test.path, test.name, stage};
        auto result = Child(options).communicate({}, 10s);
        check(result.exit_code == 73, "child reached abrupt-exit boundary");
        OwnedLinks restart(test.directory.get(), getuid(), test.netbox);
        auto failures = restart.cleanup("test");
        if (std::string_view(stage) == "link_created") {
            check(failures.size() == 1 && exists(test.name), "untagged ambiguous creation not deleted");
            // Fixture provenance proves this exact isolated name was created
            // by our child; the production service deliberately cannot infer it.
            test.netbox.delete_link(test.name);
            check(restart.cleanup("test").empty(), "manual resolution clears ambiguous intent");
        } else check(failures.empty() && !exists(test.name), "durable identity cleanup across crash");
        test.finish();
    }
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
        const auto errors = links.cleanup("test");
        std::cout << wire::stringify(errors) << std::endl;
        return errors.empty() ? 0 : 1;
    }
    if (argc == 6 && std::string_view(argv[1]) == "--crash") {
        Netbox netbox(argv[2]);
        Fd directory(open(argv[3], O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        OwnedLinks links(directory.get(), getuid(), netbox, [&](const char* stage) {
            if (std::string_view(stage) == argv[5]) _exit(73);
        });
        links.bridge("test", argv[4]);
        links.remove("test", argv[4]);
        return 74;
    }
    if (argc != 3) return 64;
    executable = argv[1]; work = argv[2];
    return run({{"bounded_tool_errors_and_literal_argv", adapter_failures}, {"real_bridge_vlan_tap_addresses", real_datapath},
        {"conflicts_and_replaced_identity", collision_and_replacement}, {"dependencies_and_partial_cleanup", dependencies_and_partial_cleanup},
        {"setup_failure_and_journal_retry", failures_and_journal}, {"five_abrupt_exit_boundaries", crash_recovery}});
}
