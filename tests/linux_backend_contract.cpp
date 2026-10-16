// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_backend_contract.h"
#include "contracts.h"
#include <unistd.h>
#include "dhcp_client.h"
#include "network/firewall.h"
#include "network/linux_bridge.h"
#include "services/network.h"
#include "services/network_config.h"
#include "store/network_config.h"
#include "runtime/child.h"
#include "common/identity.h"
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>

namespace droidvm::test {
using namespace droidvm::network;
namespace {
std::string netbox_path, work, daemon_path;
std::string binary(const char* name) { return netbox_path.substr(0, netbox_path.rfind('/') + 1) + name; }
Json::Value network_config(const std::string& bridge, bool auto_up = false) {
    auto value = wire::parse(R"({"schema":2,"name":"linux backend","bridge_type":"linux","l3":{"vlans":[{"vlan_id":0,
        "ipv4":{"cidr":"198.18.210.1/24","snat":true,"dhcp":{"enabled":true,"offset_start":10,"offset_end":20}},
        "ipv6":{"cidr":"fd91:fe21:210::1/64"}}]}})");
    value["id"] = random_id(true); value["name"] = "linux backend " + bridge; value["bridge_name"] = bridge; value["auto_up"] = auto_up;
    return value;
}
bool released(const Json::Value& inventory) {
    for (const auto& name : inventory.getMemberNames())
        if (inventory[name].isArray() && !inventory[name].empty()) return false;
    return true;
}
bool exists(const Netbox& netbox, const std::string& name) {
    for (const auto& row : netbox.links()) if (row["ifname"] == name) return true;
    return false;
}
Fd fixture_directory(const std::string& path) {
    check(mkdir(path.c_str(), 0700) == 0, "create Linux backend fixture");
    Fd fd(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    check(fd.get() >= 0, "open Linux backend fixture"); return fd;
}
void remove_files(const std::string& path) {
    DIR* dir = opendir(path.c_str()); check(dir, "open fixture for cleanup");
    std::vector<std::string> names;
    while (const auto* entry = readdir(dir)) if (entry->d_name[0] != '.') names.push_back(entry->d_name);
    closedir(dir);
    for (const auto& name : names) check(unlink((path + "/" + name).c_str()) == 0, "remove fixture journal");
    check(rmdir(path.c_str()) == 0, "fixture contains only journals");
}
// Transient TAP: closing the descriptor deletes it. It is a foreign
// dependency of the bridge, exactly like a VM port the backend does not own.
Fd client_tap(const Netbox& netbox, const std::string& name, const std::string& bridge) {
    Fd tap(open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK));
    ifreq request{}; request.ifr_flags = IFF_TAP | IFF_NO_PI;
    std::copy(name.begin(), name.end(), request.ifr_name);
    check(tap.get() >= 0 && ioctl(tap.get(), TUNSETIFF, &request) == 0, "create transient DHCP client TAP");
    netbox.master(name, bridge); netbox.state(name, true);
    return tap;
}
std::string acquire(int tap) {
    const auto deadline = std::chrono::steady_clock::now() + 15s;
    for (;;) {
        try { return acquire_dhcp4(tap); }
        catch (const std::exception&) { if (std::chrono::steady_clock::now() > deadline) throw; }
    }
}
struct Fixture {
    std::string path, dhcp;
    Fd directory;
    Netbox netbox{netbox_path};
    Iptables iptables;
    OwnedFirewall firewall;
    OwnedLinks links;
    OwnedRules rules;
    OwnedRoutes routes;
    SwitchRuntime runtime;
    LinuxFirewall coordinator;
    NetworkConfigService configs;
    explicit Fixture(const std::string& name, std::string helper = binary("bridgedhcp"))
        : path(work + "/" + name), dhcp(std::move(helper)), directory(fixture_directory(path)),
          firewall(directory.get(), getuid(), iptables), links(directory.get(), getuid(), netbox),
          rules(directory.get(), getuid(), links), routes(directory.get(), getuid(), links),
          runtime(directory.get(), getuid()), coordinator(firewall), configs(directory.get(), getuid()) {}
    NetworkService::Factory factory() {
        return [this](const Json::Value&) -> std::unique_ptr<Backend> {
            return std::make_unique<LinuxBridge>(LinuxBridge::Resources{
                netbox, links, rules, routes, coordinator, runtime, dhcp, directory.get()});
        };
    }
    bool idle() const {
        return released(links.inventory()) && released(firewall.inventory()) && released(runtime.inventory()) &&
            released(rules.inventory()) && released(routes.inventory());
    }
    void finish() {
        check(idle(), "Linux backend released links, routing, firewall and helpers");
        coordinator.stop(); remove_files(path);
    }
};
void rejections_and_rollback() {
    {
        Fixture fixture("lb-reject");
        NetworkService service(fixture.configs, fixture.factory());
        auto l2 = network_config("lbr" + random_id(false).substr(0, 8));
        l2["uplink_mode"] = "l2"; l2["l2"]["uplink"] = "Ethernet";
        const auto l2_id = fixture.configs.create(admin, l2);
        error(ErrorCode::unavailable, [&] { service.start(admin, l2_id); });
        auto pd = network_config("lbp" + random_id(false).substr(0, 8));
        pd["l3"]["vlans"][0]["ipv6"] = wire::parse(R"({"source":"dhcp_pd","cidr":"fd91:fe21:211::1/64","pd":{"uplink":"unresolved"}})");
        const auto pd_id = fixture.configs.create(admin, pd);
        error(ErrorCode::unavailable, [&] { service.start(admin, pd_id); });
        check(service.get(admin, l2_id).state == NetworkState::stopped && service.get(admin, pd_id).state == NetworkState::stopped &&
            fixture.idle(), "unimplemented L2 uplinks and PD ownership are rejected before kernel changes");
        check(service.shutdown().empty(), "rejection fixture shutdown");
        fixture.finish();
    }
    Fixture fixture("lb-rollback", binary("absent-bridgedhcp"));
    NetworkService service(fixture.configs, fixture.factory());
    const auto bridge = "lbx" + random_id(false).substr(0, 8);
    const auto id = fixture.configs.create(admin, network_config(bridge));
    bool failed = false;
    try { service.start(admin, id); } catch (const ServiceError&) { failed = true; }
    check(failed && service.get(admin, id).state == NetworkState::stopped && !exists(fixture.netbox, bridge) && fixture.idle(),
        "late helper failure rolls back topology, routing and firewall");
    check(service.shutdown().empty(), "rollback fixture shutdown");
    fixture.finish();
}
pid_t helper_pid(const std::string& prefix) {
    DIR* dir = opendir("/proc"); check(dir, "open process table");
    pid_t result = -1;
    while (const auto* entry = readdir(dir)) {
        if (entry->d_name[0] < '1' || entry->d_name[0] > '9') continue;
        std::ifstream file(std::string("/proc/") + entry->d_name + "/cmdline");
        std::string text((std::istreambuf_iterator<char>(file)), {});
        std::vector<std::string> args;
        for (size_t at = 0; at < text.size();) { const auto end = text.find('\0', at); args.push_back(text.substr(at, end - at)); at = end == std::string::npos ? text.size() : end + 1; }
        if (args.size() == 3 && args[0] == binary("bridgedhcp") && args[2].starts_with(prefix)) { result = std::stoi(entry->d_name); break; }
    }
    closedir(dir); return result;
}
void service_lifecycle() {
    Fixture fixture("lb-service");
    auto now = NetworkService::Clock::now();
    NetworkService service(fixture.configs, fixture.factory(), [&] { return now; });
    const auto bridge = "lbs" + random_id(false).substr(0, 8);
    const auto id = fixture.configs.create(admin, network_config(bridge));
    auto view = service.start(admin, id);
    check(view.state == NetworkState::running && view.tools[0]["key"] == "bridgedhcp" && view.tools[0]["running"] == true &&
        exists(fixture.netbox, bridge) && !released(fixture.firewall.inventory()), "Linux L3 network reaches RUNNING with helper and firewall");
    check(!service.tool_log(admin, id, "bridgedhcp").isNull(), "bridgedhcp log is exposed");
    auto tap = client_tap(fixture.netbox, bridge + "c", bridge);
    const auto ip = acquire(tap.get());
    check(ip.starts_with("198.18.210."), "real DHCPv4 lease through native Linux backend");
    now += 6s;
    check(service.reconcile(admin, id).state == NetworkState::running, "periodic refresh verifies topology, routing and firewall");
    const auto generation = view.tools[0]["generation"];
    const auto pid = helper_pid("/proc/" + std::to_string(getpid()) + "/fd/");
    check(pid > 0 && kill(pid, SIGKILL) == 0, "kill backend DHCP helper");
    for (int i = 0; i < 100; ++i) {
        now += 6s; view = service.reconcile(admin, id);
        if (view.state == NetworkState::running && view.tools[0]["generation"] != generation) break;
        std::this_thread::sleep_for(50ms);
    }
    check(view.state == NetworkState::running && view.tools[0]["generation"] != generation && exists(fixture.netbox, bridge),
        "helper death recovers by restarting only bridgedhcp");
    check(acquire(tap.get()) == ip, "lease survives helper SIGKILL recovery");
    fixture.netbox.delete_link(bridge);
    now += 6s;
    view = service.reconcile(admin, id);
    check(view.state == NetworkState::failed, "missing owned bridge is detected by refresh");
    for (int i = 0; i < 20 && view.state != NetworkState::running; ++i) {
        now += 6s; view = service.reconcile(admin, id);
    }
    if (view.state != NetworkState::running) std::cerr << "rebuild: " << view.error << std::endl;
    check(view.state == NetworkState::running && exists(fixture.netbox, bridge), "topology loss rebuilds the network");
    fixture.netbox.master(bridge + "c", bridge); fixture.netbox.state(bridge + "c", true);
    check(acquire(tap.get()) == ip, "rebuilt network retains persisted DHCP lease");
    error(ErrorCode::io_error, [&] { service.stop(admin, id); });
    check(service.get(admin, id).state == NetworkState::failed && exists(fixture.netbox, bridge) && !released(fixture.firewall.inventory()),
        "foreign port blocks link cleanup and keeps firewall guards");
    tap = Fd();
    check(service.stop(admin, id).state == NetworkState::stopped && !exists(fixture.netbox, bridge),
        "quiesced retry releases the network");
    check(service.shutdown().empty(), "service fixture shutdown");
    fixture.finish();
}
void actual_daemon() {
    const auto path = work + "/lb-daemon";
    for (const char* name : {"", "/bin", "/files"}) check(mkdir((path + name).c_str(), 0700) == 0, "create daemon fixture directories");
    for (const char* name : {"netbox", "bridgedhcp"})
        check(symlink(binary(name).c_str(), (path + "/bin/" + name).c_str()) == 0, "reuse installed network tools");
    { std::ofstream apk(path + "/fixture.apk"); apk << "isolated Linux backend fixture"; }
    const auto bridge = "lbd" + random_id(false).substr(0, 8);
    {
        Fd files(open((path + "/files").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        NetworkConfigService(files.get(), getuid()).create(admin, network_config(bridge, true));
    }
    Netbox netbox(netbox_path);
    ChildOptions launch; launch.argv = {daemon_path, "--data-dir", path, "--apk", path + "/fixture.apk"};
    unsigned previous = 0;
    // A killed daemon leaves its bridge until the next startup recovers it;
    // wait for the replacement link rather than the stale one.
    auto ready = [&](Child& daemon, Fd& tap) {
        const auto deadline = std::chrono::steady_clock::now() + 15s;
        auto created = [&] { const auto index = if_nametoindex(bridge.c_str()); return index && index != previous; };
        while (!created() && !daemon.poll_exit() && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(20ms);
        previous = if_nametoindex(bridge.c_str());
        if (!exists(netbox, bridge)) {
            daemon.signal(SIGTERM); std::cerr << "daemon: " << daemon.communicate({}, 5s).error << std::endl;
            std::ifstream log(path + "/cache/daemon.log"); std::cerr << log.rdbuf() << std::endl;
        }
        check(exists(netbox, bridge), "daemon autostarts native Linux network");
        tap = client_tap(netbox, bridge + "c", bridge);
        return acquire(tap.get());
    };
    std::string ip;
    {
        Child daemon(launch); Fd tap;
        ip = ready(daemon, tap);
        check(ip.starts_with("198.18.210."), "production factory serves real DHCP");
        check(daemon.signal(SIGKILL) && daemon.communicate({}, 5s).exit_code == -SIGKILL, "kill daemon with live Linux network");
        const auto rejected = Child(launch).communicate({}, 20s);
        check(rejected.exit_code == 1 && rejected.error.find("Network link recovery incomplete") != std::string::npos,
            "startup refuses readiness while a foreign port is still attached");
        Fd run(open((path + "/run").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        Iptables iptables; OwnedFirewall firewall(run.get(), getuid(), iptables);
        check(!released(firewall.inventory()), "firewall guards survive until links are recovered");
    }
    {
        Child daemon(launch); Fd tap;
        check(ready(daemon, tap) == ip, "recovered daemon restarts network and keeps lease");
        tap = Fd();
        check(daemon.signal(SIGTERM) && daemon.communicate({}, 10s).exit_code == 128 + SIGTERM, "daemon stops Linux network on SIGTERM");
    }
    Fd run(open((path + "/run").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    Iptables iptables; OwnedFirewall firewall(run.get(), getuid(), iptables);
    OwnedLinks links(run.get(), getuid(), netbox); SwitchRuntime runtime(run.get(), getuid());
    check(!exists(netbox, bridge) && released(firewall.inventory()) && released(links.inventory()) && released(runtime.inventory()),
        "daemon shutdown releases every Linux network resource");
    for (const char* name : {"/run", "/cache", "/files", "/bin"}) remove_files(path + name);
    check(unlink((path + "/fixture.apk").c_str()) == 0 && rmdir(path.c_str()) == 0, "daemon fixture reclaimed");
}
}
int linux_backend_namespace_child(const std::string& netbox, const std::string& directory, const std::string& daemon) {
    struct stat before{}, after{};
    if (stat("/proc/self/ns/net", &before) != 0 || unshare(CLONE_NEWNET | CLONE_NEWNS) != 0 ||
        stat("/proc/self/ns/net", &after) != 0 || before.st_ino == after.st_ino) return 70;
    // OwnedLinks resolves identities through sysfs, which shows the network
    // namespace of its mounter. Remount it privately for this fixture only.
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0 ||
        mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) != 0) return 71;
    netbox_path = netbox; work = directory; daemon_path = daemon;
    Netbox(netbox).state("lo", true); // the daemon listens on loopback
    return run({{"linux_backend_rejections_and_rollback", rejections_and_rollback},
        {"linux_backend_service_dhcp_recovery_and_quiesce", service_lifecycle},
        {"actual_daemon_linux_network_lifecycle", actual_daemon}});
}
}
