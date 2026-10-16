// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_backend_contract.h"
#include "contracts.h"
#include <unistd.h>
#include "dhcp_client.h"
#include "network/firewall.h"
#include "network/linux_bridge.h"
#include "network/pd_ownership.h"
#include "network/ports.h"
#include "network/host_discovery.h"
#include "network/host_watch.h"
#include "network/netlink.h"
#include <linux/if_addr.h>
#include "services/tasks.h"
#include <set>
#include <linux/if_packet.h>
#include <net/ethernet.h>
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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <future>
#include <atomic>

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
// Plain fixtures keep every journal in one new directory. A data layout uses
// the daemon's existing run/ and files/ split so droidvmd can recover it.
struct Fixture {
    std::string path, dhcp;
    bool layout;
    Fd run, files;
    Netbox netbox{netbox_path};
    Iptables iptables;
    OwnedFirewall firewall;
    OwnedLinks links;
    OwnedRules rules;
    OwnedRoutes routes;
    SwitchRuntime runtime;
    PdOwnership pd;
    OwnedPorts ports;
    PbridgeOwnership pbridge;
    LinuxFirewall coordinator;
    NetworkConfigService configs;
    explicit Fixture(const std::string& name, std::string helper = binary("bridgedhcp"), bool data_layout = false)
        : path(data_layout ? name : work + "/" + name), dhcp(std::move(helper)), layout(data_layout),
          run(data_layout ? Fd(open((path + "/run").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)) : fixture_directory(path)),
          files(data_layout ? Fd(open((path + "/files").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)) : Fd(fcntl(run.get(), F_DUPFD_CLOEXEC, 3))),
          firewall(run.get(), getuid(), iptables), links(run.get(), getuid(), netbox),
          rules(run.get(), getuid(), links), routes(run.get(), getuid(), links),
          runtime(run.get(), getuid()), pd(run.get(), getuid()), ports(run.get(), getuid(), netbox), pbridge(run.get(), getuid(), netbox), coordinator(firewall), configs(files.get(), getuid()) {}
    NetworkService::Factory factory() {
        return [this](const Json::Value&) -> std::unique_ptr<Backend> {
            return std::make_unique<LinuxBridge>(LinuxBridge::Resources{
                netbox, links, rules, routes, coordinator, pd, ports, pbridge, runtime, dhcp, binary("pbridge"), files.get()});
        };
    }
    bool idle() const {
        return released(links.inventory()) && released(firewall.inventory()) && released(runtime.inventory()) &&
            released(rules.inventory()) && released(routes.inventory()) && released(pd.inventory()) && released(ports.inventory()) && released(pbridge.inventory());
    }
    void finish() {
        check(idle(), "Linux backend released links, routing, firewall, PD and helpers");
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
        check(service.get(admin, l2_id).state == NetworkState::stopped && fixture.idle(),
            "unimplemented L2 uplinks are rejected before kernel changes");
        auto pd = network_config("lbp" + random_id(false).substr(0, 8));
        pd["l3"]["vlans"][0]["ipv6"] = wire::parse(R"({"source":"dhcp_pd","cidr":"fd91:fe21:211::1/64","pd":{"uplink":"unresolved"}})");
        const auto pd_id = fixture.configs.create(admin, pd);
        check(service.start(admin, pd_id).state == NetworkState::running && released(fixture.pd.inventory()),
            "unresolved PD uplink starts without registering a delegation, as legacy did");
        check(service.stop(admin, pd_id).state == NetworkState::stopped, "unresolved PD network stops");
        check(service.shutdown().empty(), "rejection fixture shutdown");
        fixture.finish();
    }    Fixture fixture("lb-rollback", binary("absent-bridgedhcp"));
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
std::vector<pid_t> monitor_pids(const std::string& tool) {
    DIR* dir = opendir("/proc"); check(dir, "open process table");
    std::vector<pid_t> result;
    while (const auto* entry = readdir(dir)) {
        if (entry->d_name[0] < '1' || entry->d_name[0] > '9') continue;
        std::ifstream file(std::string("/proc/") + entry->d_name + "/cmdline");
        std::string text((std::istreambuf_iterator<char>(file)), {});
        if (text.starts_with(tool + std::string(1, '\0') + "monitor-addr" + std::string(1, '\0'))) result.push_back(std::stoi(entry->d_name));
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
        const auto monitors = monitor_pids(path + "/bin/netbox");
        check(monitors.size() == 1, "daemon runs one host address monitor");
        check(daemon.signal(SIGKILL) && daemon.communicate({}, 5s).exit_code == -SIGKILL, "kill daemon with live Linux network");
        check(kill(monitors[0], 0) == 0, "killed daemon orphaned its host address monitor");
        const auto rejected = Child(launch).communicate({}, 20s);
        check(rejected.exit_code == 1 && rejected.error.find("Network link recovery incomplete") != std::string::npos,
            "startup refuses readiness while a foreign port is still attached");
        check(monitor_pids(path + "/bin/netbox").empty(), "startup reclaims the orphaned monitor by its helper identity");
        Fd run(open((path + "/run").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        Iptables iptables; OwnedFirewall firewall(run.get(), getuid(), iptables);
        check(!released(firewall.inventory()), "firewall guards survive until links are recovered");
    }
    {
        Child daemon(launch); Fd tap;
        check(ready(daemon, tap) == ip, "recovered daemon restarts network and keeps lease");
        tap = Fd();
        check(daemon.signal(SIGTERM) && daemon.communicate({}, 10s).exit_code == 128 + SIGTERM, "daemon stops Linux network on SIGTERM");
        check(monitor_pids(path + "/bin/netbox").empty(), "daemon shutdown stops its host address monitor");
    }
    Fd run(open((path + "/run").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    Iptables iptables; OwnedFirewall firewall(run.get(), getuid(), iptables);
    OwnedLinks links(run.get(), getuid(), netbox); SwitchRuntime runtime(run.get(), getuid());
    check(!exists(netbox, bridge) && released(firewall.inventory()) && released(links.inventory()) && released(runtime.inventory()),
        "daemon shutdown releases every Linux network resource");
    for (const char* name : {"/run", "/cache", "/files", "/bin"}) remove_files(path + name);
    check(unlink((path + "/fixture.apk").c_str()) == 0 && rmdir(path.c_str()) == 0, "daemon fixture reclaimed");
}
std::string read_text(const std::string& path) {
    std::ifstream file(path); std::string value; std::getline(file, value); return value;
}
void write_text(const std::string& path, const std::string& value) {
    std::ofstream file(path); file << value << "\n"; check(file.good(), "write fixture sysctl");
}
void ip(std::vector<std::string> args) {
    args.insert(args.begin(), "/system/bin/ip");
    ChildOptions options; options.argv = std::move(args);
    const auto result = Child(options).communicate({}, 5s);
    if (result.exit_code != 0) throw std::runtime_error("ip failed: " + result.error);
}
std::string uplink_sysctl(const std::string& uplink, const char* key) { return read_text("/proc/sys/net/ipv6/conf/" + uplink + "/" + key); }
// Minimal RFC 8415 IA_PD server on the far end of a veth pair. Its end lives
// in a network namespace private to the server thread, so replies cross the
// veth instead of being short-circuited to a local link-local address.
class PdServer {
public:
    std::string uplink, peer;
    explicit PdServer(const std::string& name) : uplink(name + "u"), peer(name + "s") {
        ip({"link", "add", uplink, "type", "veth", "peer", "name", peer});
        auto tid = tid_.get_future();
        thread_ = std::thread([this] { serve(); });
        try {
            const auto id = tid.get();
            ip({"link", "set", peer, "netns", std::to_string(id)});
            write_text("/proc/sys/net/ipv6/conf/" + uplink + "/accept_dad", "0");
        } catch (...) { stop_ = true; release(); thread_.join(); throw; }
        release();
    }
    ~PdServer() { stop_ = true; release(); if (thread_.joinable()) thread_.join(); }
    int replies() const { return replies_; }
    std::string error() const { std::lock_guard lock(mutex_); return error_; }
private:
    std::promise<pid_t> tid_;
    std::promise<void> moved_;
    bool released_ = false;
    std::atomic<bool> stop_{false};
    std::atomic<int> replies_{0};
    mutable std::mutex mutex_;
    std::string error_;
    std::thread thread_;
    void release() { if (!released_) { released_ = true; moved_.set_value(); } }
    void serve() {
        auto moved = moved_.get_future();
        if (unshare(CLONE_NEWNET) != 0) { tid_.set_exception(std::make_exception_ptr(std::runtime_error("PD server netns"))); return; }
        tid_.set_value(static_cast<pid_t>(gettid()));
        moved.wait();
        if (stop_) return;
        try {
            write_text("/proc/sys/net/ipv6/conf/" + peer + "/accept_dad", "0");
            Fd socket_fd(socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0));
            ifreq request{}; std::copy(peer.begin(), peer.end(), request.ifr_name);
            check(socket_fd.get() >= 0 && ioctl(socket_fd.get(), SIOCGIFFLAGS, &request) == 0, "PD server link flags");
            request.ifr_flags |= IFF_UP;
            check(ioctl(socket_fd.get(), SIOCSIFFLAGS, &request) == 0, "PD server link up");
            check(setsockopt(socket_fd.get(), SOL_SOCKET, SO_BINDTODEVICE, peer.c_str(), peer.size()) == 0, "PD server device");
            sockaddr_in6 local{}; local.sin6_family = AF_INET6; local.sin6_port = htons(547);
            check(bind(socket_fd.get(), reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0, "PD server bind");
            ipv6_mreq group{}; inet_pton(AF_INET6, "ff02::1:2", &group.ipv6mr_multiaddr);
            group.ipv6mr_interface = if_nametoindex(peer.c_str());
            check(setsockopt(socket_fd.get(), IPPROTO_IPV6, IPV6_JOIN_GROUP, &group, sizeof(group)) == 0, "PD server group");
            while (!stop_) {
                pollfd fd{socket_fd.get(), POLLIN, 0};
                if (poll(&fd, 1, 100) <= 0) continue;
                uint8_t in[1500]; sockaddr_in6 from{}; socklen_t size = sizeof(from);
                const auto n = recvfrom(socket_fd.get(), in, sizeof(in), 0, reinterpret_cast<sockaddr*>(&from), &size);
                if (n < 4) continue;
                // SOLICIT -> ADVERTISE; REQUEST/RENEW/REBIND/RELEASE -> REPLY
                const uint8_t type = in[0] == 1 ? 2 : (in[0] == 3 || in[0] == 5 || in[0] == 6 || in[0] == 8) ? 7 : 0;
                if (!type) continue;
                std::vector<uint8_t> client, out{type, in[1], in[2], in[3]};
                std::array<uint8_t, 4> iaid{};
                for (ssize_t at = 4; at + 4 <= n;) {
                    const uint16_t code = (in[at] << 8) | in[at + 1], length = (in[at + 2] << 8) | in[at + 3];
                    if (at + 4 + length > n) break;
                    if (code == 1) client.assign(in + at + 4, in + at + 4 + length);
                    if (code == 25 && length >= 4) std::copy_n(in + at + 4, 4, iaid.begin());
                    at += 4 + length;
                }
                auto option = [&](uint16_t code, const std::vector<uint8_t>& body) {
                    out.insert(out.end(), {uint8_t(code >> 8), uint8_t(code), uint8_t(body.size() >> 8), uint8_t(body.size())});
                    out.insert(out.end(), body.begin(), body.end());
                };
                auto u32 = [](std::vector<uint8_t>& body, uint32_t value) {
                    body.insert(body.end(), {uint8_t(value >> 24), uint8_t(value >> 16), uint8_t(value >> 8), uint8_t(value)});
                };
                option(1, client);
                option(2, {0, 3, 0, 1, 2, 0, 0, 0, 0xaa, 1});
                if (in[0] != 8) {
                    std::vector<uint8_t> prefix; u32(prefix, 3000); u32(prefix, 4000); prefix.push_back(64);
                    std::array<uint8_t, 16> bytes{}; inet_pton(AF_INET6, "2001:db8:aa:1::", bytes.data());
                    prefix.insert(prefix.end(), bytes.begin(), bytes.end());
                    std::vector<uint8_t> ia(iaid.begin(), iaid.end()); u32(ia, 1000); u32(ia, 2000);
                    ia.insert(ia.end(), {0, 26, 0, uint8_t(prefix.size())}); ia.insert(ia.end(), prefix.begin(), prefix.end());
                    option(25, ia);
                }
                if (sendto(socket_fd.get(), out.data(), out.size(), 0, reinterpret_cast<sockaddr*>(&from), size) == static_cast<ssize_t>(out.size()))
                    ++replies_;
            }
        } catch (const std::exception& error) { std::lock_guard lock(mutex_); error_ = error.what(); }
    }
};
// Earlier global forwarding demand propagates to new links; start from the
// typical phone uplink state the helper changes.
void reset_uplink(const std::string& uplink) {
    write_text("/proc/sys/net/ipv6/conf/" + uplink + "/accept_ra", "1");
    write_text("/proc/sys/net/ipv6/conf/" + uplink + "/forwarding", "0");
    check(uplink_sysctl(uplink, "accept_ra") == "1" && uplink_sysctl(uplink, "forwarding") == "0", "uplink starts as a host interface");
}
constexpr const char* pd_prefix = "2001:db8:aa:1::/64";
Json::Value pd_network(const std::string& bridge, const std::string& uplink) {
    auto config = network_config(bridge);
    config["l3"]["vlans"][0]["ipv6"] = wire::parse(R"({"source":"dhcp_pd","pd":{}})");
    config["l3"]["vlans"][0]["ipv6"]["pd"]["uplink"] = uplink;
    return config;
}
uint32_t pd_table(NetworkConfigService& configs, const std::string& id) {
    return configs.get(admin, id)["l3"]["vlans"][0]["ipv6"]["pd"]["route_table"].asUInt();
}
// Rules from/to the prefix plus its subnet route, and the daemon applied the
// helper's delegation to the firewall plan.
bool delegated(const Fixture& fixture, uint32_t table) {
    return pd_table_users(table) >= 3 && wire::stringify(fixture.firewall.inventory()).find(pd_prefix) != std::string::npos;
}
void wait_delegated(Fixture& fixture, NetworkService& service, const std::string& id,
                    NetworkService::Clock::time_point& now, const PdServer* server) {
    const auto table = pd_table(fixture.configs, id);
    const auto deadline = std::chrono::steady_clock::now() + 20s;
    while (!delegated(fixture, table) && std::chrono::steady_clock::now() < deadline) {
        now += 6s; service.reconcile(admin, id); std::this_thread::sleep_for(100ms);
    }
    if (!delegated(fixture, table))
        std::cerr << "PD: replies=" << (server ? server->replies() : -1) << " server=" << (server ? server->error() : "")
                  << " users=" << pd_table_users(table) << " view=" << service.get(admin, id).error
                  << " state=" << network_state_name(service.get(admin, id).state)
                  << " firewall=" << wire::stringify(fixture.firewall.inventory()).substr(0, 6000) << std::endl;
    check(delegated(fixture, table), "real DHCPv6-PD delegation reaches helper routing and daemon firewall");
}
void pd_delegation_ownership() {
    PdServer server("pd" + random_id(false).substr(0, 6));
    Fixture fixture("lb-pd");
    fixture.netbox.state(server.uplink, true);
    reset_uplink(server.uplink);
    auto now = NetworkService::Clock::now();
    NetworkService service(fixture.configs, fixture.factory(), [&] { return now; });
    const auto id = fixture.configs.create(admin, pd_network("lbq" + random_id(false).substr(0, 8), server.uplink));
    check(service.start(admin, id).state == NetworkState::running, "PD network reaches RUNNING");
    const auto table = pd_table(fixture.configs, id);
    const auto entries = fixture.pd.inventory()["entries"];
    check(entries.size() == 1 && entries[0]["table"].asUInt() == table && entries[0]["uplink"] == server.uplink,
        "delegation registered durably before helper start");
    wait_delegated(fixture, service, id, now, &server);
    check(uplink_sysctl(server.uplink, "accept_ra") == "2" && uplink_sysctl(server.uplink, "forwarding") == "1", "helper relaxed uplink sysctls");
    for (const auto& row : fixture.routes.inventory()["routes"]) check(row["table"].asUInt() != table, "return routes never enter the helper PD table");
    const auto pid = helper_pid("/proc/" + std::to_string(getpid()) + "/fd/");
    check(pid > 0 && kill(pid, SIGKILL) == 0, "kill PD helper before it can clean up");
    std::this_thread::sleep_for(200ms);
    check(pd_table_users(table) >= 2, "killed helper left its PD rules behind");
    check(service.stop(admin, id).state == NetworkState::stopped, "network stops after helper death");
    check(!pd_table_users(table) && uplink_sysctl(server.uplink, "accept_ra") == "1" && uplink_sysctl(server.uplink, "forwarding") == "0",
        "daemon flushed PD rules/routes and restored uplink sysctls");
    check(service.shutdown().empty(), "PD fixture shutdown");
    fixture.finish();
}
// Two networks on one uplink: a clean helper stop restores the per-process
// original, so the daemon must reassert it for the remaining network.
void pd_shared_uplink_and_foreign_table() {
    const auto path = work + "/lb-pd-shared";
    for (const char* dir : {"", "/sys", "/sys/up0"}) check(mkdir((path + dir).c_str(), 0700) == 0, "create PD sysctl fixture");
    const auto key = [&](const char* name) { return path + "/sys/up0/" + name; };
    write_text(key("accept_ra"), "1"); write_text(key("forwarding"), "0");
    Fd directory(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    PdOwnership owner(directory.get(), getuid(), {}, path + "/sys");
    owner.acquire("net-a", 0, 50001, "up0");
    write_text(key("accept_ra"), "2"); write_text(key("forwarding"), "1"); // helper A
    owner.acquire("net-b", 0, 50002, "up0"); // helper B sees 2/1 and changes nothing
    error(ErrorCode::conflict, [&] { owner.acquire("net-c", 0, 50001, "up0"); });
    write_text(key("accept_ra"), "1"); write_text(key("forwarding"), "0"); // helper A clean stop
    owner.release("net-a");
    check(read_text(key("accept_ra")) == "2" && read_text(key("forwarding")) == "1", "remaining network gets uplink sysctls reasserted");
    write_text(key("accept_ra"), "0"); // administrator disables RA meanwhile
    owner.release("net-b");
    check(read_text(key("accept_ra")) == "0" && read_text(key("forwarding")) == "0", "last release restores only helper-owned values");
    check(released(owner.inventory()) && owner.inventory()["uplinks"].empty(), "shared uplink record retired");
    ip({"-6", "rule", "add", "from", "2001:db8:ff::/64", "table", "50003", "priority", "5000"});
    error(ErrorCode::conflict, [&] { owner.acquire("net-d", 0, 50003, "up0"); });
    check(pd_table_users(50003) == 1 && released(owner.inventory()), "foreign table user is never registered or flushed");
    ip({"-6", "rule", "del", "from", "2001:db8:ff::/64", "table", "50003", "priority", "5000"});
    remove_files(path + "/sys/up0"); remove_files(path + "/sys"); remove_files(path);
}
std::string master_of(const std::string& name) {
    char target[256];
    const auto length = readlink(("/sys/class/net/" + name + "/master").c_str(), target, sizeof(target) - 1);
    if (length <= 0) return {};
    const std::string path(target, static_cast<size_t>(length));
    return path.substr(path.rfind('/') + 1);
}
Json::Value l2_network(const std::string& bridge, const std::string& uplink, bool pseudo) {
    auto config = network_config(bridge);
    config["uplink_mode"] = "l2"; config["l2"]["uplink"] = uplink;
    if (!pseudo) config["l2"]["pseudo_bridge"] = false;
    return config;
}
// A broadcast frame injected into a guest-side TAP must leave on the uplink.
bool bridged(int tap, const std::string& peer, uint8_t sequence) {
    Fd raw(socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, htons(ETH_P_ALL)));
    sockaddr_ll address{}; address.sll_family = AF_PACKET; address.sll_protocol = htons(ETH_P_ALL);
    address.sll_ifindex = static_cast<int>(if_nametoindex(peer.c_str()));
    check(raw.get() >= 0 && bind(raw.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0, "capture on uplink peer");
    std::array<uint8_t, 60> frame{};
    std::fill_n(frame.begin(), 6, 0xff);
    const std::array<uint8_t, 6> source{2, 0, 0, 0x4c, 0x32, sequence};
    std::copy(source.begin(), source.end(), frame.begin() + 6);
    frame[12] = 0x88; frame[13] = 0xb5; // IEEE local experimental EtherType
    frame[14] = sequence;
    check(write(tap, frame.data(), frame.size()) == static_cast<ssize_t>(frame.size()), "inject guest broadcast");
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (std::chrono::steady_clock::now() < deadline) {
        pollfd fd{raw.get(), POLLIN, 0};
        if (poll(&fd, 1, 50) <= 0) continue;
        std::array<uint8_t, 2048> bytes{};
        const auto n = read(raw.get(), bytes.data(), bytes.size());
        if (n >= 15 && std::equal(source.begin(), source.end(), bytes.begin() + 6) && bytes[14] == sequence) return true;
    }
    return false;
}
void l2_direct_uplink() {
    const auto name = "l2" + random_id(false).substr(0, 6);
    const auto uplink = name + "u", peer = name + "s";
    ip({"link", "add", uplink, "type", "veth", "peer", "name", peer});
    Fixture fixture("lb-l2");
    fixture.netbox.state(uplink, true); fixture.netbox.state(peer, true);
    auto now = NetworkService::Clock::now();
    NetworkService service(fixture.configs, fixture.factory(), [&] { return now; });
    const auto bridge = "lbl" + random_id(false).substr(0, 8);
    const auto id = fixture.configs.create(admin, l2_network(bridge, uplink, false));
    const auto view = service.start(admin, id);
    check(view.state == NetworkState::running && view.tools.empty() && master_of(uplink) == bridge &&
        fixture.ports.inventory()["ports"].size() == 1 && !released(fixture.firewall.inventory()),
        "direct L2 enslaves the uplink with a durable port record and L2 firewall");
    auto tap = client_tap(fixture.netbox, bridge + "c", bridge);
    check(bridged(tap.get(), peer, 1), "guest frame crosses the bridge onto the uplink");
    fixture.netbox.nomaster(uplink);
    now += 6s;
    check(service.reconcile(admin, id).state == NetworkState::running && master_of(uplink) == bridge && bridged(tap.get(), peer, 2),
        "refresh reattaches an uplink that left the bridge");
    tap = Fd();
    check(service.stop(admin, id).state == NetworkState::stopped && master_of(uplink).empty() && !exists(fixture.netbox, bridge),
        "stop detaches the uplink before releasing the bridge");
    check(service.shutdown().empty(), "L2 fixture shutdown");
    fixture.finish();
    fixture.netbox.delete_link(uplink);
}
std::vector<uint8_t> mac_of(const std::string& link) {
    std::vector<uint8_t> result;
    const auto text = read_text("/sys/class/net/" + link + "/address");
    for (size_t at = 0; at + 2 <= text.size(); at += 3) result.push_back(static_cast<uint8_t>(std::stoul(text.substr(at, 2), nullptr, 16)));
    return result;
}
// Guest ARP announcement for 198.18.230.50 from a guest MAC behind the TAP.
void announce(int tap) {
    std::array<uint8_t, 42> frame{};
    const std::array<uint8_t, 6> guest{2, 0, 0, 0x4c, 0x33, 1};
    std::fill_n(frame.begin(), 6, 0xff); std::copy(guest.begin(), guest.end(), frame.begin() + 6);
    frame[12] = 8; frame[13] = 6;
    const std::array<uint8_t, 8> header{0, 1, 8, 0, 6, 4, 0, 2};
    std::copy(header.begin(), header.end(), frame.begin() + 14);
    std::copy(guest.begin(), guest.end(), frame.begin() + 22);
    const std::array<uint8_t, 4> ip{198, 18, 230, 50};
    std::copy(ip.begin(), ip.end(), frame.begin() + 28); std::copy(ip.begin(), ip.end(), frame.begin() + 38);
    check(write(tap, frame.data(), frame.size()) == static_cast<ssize_t>(frame.size()), "inject guest ARP announcement");
}
void pbridge_pseudo_uplink() {
    const auto name = "pb" + random_id(false).substr(0, 6);
    const auto uplink = name + "u", peer = name + "s";
    ip({"link", "add", uplink, "type", "veth", "peer", "name", peer});
    Fixture fixture("lb-pbridge");
    fixture.netbox.address(uplink, "198.18.230.1/24", true);
    fixture.netbox.state(uplink, true); fixture.netbox.state(peer, true);
    auto now = NetworkService::Clock::now();
    NetworkService service(fixture.configs, fixture.factory(), [&] { return now; });
    const auto bridge = "lbb" + random_id(false).substr(0, 8);
    const auto fwd0 = bridge.substr(0, 12) + "-pi", fwd1 = bridge.substr(0, 12) + "-pb";
    const auto id = fixture.configs.create(admin, l2_network(bridge, uplink, true));
    const auto view = service.start(admin, id);
    check(view.state == NetworkState::running && view.tools[0]["key"] == "pbridge" && view.tools[0]["running"] == true &&
        master_of(fwd1) == bridge && exists(fixture.netbox, fwd0) && master_of(uplink).empty() &&
        fixture.pbridge.inventory()["entries"].size() == 1, "pseudo L2 runs pbridge with a recorded per-network veth pair");
    auto tap = client_tap(fixture.netbox, bridge + "c", bridge);
    // Guest frames leave the uplink MAC-NATed to the uplink's own address,
    // and the learned guest IP is proxied on the uplink with the magic tag.
    Fd raw(socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, htons(ETH_P_ARP)));
    sockaddr_ll address{}; address.sll_family = AF_PACKET; address.sll_protocol = htons(ETH_P_ARP);
    address.sll_ifindex = static_cast<int>(if_nametoindex(peer.c_str()));
    check(raw.get() >= 0 && bind(raw.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0, "capture ARP on uplink peer");
    const auto host = mac_of(uplink);
    bool natted = false;
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    while ((!natted || fixture.netbox.addresses(uplink, pbridge_offload_metric).empty()) && std::chrono::steady_clock::now() < deadline) {
        announce(tap.get());
        for (int i = 0; i < 10 && !natted; ++i) {
            pollfd fd{raw.get(), POLLIN, 0};
            if (poll(&fd, 1, 50) <= 0) continue;
            std::array<uint8_t, 2048> bytes{};
            const auto n = read(raw.get(), bytes.data(), bytes.size());
            natted = n >= 42 && std::equal(host.begin(), host.end(), bytes.begin() + 6) && bytes[28] == 198 && bytes[31] == 50;
        }
    }
    const auto proxies = fixture.netbox.addresses(uplink, pbridge_offload_metric);
    if (!natted || proxies.empty()) std::cerr << "pbridge: " << wire::stringify(service.tool_log(admin, id, "pbridge")) << std::endl;
    check(natted, "guest frame leaves the uplink rewritten to the host MAC");
    check(proxies.size() == 1 && proxies[0]["local"] == "198.18.230.50", "learned guest IP proxied on the uplink with the magic metric");
    bool rule = false;
    for (const auto& row : fixture.netbox.rules(false))
        rule = rule || (row["iif"] == "lo" && row["table"].asUInt() == PbridgeOwnership::vmroute_table && row["priority"].asUInt() == PbridgeOwnership::vmroute_priority);
    check(rule, "pbridge installed its vmroute rule");
    const auto pid = [&] {
        DIR* dir = opendir("/proc"); pid_t result = -1;
        while (const auto* entry = readdir(dir)) {
            if (entry->d_name[0] < '1' || entry->d_name[0] > '9') continue;
            std::ifstream file(std::string("/proc/") + entry->d_name + "/cmdline");
            std::string text((std::istreambuf_iterator<char>(file)), {});
            if (text.starts_with(binary("pbridge") + std::string(1, '\0')) && text.find(fwd0) != std::string::npos) { result = std::stoi(entry->d_name); break; }
        }
        closedir(dir); return result;
    }();
    check(pid > 0 && kill(pid, SIGKILL) == 0, "kill pbridge before its teardown");
    std::this_thread::sleep_for(300ms);
    check(master_of(fwd1) == bridge && !fixture.netbox.addresses(uplink, pbridge_offload_metric).empty(), "killed pbridge left veth and proxies");
    tap = Fd();
    check(service.stop(admin, id).state == NetworkState::stopped, "pseudo L2 network stops after helper death");
    rule = false;
    for (const auto& row : fixture.netbox.rules(false))
        rule = rule || (row["iif"] == "lo" && row["table"].asUInt() == PbridgeOwnership::vmroute_table && row["priority"].asUInt() == PbridgeOwnership::vmroute_priority);
    check(!exists(fixture.netbox, fwd0) && !exists(fixture.netbox, fwd1) && !exists(fixture.netbox, bridge) && !rule &&
        fixture.netbox.addresses(uplink, pbridge_offload_metric).empty() && fixture.netbox.addresses(uplink).size() >= 1,
        "daemon removed veth, proxies and rules while keeping the uplink's own address");
    check(service.shutdown().empty(), "pbridge fixture shutdown");
    fixture.finish();
    fixture.netbox.delete_link(uplink);
}
void l2_daemon_recovery(bool pseudo) {
    const auto name = (pseudo ? "l4" : "l3") + random_id(false).substr(0, 6);
    const auto uplink = name + "u";
    ip({"link", "add", uplink, "type", "veth", "peer", "name", name + "s"});
    Netbox netbox(netbox_path); netbox.state(uplink, true);
    const auto path = work + "/lb-l2-daemon";
    for (const char* dir : {"", "/bin", "/files", "/run"}) check(mkdir((path + dir).c_str(), 0700) == 0, "create L2 daemon fixture");
    for (const char* tool : {"netbox", "bridgedhcp"})
        check(symlink(binary(tool).c_str(), (path + "/bin/" + tool).c_str()) == 0, "reuse installed network tools");
    { std::ofstream apk(path + "/fixture.apk"); apk << "isolated L2 recovery fixture"; }
    const auto bridge = "lbn" + random_id(false).substr(0, 8);
    {
        Fd files(open((path + "/files").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        NetworkConfigService(files.get(), getuid()).create(admin, l2_network(bridge, uplink, pseudo));
    }
    ChildOptions crash; crash.argv = {"/proc/self/exe", "--linux-backend-pd-crash", netbox_path, path};
    const auto crashed = Child(crash).communicate({}, 20s);
    if (crashed.exit_code != -SIGKILL) std::cerr << "L2 crash fixture: " << crashed.exit_code << " " << crashed.error << std::endl;
    const auto foreign = pseudo ? bridge.substr(0, 12) + "-pb" : uplink;
    check(crashed.exit_code == -SIGKILL && master_of(foreign) == bridge, "killed owner left a foreign port in its bridge");
    ChildOptions launch; launch.argv = {daemon_path, "--data-dir", path, "--apk", path + "/fixture.apk"};
    Child daemon(launch);
    const auto port = path + "/run/droidvmd-port.txt";
    const auto deadline = std::chrono::steady_clock::now() + 15s;
    while (access(port.c_str(), F_OK) < 0 && !daemon.poll_exit() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(20ms);
    if (access(port.c_str(), F_OK) < 0) std::cerr << "daemon: " << daemon.communicate({}, 3s).error << std::endl;
    check(access(port.c_str(), F_OK) == 0 && master_of(uplink).empty() && !exists(netbox, bridge) &&
        !exists(netbox, bridge.substr(0, 12) + "-pi") && !exists(netbox, bridge.substr(0, 12) + "-pb"),
        "startup detaches foreign ports and pbridge veths, then reclaims the bridge");
    check(daemon.signal(SIGTERM) && daemon.communicate({}, 10s).exit_code == 128 + SIGTERM, "recovered daemon stops");
    for (const char* dir : {"/run", "/cache", "/files", "/bin"}) remove_files(path + dir);
    check(unlink((path + "/fixture.apk").c_str()) == 0 && rmdir(path.c_str()) == 0, "L2 daemon fixture reclaimed");
    netbox.delete_link(uplink);
}
void pd_daemon_recovery() {
    PdServer server("pr" + random_id(false).substr(0, 6));
    Netbox netbox(netbox_path); netbox.state(server.uplink, true); reset_uplink(server.uplink);
    const auto path = work + "/lb-pd-daemon";
    for (const char* dir : {"", "/bin", "/files", "/run"}) check(mkdir((path + dir).c_str(), 0700) == 0, "create PD daemon fixture");
    for (const char* tool : {"netbox", "bridgedhcp"})
        check(symlink(binary(tool).c_str(), (path + "/bin/" + tool).c_str()) == 0, "reuse installed network tools");
    { std::ofstream apk(path + "/fixture.apk"); apk << "isolated PD recovery fixture"; }
    {
        Fd files(open((path + "/files").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        NetworkConfigService(files.get(), getuid()).create(admin, pd_network("lbk" + random_id(false).substr(0, 8), server.uplink));
    }
    ChildOptions crash; crash.argv = {"/proc/self/exe", "--linux-backend-pd-crash", netbox_path, path};
    const auto crashed = Child(crash).communicate({}, 40s);
    if (crashed.exit_code != -SIGKILL) std::cerr << "PD crash fixture: " << crashed.exit_code << " " << crashed.error << std::endl;
    check(crashed.exit_code == -SIGKILL, "PD owner killed after live delegation");
    uint32_t table;
    {
        Fd files(open((path + "/files").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        NetworkConfigService configs(files.get(), getuid());
        table = pd_table(configs, configs.list(admin)[0]["id"].asString());
    }
    check(pd_table_users(table) >= 2 && uplink_sysctl(server.uplink, "accept_ra") == "2", "crashed owner left PD host state");
    ChildOptions launch; launch.argv = {daemon_path, "--data-dir", path, "--apk", path + "/fixture.apk"};
    Child daemon(launch);
    const auto port = path + "/run/droidvmd-port.txt";
    const auto deadline = std::chrono::steady_clock::now() + 15s;
    while (access(port.c_str(), F_OK) < 0 && !daemon.poll_exit() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(20ms);
    if (access(port.c_str(), F_OK) < 0) std::cerr << "daemon: " << daemon.communicate({}, 3s).error << std::endl;
    check(access(port.c_str(), F_OK) == 0, "daemon recovers PD ownership before readiness");
    check(!pd_table_users(table) && uplink_sysctl(server.uplink, "accept_ra") == "1" && uplink_sysctl(server.uplink, "forwarding") == "0",
        "startup recovery flushed orphan PD state and restored uplink sysctls");
    check(daemon.signal(SIGTERM) && daemon.communicate({}, 10s).exit_code == 128 + SIGTERM, "recovered daemon stops");
    for (const char* dir : {"/run", "/cache", "/files", "/bin"}) remove_files(path + dir);
    check(unlink((path + "/fixture.apk").c_str()) == 0 && rmdir(path.c_str()) == 0, "PD daemon fixture reclaimed");
}
// The tagged /32 shape pbridge parks on an uplink; system ip cannot set it.
bool fixture_tagged(const std::string& link) { return !Netbox(netbox_path).addresses(link, pbridge_offload_metric).empty(); }
void proxy_address(const std::string& link, const char* address) {
    NetlinkMessage<ifaddrmsg> request;
    request.header.nlmsg_type = RTM_NEWADDR; request.header.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
    request.payload.ifa_family = AF_INET; request.payload.ifa_prefixlen = 32;
    request.payload.ifa_index = if_nametoindex(link.c_str());
    in_addr value{}; check(inet_pton(AF_INET, address, &value) == 1, "parse proxy address");
    const uint32_t metric = pbridge_offload_metric, flags = IFA_F_NOPREFIXROUTE;
    request.attribute(IFA_LOCAL, &value, sizeof(value)); request.attribute(IFA_ADDRESS, &value, sizeof(value));
    request.attribute(IFA_RT_PRIORITY, &metric, sizeof(metric)); request.attribute(IFA_FLAGS, &flags, sizeof(flags));
    netlink_exchange(request.header);
    check(fixture_tagged(link), "tagged proxy address installed");
}
void host_ipv4_watch() {
    const auto name = "eth" + random_id(false).substr(0, 6), peer = "hw" + random_id(false).substr(0, 6);
    ip({"link", "add", name, "type", "veth", "peer", "name", peer});
    Fixture fixture("lb-host-watch");
    fixture.netbox.state(name, true); fixture.netbox.state(peer, true);
    // One registered network with a forward gives the host set DNAT to scope.
    const auto config = network_config("lbw" + random_id(false).substr(0, 8));
    const LinuxPortForward forward{"tapguest", 0, 2, "tcp", 40000, 40000, 45679, 45679};
    fixture.coordinator.set(config); fixture.coordinator.set_forwards(config["id"].asString(), {forward});
    std::mutex mutex;
    size_t applies = 0;
    // Real time plus a skew the test advances to reach the backstop poll.
    std::atomic<int64_t> skew{0};
    HostIpv4Watch watch(fixture.netbox, fixture.runtime, [&](const std::vector<std::string>& hosts) {
        fixture.coordinator.set_host_ipv4(hosts); std::lock_guard lock(mutex); ++applies;
    }, [&] { return HostIpv4Watch::Clock::now() + std::chrono::milliseconds(skew.load()); });
    TaskService workers;
    auto nat = [&](const std::vector<std::string>& hosts) {
        std::vector<OwnedFirewall::Rule> rows;
        for (const auto& row : linux_firewall_plan(config, {}, {forward}, hosts).nat4) rows.push_back({config["id"].asString() + "/" + row.key, row.rule});
        return rows;
    };
    auto settle = [&](const std::set<std::string>& want, std::chrono::milliseconds budget) {
        const auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < budget) {
            watch.schedule(workers);
            const auto hosts = watch.current();
            if (std::set<std::string>(hosts.begin(), hosts.end()) == want &&
                fixture.firewall.matches_table(LinuxFirewall::owner_key, false, "nat", nat(hosts)))
                return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
            std::this_thread::sleep_for(50ms);
        }
        std::string seen; for (const auto& host : watch.current()) seen += host + " ";
        std::lock_guard lock(mutex);
        throw std::runtime_error("host IPv4 watch deadline; current: " + seen + "applies " + std::to_string(applies) +
            " ready " + std::to_string(fixture.coordinator.ready()) + " nat " + wire::stringify(fixture.firewall.inventory()["rules"].size()));
    };
    const auto tool = netbox_path;
    for (int i = 0; i < 60 && monitor_pids(tool).empty(); ++i) { watch.schedule(workers); std::this_thread::sleep_for(50ms); }
    const auto first = monitor_pids(tool);
    check(first.size() == 1 && fixture.runtime.inventory()["switches"].size() == 1, "watch runs one monitor with a helper identity");
    settle({}, 1000ms); std::this_thread::sleep_for(500ms); // let the monitor subscribe
    fixture.netbox.address(name, "198.18.240.1/24", true);
    check(settle({"198.18.240.1"}, 3000ms) < 3s, "monitor event scopes DNAT well before the backstop poll");
    // Separate subnets: deleting a primary also deletes its secondaries.
    // Excluded by the shared policy: a non-allowlisted interface and a
    // pbridge-tagged proxy address. The later event proves both were seen.
    fixture.netbox.address(peer, "198.18.240.2/24", true);
    proxy_address(name, "198.18.240.50");
    fixture.netbox.address(name, "198.18.241.3/24", true);
    settle({"198.18.240.1", "198.18.241.3"}, 3000ms);
    check(watch.signal_monitor(SIGKILL), "kill host address monitor");
    std::this_thread::sleep_for(200ms);
    fixture.netbox.address(name, "198.18.240.1/24", false);
    skew += 6000;
    settle({"198.18.241.3"}, 3000ms);
    const auto second = monitor_pids(tool);
    check(second.size() == 1 && second != first && fixture.runtime.inventory()["switches"].size() == 1,
        "backstop poll catches the missed change and restarts the monitor");
    std::this_thread::sleep_for(500ms);
    fixture.netbox.address(name, "198.18.242.4/24", true);
    check(settle({"198.18.241.3", "198.18.242.4"}, 3000ms) < 3s, "restarted monitor streams changes again");
    size_t before;
    { std::lock_guard lock(mutex); before = applies; }
    skew += 6000;
    for (int i = 0; i < 20; ++i) { watch.schedule(workers); std::this_thread::sleep_for(50ms); }
    { std::lock_guard lock(mutex); check(applies == before, "unchanged backstop polls do not republish the firewall"); }
    workers.shutdown(); watch.stop();
    check(monitor_pids(tool).empty() && fixture.runtime.inventory()["switches"].empty(), "watch stop reaps the monitor and its identity");
    fixture.coordinator.remove(config["id"].asString());
    fixture.finish();
    fixture.netbox.delete_link(name);
}
}
int linux_backend_pd_crash_child(const std::string& netbox, const std::string& path) {
    netbox_path = netbox;
    try {
        Fixture fixture(path, binary("bridgedhcp"), true);
        auto now = NetworkService::Clock::now();
        NetworkService service(fixture.configs, fixture.factory(), [&] { return now; });
        const auto id = fixture.configs.list(admin)[0]["id"].asString();
        service.start(admin, id);
        if (config::string(fixture.configs.get(admin, id), "uplink_mode") != "l2") wait_delegated(fixture, service, id, now, nullptr);
        kill(getpid(), SIGKILL);
    } catch (const std::exception& error) { std::cerr << error.what() << std::endl; }
    return 1;
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
        {"actual_daemon_linux_network_lifecycle", actual_daemon},
        {"real_pd_delegation_and_helper_death_cleanup", pd_delegation_ownership},
        {"pd_shared_uplink_and_foreign_table", pd_shared_uplink_and_foreign_table},
        {"actual_daemon_pd_ownership_recovery", pd_daemon_recovery},
        {"direct_l2_uplink_datapath_and_reattach", l2_direct_uplink},
        {"actual_daemon_l2_port_recovery", [] { l2_daemon_recovery(false); }},
        {"pbridge_mac_nat_proxy_and_helper_death_cleanup", pbridge_pseudo_uplink},
        {"actual_daemon_pbridge_recovery", [] { l2_daemon_recovery(true); }},
        {"host_ipv4_watch_scopes_dnat_and_restarts_monitor", host_ipv4_watch}});
}
}
