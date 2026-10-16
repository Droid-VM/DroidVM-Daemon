// SPDX-License-Identifier: GPL-3.0-or-later
#include "forwarding_contract.h"
#include "firewall_contract.h"
#include "contracts.h"
#include "network/forwarding.h"
#include "network/firewall.h"
#include "network/linux_firewall.h"
#include "network/netbox.h"
#include "network/netlink.h"
#include "services/network.h"
#include "common/identity.h"
#include <algorithm>
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/neighbour.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <poll.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

namespace droidvm::test {
namespace {
using namespace droidvm::network;
std::string executable, directory;
const char* forwarding_path(bool ipv6) { return ipv6 ? "/proc/sys/net/ipv6/conf/all/forwarding" : "/proc/sys/net/ipv4/ip_forward"; }
int read_forwarding(bool ipv6) {
    Fd file(open(forwarding_path(ipv6), O_RDONLY | O_CLOEXEC));
    char value[4]{};
    check(file.get() >= 0 && read(file.get(), value, sizeof(value)) == 2 && (value[0] == '0' || value[0] == '1'), "read real namespace sysctl");
    return value[0] - '0';
}
void set_forwarding(int value) {
    for (const bool ipv6 : {false, true}) {
        Fd file(open(forwarding_path(ipv6), O_WRONLY | O_CLOEXEC));
        if (file.get() < 0) throw std::system_error(errno, std::generic_category(), "open test forwarding reset");
        const auto count = write(file.get(), value ? "1" : "0", 1);
        if (count != 1) throw std::system_error(count < 0 ? errno : EIO, std::generic_category(),
            std::string("write test forwarding reset ") + forwarding_path(ipv6) + " count=" + std::to_string(count));
    }
}
void flags(int expected) { check(read_forwarding(false) == expected && read_forwarding(true) == expected, "dual-stack forwarding state"); }
Json::Value configuration(const std::string& name) {
    auto value = wire::parse(R"({"schema":2,"bridge_name":"test","bridge_type":"linux","uplink_mode":"l3","l3":{"vlans":[]}})");
    value["id"] = random_id(true); value["name"] = name;
    return value;
}
void demand_lifecycle() {
    set_forwarding(0);
    int writes = 0;
    Forwarding forwarding([&](const char* stage) { if (std::string_view(stage).ends_with("_written")) ++writes; });
    forwarding.refresh(); flags(0);
    auto network = configuration("forward");
    auto gvisor = network; gvisor["bridge_type"] = "gvisor";
    check(!forwarding.acquire(gvisor), "gvisor needs no host forwarding");
    auto l2 = network; l2["uplink_mode"] = "l2"; l2["l2"]["uplink"] = "Ethernet";
    check(!forwarding.acquire(l2), "L2 needs no host forwarding"); flags(0);
    auto first = forwarding.acquire(network); flags(1); check(writes == 2, "first demand enables both families");
    error(ErrorCode::conflict, [&] { forwarding.acquire(network); });
    auto second = forwarding.acquire(configuration("second"));
    forwarding.refresh(); check(writes == 2, "correct sysctl is not rewritten");
    first.reset(); set_forwarding(0); forwarding.refresh(); flags(1);
    second.reset(); flags(1); // shared value is never restored over netd
    set_forwarding(0); forwarding.refresh(); flags(0);
    first = forwarding.acquire(network); flags(1);
    forwarding.shutdown(); set_forwarding(0); forwarding.refresh(); flags(0);
    error(ErrorCode::unavailable, [&] { forwarding.acquire(network); });
    first.reset(); flags(0);
    std::unique_ptr<Forwarding::Lease> retained;
    { Forwarding owner; retained = owner.acquire(network); }
    set_forwarding(0); retained.reset(); flags(0); // lease may outlive owner
}
void partial_failure_retry() {
    set_forwarding(0);
    std::string fail = "before_ipv6_write";
    Forwarding forwarding([&](const char* stage) { if (fail == stage) throw std::runtime_error("injected sysctl failure"); });
    const auto network = configuration("retry");
    error(ErrorCode::io_error, [&] { forwarding.acquire(network); });
    check(read_forwarding(false) == 1 && read_forwarding(true) == 0, "partial enable not reported as readiness or rolled back");
    set_forwarding(0); forwarding.refresh(); flags(0); // failed acquire left no demand
    fail.clear(); auto lease = forwarding.acquire(network); flags(1);
    set_forwarding(0); fail = "before_ipv4_write";
    error(ErrorCode::io_error, [&] { forwarding.refresh(); });
    check(read_forwarding(false) == 0 && read_forwarding(true) == 1, "independent family attempted despite first failure");
    fail.clear(); forwarding.refresh(); flags(1); // refresh failure retained demand
    lease.reset(); set_forwarding(0); forwarding.refresh(); flags(0);
}
uint16_t checksum(const uint8_t* data, size_t size, uint32_t sum = 0) {
    for (size_t i = 0; i < size; i += 2) sum += (uint32_t(data[i]) << 8) | (i + 1 < size ? data[i + 1] : 0);
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}
struct Path {
    Netbox netbox{executable};
    std::string input_name, output_name;
    Fd input, output;
    std::array<uint8_t, 6> router{};
    Path(std::string ingress = "fwin", std::string egress = "fwout")
        : input_name(std::move(ingress)), output_name(std::move(egress)),
          input(open_transient_tap(input_name)), output(open_transient_tap(output_name)) {
        check(fcntl(input.get(), F_SETFL, O_NONBLOCK) == 0 && fcntl(output.get(), F_SETFL, O_NONBLOCK) == 0, "nonblocking test TAPs");
        int header_size = 10;
        check(ioctl(input.get(), TUNSETVNETHDRSZ, &header_size) == 0 && ioctl(output.get(), TUNSETVNETHDRSZ, &header_size) == 0,
            "set existing TAP adapter's virtio header size");
        for (const auto& name : {input_name, output_name}) netbox.state(name, true);
        netbox.address(input_name, "198.18.201.1/24", true); netbox.address(output_name, "198.18.202.1/24", true);
        netbox.address(input_name, "fd91:fe21:201::1/64", true); netbox.address(output_name, "fd91:fe21:202::1/64", true);
        Fd socket(::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
        ifreq request{}; std::copy(input_name.begin(), input_name.end(), request.ifr_name);
        check(socket.get() >= 0 && ioctl(socket.get(), SIOCGIFHWADDR, &request) == 0, "read ingress TAP MAC");
        std::copy_n(reinterpret_cast<uint8_t*>(request.ifr_hwaddr.sa_data), 6, router.begin());
        for (const bool ipv6 : {false, true}) {
            NetlinkMessage<ndmsg> message;
            message.header.nlmsg_type = RTM_NEWNEIGH; message.header.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
            message.payload.ndm_family = ipv6 ? AF_INET6 : AF_INET;
            message.payload.ndm_ifindex = if_nametoindex(output_name.c_str()); message.payload.ndm_state = NUD_PERMANENT;
            std::array<uint8_t, 16> address{};
            check(inet_pton(message.payload.ndm_family, ipv6 ? "fd91:fe21:202::2" : "198.18.202.2", address.data()) == 1, "parse peer IP");
            const uint8_t mac[]{2, 0, 0, 0, 0, 2};
            message.attribute(NDA_DST, address.data(), ipv6 ? 16 : 4); message.attribute(NDA_LLADDR, mac, sizeof(mac));
            netlink_exchange(message.header);
        }
    }
    bool packet(bool ipv6, uint8_t sequence, const std::string& expected_source = {}, const std::string& from = {}) {
        const auto source_ip = from.empty() ? std::string(ipv6 ? "fd91:fe21:201::2" : "198.18.201.2") : from;
        const size_t ip_size = ipv6 ? 40 : 20, udp = 14 + ip_size;
        std::vector<uint8_t> packet(udp + 12, 0);
        auto word = [&](size_t at, uint16_t value) { packet[at] = value >> 8; packet[at + 1] = value & 255; };
        std::copy(router.begin(), router.end(), packet.begin()); packet[6] = 2; packet[11] = 1;
        word(12, ipv6 ? 0x86dd : 0x0800);
        if (ipv6) {
            packet[14] = 0x60; word(18, 12); packet[20] = 17; packet[21] = 64;
            check(inet_pton(AF_INET6, source_ip.c_str(), packet.data() + 22) == 1 &&
                inet_pton(AF_INET6, "fd91:fe21:202::2", packet.data() + 38) == 1, "encode IPv6 packet");
        } else {
            packet[14] = 0x45; word(16, ip_size + 12); packet[22] = 64; packet[23] = 17;
            check(inet_pton(AF_INET, source_ip.c_str(), packet.data() + 26) == 1 &&
                inet_pton(AF_INET, "198.18.202.2", packet.data() + 30) == 1, "encode IPv4 packet");
            word(24, checksum(packet.data() + 14, ip_size));
        }
        // A fresh flow per packet also permits meaningful NAT changes without
        // reusing a previous conntrack translation decision.
        word(udp, 45000 + sequence); word(udp + 2, 45679); word(udp + 4, 12);
        packet[udp + 8] = 'D'; packet[udp + 9] = 'V'; packet[udp + 10] = 'M'; packet[udp + 11] = sequence;
        if (ipv6) {
            const uint32_t pseudo = static_cast<uint16_t>(~checksum(packet.data() + 22, 32));
            const auto value = checksum(packet.data() + udp, 12, pseudo + 12 + 17);
            word(udp + 6, value ? value : 65535);
        }
        std::vector<uint8_t> frame(10, 0); // no checksum/GSO offload requested
        frame.insert(frame.end(), packet.begin(), packet.end());
        check(write(input.get(), frame.data(), frame.size()) == static_cast<ssize_t>(frame.size()), "inject real guest UDP packet");
        const auto deadline = std::chrono::steady_clock::now() + 300ms;
        while (std::chrono::steady_clock::now() < deadline) {
            pollfd readable{output.get(), POLLIN, 0};
            if (poll(&readable, 1, 20) <= 0) continue;
            uint8_t buffer[2048]; const auto count = read(output.get(), buffer, sizeof(buffer));
            const auto* bytes = buffer + 10;
            if (count != static_cast<ssize_t>(frame.size()) || bytes[12] != packet[12] || bytes[13] != packet[13] ||
                !std::equal(packet.begin() + udp, packet.end(), bytes + udp)) continue;
            check(bytes[ipv6 ? 21 : 22] == 63, "kernel routed packet and decremented hop count");
            std::array<uint8_t, 16> source{};
            const auto text = expected_source.empty() ? source_ip.c_str() : expected_source.c_str();
            check(inet_pton(ipv6 ? AF_INET6 : AF_INET, text, source.data()) == 1 &&
                std::equal(source.begin(), source.begin() + (ipv6 ? 16 : 4), bytes + (ipv6 ? 22 : 26)), "forwarded source address matches expected NAT behavior");
            return true;
        }
        return false;
    }
};
void real_dual_stack_packets() {
    set_forwarding(0);
    Path path;
    check(!path.packet(false, 1) && !path.packet(true, 2), "disabled forwarding drops transit packets");
    Forwarding forwarding;
    auto lease = forwarding.acquire(configuration("packets"));
    check(path.packet(false, 3) && path.packet(true, 4), "enabling forwarding delivers real IPv4 and IPv6 guest packets");
    set_forwarding(0);
    check(!path.packet(false, 5) && !path.packet(true, 6), "simulated netd reset interrupts both data paths");
    forwarding.refresh();
    check(path.packet(false, 7) && path.packet(true, 8), "watcher refresh restores real dual-stack packet forwarding");
    lease.reset(); set_forwarding(0); forwarding.refresh();
    check(!path.packet(false, 9) && !path.packet(true, 10), "no demand does not reenable either data path");
}
void service_lifecycle() {
    set_forwarding(0);
    Fd files(open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    NetworkConfigService configs(files.get(), getuid());
    const auto first = configs.create(admin, configuration("service-first"));
    const auto second = configs.create(admin, configuration("service-second"));
    struct Candidate final : Backend {
        bool live = false, fail_stop = false;
        void start(const Json::Value&) override { flags(0); live = true; }
        bool healthy() const override { return live; }
        void recover(const Json::Value&) override { live = true; }
        void refresh() override { flags(1); }
        void stop() override { if (fail_stop) throw std::runtime_error("cleanup retained"); live = false; }
    };
    std::map<std::string, Candidate*> backends;
    auto now = NetworkService::Clock::now();
    NetworkService service(configs, [&](const Json::Value& network) {
        auto backend = std::make_unique<Candidate>(); backends[network["id"].asString()] = backend.get(); return backend;
    }, [&] { return now; });
    check(service.start(admin, first).state == NetworkState::running, "Linux candidate reaches RUNNING after forwarding"); flags(1);
    set_forwarding(0); now += 5s;
    check(service.reconcile(admin, first).state == NetworkState::running, "periodic service tick reasserts before backend refresh"); flags(1);
    set_forwarding(0); service.start(admin, second); flags(1);
    service.stop(admin, first); set_forwarding(0); now += 5s;
    service.reconcile(admin, second); flags(1);
    backends.at(second)->live = false; set_forwarding(0); now += 5s;
    check(service.reconcile(admin, second).state == NetworkState::running, "backend recovery reasserts forwarding before readiness"); flags(1);
    backends.at(second)->fail_stop = true;
    error(ErrorCode::io_error, [&] { service.stop(admin, second); });
    set_forwarding(0); now += 5s;
    check(service.reconcile(admin, second).state == NetworkState::failed, "failed explicit stop is not refreshed"); flags(0);
    backends.at(second)->fail_stop = false; service.stop(admin, second);
    service.start(admin, first); flags(1);
    check(service.shutdown().empty(), "service releases forwarding demand on shutdown"); flags(1);
    set_forwarding(0); service.reconcile(admin, first); flags(0);
    for (const char* file : {"networks.json", "networks.json.bak"}) unlinkat(files.get(), file, 0);
}
}
void firewall_packet_contract(const std::string& netbox, const std::string& work) {
    // Only invoked after the firewall suite has entered its private netns.
    executable = netbox;
    set_forwarding(0); Path path;
    Forwarding forwarding; auto demand = forwarding.acquire(configuration("firewall packets"));
    const auto place = work + "/packets";
    check(mkdir(place.c_str(), 0700) == 0, "create packet firewall inventory");
    Fd fd(open(place.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)); Iptables iptables;
    OwnedFirewall owner(fd.get(), getuid(), iptables);
    check(path.packet(false, 20) && path.packet(true, 21), "baseline dual-stack data path");
    for (const bool ipv6 : {false, true}) {
        FirewallRule drop; drop.ipv6 = ipv6; drop.input = "fwin"; drop.output = "fwout"; drop.target = "DROP";
        owner.put("packets", ipv6 ? "drop6" : "drop4", drop);
    }
    check(!path.packet(false, 22) && !path.packet(true, 23), "owned scoped drops block actual packets in both families");
    for (const bool ipv6 : {false, true}) {
        FirewallRule accept; accept.ipv6 = ipv6; accept.input = "fwin"; accept.output = "fwout";
        accept.protocol = "udp"; accept.port_first = accept.port_last = 45678;
        owner.put("packets", ipv6 ? "wrong6" : "wrong4", accept);
    }
    check(!path.packet(false, 24) && !path.packet(true, 25), "port-specific acceptance does not allow a different destination port");
    for (const bool ipv6 : {false, true}) {
        FirewallRule accept; accept.ipv6 = ipv6; accept.input = "fwin"; accept.output = "fwout";
        accept.protocol = "udp"; accept.port_first = accept.port_last = 45679;
        owner.put("packets", ipv6 ? "allow6" : "allow4", accept);
    }
    check(path.packet(false, 26) && path.packet(true, 27), "head insertion allows intended dual-stack traffic ahead of drop");
    FirewallRule snat; snat.table = "nat"; snat.chain = "POSTROUTING"; snat.source = "198.18.201.0/24";
    snat.output = "fwout"; snat.target = "MASQUERADE";
    owner.put("packets", "snat", snat);
    check(path.packet(false, 28, "198.18.202.1"), "real MASQUERADE rewrites guest source to egress router IP");
    owner.remove("packets", "snat");
    check(path.packet(false, 29), "removing owned NAT restores original source for new flows");
    owner.remove("packets", "allow4"); owner.remove("packets", "allow6");
    check(!path.packet(false, 30) && !path.packet(true, 31), "exact ACCEPT removal leaves independent DROP rules active");
    check(owner.cleanup("packets").empty(), "packet firewall inventory cleanup");
    check(path.packet(false, 32) && path.packet(true, 33), "cleanup restores baseline forwarding behavior");
    for (const bool ipv6 : {false, true}) {
        FirewallRule drop; drop.ipv6 = ipv6; drop.input = "fwin"; drop.output = "fwout"; drop.target = "DROP";
        auto accept = drop; accept.target = "ACCEPT";
        const uint16_t sequence = ipv6 ? 50 : 40;
        owner.replace_table("batch", ipv6, "filter", {{"drop", drop}, {"accept", accept}});
        check(!path.packet(ipv6, sequence), "atomic ordered policy enforces DROP before ACCEPT");
        owner.replace_table("batch", ipv6, "filter", {{"accept", accept}, {"drop", drop}});
        check(path.packet(ipv6, sequence + 1), "atomic reorder changes actual forwarding verdict");
        owner.replace_table("batch", ipv6, "filter", {{"drop", drop}});
        check(!path.packet(ipv6, sequence + 2), "atomic policy tightening removes previous acceptance");
        owner.replace_table("batch", ipv6, "filter", {});
        check(path.packet(ipv6, sequence + 3), "empty atomic revision restores original data path");
    }
    for (const char* name : {"network-firewall.json", "network-firewall.json.bak"}) unlinkat(fd.get(), name, 0);
    check(rmdir(place.c_str()) == 0, "packet firewall fixture empty");
}
void linux_firewall_packet_contract(const std::string& netbox, const std::string& work) {
    executable = netbox; set_forwarding(0);
    auto config = configuration("Linux policy packets"); config["bridge_name"] = "brfp";
    config["l3"]["vlans"].append(wire::parse(R"({"vlan_id":0,"ipv4":{"cidr":"198.18.201.1/24","snat":false},
        "ipv6":{"source":"static","cidr":"fd91:fe21:201::1/64"}})"));
    Forwarding forwarding; auto demand = forwarding.acquire(config);
    const auto place = work + "/planned-packets";
    check(mkdir(place.c_str(), 0700) == 0, "create planned packet inventory");
    Fd fd(open(place.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)); Iptables iptables;
    OwnedFirewall owner(fd.get(), getuid(), iptables);
    auto filters = [&](const LinuxFirewallPlan& plan) {
        for (const bool ipv6 : {false, true}) owner.replace_table(plan.owner, ipv6, "filter", plan.filter[ipv6]);
    };
    // This private fixture has one controlled flow. It verifies generated
    // rules, not cross-table publication/readiness of a production backend.
    const auto base = linux_firewall_plan(config);
    uint8_t sequence = 80;
    for (const std::string egress : {"eth0", "wlan0", "rmnet_data0", "tun0", "usb0", "veth0", "brfp.7"}) {
        Path path("brfp", egress);
        if (egress == "eth0") {
            check(path.packet(false, sequence++, {}, "198.19.201.2") && path.packet(true, sequence++, {}, "fd91:fe21:901::2"),
                "baseline routes unapproved source addresses before policy filtering");
            filters(base); owner.replace_table(base.owner, false, "mangle", base.mangle4);
        }
        const bool inter = egress == "brfp.7", allowed = inter || (egress != "usb0" && egress != "veth0");
        check(path.packet(false, sequence++) == allowed && path.packet(true, sequence++) == allowed,
            "actual dual-stack forwarding follows external allowlist or inter-VLAN prefix");
        check(path.packet(false, sequence++, {}, "198.19.201.2") == inter && path.packet(true, sequence++, {}, "fd91:fe21:901::2") == inter,
            "external forwarding checks source subnet while legacy inter-VLAN acceptance remains scoped to bridge prefix");
        if (egress == "eth0" || inter) {
            auto nat = config; nat["l3"]["vlans"][0]["ipv4"]["snat"] = true;
            owner.replace_table(base.owner, false, "nat", linux_firewall_plan(nat).nat4);
            check(path.packet(false, sequence++, inter ? "198.18.201.2" : "198.18.202.1"), "planned SNAT rewrites only non-bridge egress");
            owner.replace_table(base.owner, false, "nat", {});
            check(path.packet(false, sequence++), "disabling planned SNAT preserves original source");
        }
        if (egress == "eth0") {
            auto pd = config; auto& vlan = pd["l3"]["vlans"][0];
            vlan["ipv6"]["source"] = "dhcp_pd"; vlan["ipv6"]["cidr"] = "fd91:fe21:999::1/64";
            vlan["ipv6"]["pd"]["uplink"] = "eth0";
            auto apply = [&](const PdAddresses& lease) { owner.replace_table(base.owner, true, "filter", linux_firewall_plan(pd, lease).filter[1]); };
            apply({}); check(!path.packet(true, sequence++), "absent PD does not authorize configured placeholder or former static subnet");
            apply({{0, "fd91:fe21:201::1/64"}}); check(path.packet(true, sequence++), "authoritative live PD enables actual guest forwarding");
            apply({{0, "fd91:fe21:203::1/64"}}); check(!path.packet(true, sequence++), "changed delegation revokes former subnet for new flows");
            apply({}); check(!path.packet(true, sequence++), "PD withdrawal keeps unknown subnet blocked");
            vlan["ipv6_secondary"].append("fd91:fe21:201::1/64"); apply({});
            check(path.packet(true, sequence++), "static IPv6 secondary remains available without a live delegation");
            owner.replace_table(base.owner, true, "filter", base.filter[1]);
        }
    }
    // Reverse topology: the packet enters via a host uplink and is routed to
    // the guest-facing interface. Its destination, not source, is scoped.
    config["l3"]["vlans"][0]["ipv4"]["cidr"] = "198.18.202.1/24";
    config["l3"]["vlans"][0]["ipv6"]["cidr"] = "fd91:fe21:202::1/64";
    filters(linux_firewall_plan(config));
    for (const std::string ingress : {"eth0", "usb0"}) {
        Path path(ingress, "brfp");
        const bool allowed = ingress == "eth0";
        check(path.packet(false, sequence++) == allowed && path.packet(true, sequence++) == allowed,
            "inbound uplink traffic uses exact guest device and external interface allowlist");
        if (allowed) {
            auto other = config; other["l3"]["vlans"][0]["ipv4"]["cidr"] = "198.18.203.1/24";
            other["l3"]["vlans"][0]["ipv6"]["cidr"] = "fd91:fe21:203::1/64";
            filters(linux_firewall_plan(other));
            check(!path.packet(false, sequence++) && !path.packet(true, sequence++), "inbound acceptance requires a configured destination subnet");
            filters(linux_firewall_plan(config));
        }
    }
    check(owner.cleanup(base.owner).empty(), "planned policy exact cleanup");
    for (const char* name : {"network-firewall.json", "network-firewall.json.bak"}) unlinkat(fd.get(), name, 0);
    check(rmdir(place.c_str()) == 0, "planned packet fixture empty");
}
void linux_firewall_coordinator_packets(const std::string& netbox, const std::string& work) {
    std::cerr << "coordinator: guarded packet transitions" << std::endl;
    executable = netbox; set_forwarding(0);
    auto config = configuration("coordinated firewall packets"); config["bridge_name"] = "brcf";
    config["l3"]["vlans"].append(wire::parse(R"({"vlan_id":0,"ipv4":{"cidr":"198.18.201.1/24","snat":false},
        "ipv6":{"source":"static","cidr":"fd91:fe21:201::1/64"}})"));
    Forwarding forwarding; auto demand = forwarding.acquire(config);
    const auto place = work + "/coordinated-packets";
    check(mkdir(place.c_str(), 0700) == 0, "create coordinator packet inventory");
    Fd fd(open(place.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)); Iptables iptables;
    OwnedFirewall owner(fd.get(), getuid(), iptables);
    std::string failure;
    bool tamper = false;
    LinuxFirewall coordinator(owner, [&](const char* stage) {
        if (failure == stage) throw std::runtime_error("injected publication failure");
        if (tamper && std::string_view(stage) == "linux_firewall_mangle4") {
            const auto inventory = owner.inventory();
            for (const auto& row : inventory["rules"]) if (row["owner"] == LinuxFirewall::owner_key && row["rule"]["table"] == "nat") {
                iptables.erase(FirewallRule::from(row["rule"]), row["tag"].asString()); break;
            }
        }
    });
    auto fail_set = [&](const Json::Value& desired) {
        bool rejected = false;
        try { coordinator.set(desired); } catch (const std::runtime_error&) { rejected = true; }
        check(rejected && !coordinator.ready(), "incomplete publication never reports ready");
    };
    uint8_t sequence = 170;
    {
        Path path("brcf", "eth0"); coordinator.set(config);
        check(coordinator.ready() && path.packet(false, sequence++) && path.packet(true, sequence++), "published baseline forwards both families");
        config["l3"]["vlans"][0]["ipv4"]["snat"] = true;
        failure = "linux_firewall_guard6"; fail_set(config);
        check(!path.packet(false, sequence++) && !path.packet(true, sequence++), "both families remain blocked before NAT update");
        failure.clear(); coordinator.refresh();
        check(coordinator.ready() && path.packet(false, sequence++, "198.18.202.1") && path.packet(true, sequence++), "retry publishes forwarding only after dependencies converge");
        config["l3"]["vlans"][0]["ipv4_secondary"].append("198.18.203.1/24"); tamper = true;
        error(ErrorCode::conflict, [&] { coordinator.set(config); });
        check(!coordinator.ready() && !path.packet(false, sequence++) && !path.packet(true, sequence++), "dependency drift is detected before releasing either family guard");
        tamper = false; coordinator.refresh();
        check(coordinator.ready() && path.packet(false, sequence++, "198.18.202.1") && path.packet(true, sequence++), "dependency drift recovery restores actual data path");
        config["l3"]["vlans"][0]["ipv4_secondary"] = Json::Value(Json::arrayValue);
        failure = "linux_firewall_filter4"; fail_set(config);
        check(path.packet(false, sequence++, "198.18.202.1") && !path.packet(true, sequence++),
            "partial family publication exposes only completed dependencies while remaining family stays blocked");
        failure.clear(); coordinator.refresh();
        check(coordinator.ready() && path.packet(true, sequence++), "retry completes remaining family publication");
    }
    {
        // Legacy SNAT is source-scoped, even when a packet did not enter a
        // bridge. Guard both old and new source ranges, not just bridge names.
        std::cerr << "coordinator: old and new NAT source domains" << std::endl;
        Path path("otherin", "eth0");
        check(path.packet(false, sequence++, "198.18.202.1"), "legacy source-scoped NAT can match a non-bridge ingress");
        config["l3"]["vlans"][0]["ipv4"]["cidr"] = "198.18.203.1/24";
        failure = "linux_firewall_nat4"; fail_set(config);
        check(!path.packet(false, sequence++) && !path.packet(false, sequence++, {}, "198.18.203.2"),
            "old and new NAT match domains remain protected after NAT commit failure");
        failure.clear(); coordinator.refresh();
        check(coordinator.ready() && path.packet(false, sequence++) && path.packet(false, sequence++, "198.18.202.1", "198.18.203.2"),
            "successful publication removes obsolete NAT and activates only new source range");
    }
    coordinator.remove(config["id"].asString()); // all fixture TAPs are closed
    check(coordinator.ready() && owner.inventory()["rules"].empty(), "quiesced network removal retires all policy and guard rules");
    coordinator.stop();
    for (const char* name : {"network-firewall.json", "network-firewall.json.bak"}) unlinkat(fd.get(), name, 0);
    check(rmdir(place.c_str()) == 0, "coordinator packet fixture empty");
}
void forwarding_namespace_contract(const std::string& netbox, const std::string& work) {
    const auto path = work + "/forwarding";
    check(mkdir(path.c_str(), 0700) == 0, "create isolated forwarding fixture");
    const auto v4 = read_forwarding(false), v6 = read_forwarding(true);
    ChildOptions options; options.argv = {"/proc/self/exe", "--forwarding-namespace", netbox, path};
    const auto result = Child(options).communicate({}, 30s);
    std::cerr << "isolated forwarding contracts: " << result.output << result.error << std::endl;
    check(!result.timed_out && result.exit_code == 0 && wire::parse(result.output)["passed"] == true, "isolated forwarding contracts pass");
    check(read_forwarding(false) == v4 && read_forwarding(true) == v6, "host forwarding sysctls unchanged");
    check(rmdir(path.c_str()) == 0, "forwarding fixture empty");
}
int forwarding_namespace_child(const std::string& netbox, const std::string& work) {
    struct stat before{}, after{};
    if (stat("/proc/self/ns/net", &before) != 0 || unshare(CLONE_NEWNET) != 0 ||
        stat("/proc/self/ns/net", &after) != 0 || before.st_ino == after.st_ino) return 70;
    executable = netbox; directory = work;
    return run({{"forwarding_demand_and_late_release", demand_lifecycle}, {"partial_failure_and_retry", partial_failure_retry},
        {"real_ipv4_ipv6_transit_and_reset", real_dual_stack_packets}, {"network_service_forwarding_lifecycle", service_lifecycle}});
}
}
