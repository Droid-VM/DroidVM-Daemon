// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_topology.h"
#include "store/network_config.h"
#include "services/context.h"
#include "common/wire.h"
#include <bit>
#include <fcntl.h>
#include <regex>
#include <set>
#include <system_error>

namespace droidvm::network {
namespace {
struct Vlan {
    int id;
    std::string device, leg;
    std::vector<std::string> addresses;
};
}
LinuxTopology::LinuxTopology(const Netbox& netbox, OwnedLinks& links, Observer observer)
    : netbox_(netbox), links_(links), observer_(std::move(observer)) {}
void LinuxTopology::disable_ra(const std::string& name) {
    links_.require_owned(owner_, name);
    const auto path = "/proc/sys/net/ipv6/conf/" + name + "/accept_ra";
    Fd file(open(path.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
    // IPv6 can be absent entirely. Other failures cannot silently leave a
    // guest-facing router interface accepting unsolicited advertisements.
    if (file.get() < 0 && errno == ENOENT) return;
    if (file.get() < 0) throw std::system_error(errno, std::generic_category(), "open owned interface accept_ra");
    ssize_t count;
    do { count = write(file.get(), "0\n", 2); } while (count < 0 && errno == EINTR);
    if (count != 2) throw std::system_error(count < 0 ? errno : EIO, std::generic_category(), "disable owned interface accept_ra");
    links_.require_owned(owner_, name);
}
void LinuxTopology::start(Json::Value configuration, const std::string& mac) {
    if (!owner_.empty()) throw ServiceError(ErrorCode::conflict, "Linux topology requires cleanup before start");
    config::validate_network(configuration);
    if (config::string(configuration, "bridge_type") == "gvisor")
        throw ServiceError(ErrorCode::invalid_argument, "Linux topology requires a Linux bridge");
    if (!std::regex_match(mac, std::regex("([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")))
        throw ServiceError(ErrorCode::invalid_argument, "Linux topology requires a persisted bridge MAC");
    const auto owner = config::uuid(configuration), bridge = config::string(configuration, "bridge_name");
    const bool l3 = config::string(configuration, "uplink_mode") != "l2";
    std::vector<Vlan> vlans;
    std::set<std::string> names{bridge};
    const auto& rows = config::member(config::member(configuration, "l3"), "vlans");
    if (l3 && rows.isArray()) for (const auto& row : rows) {
        if (!row.isObject()) continue;
        const int vid = std::bit_cast<int32_t>(static_cast<uint32_t>(config::integer(row, "vlan_id")));
        Vlan vlan{vid, OwnedLinks::vlan_device(bridge, vid), vid ? OwnedLinks::vlan_leg(bridge, vid) : "", {}};
        if (vid) { names.insert(vlan.device); names.insert(vlan.leg); }
        std::set<std::string> unique;
        for (const bool ipv6 : {false, true}) {
            const auto& ip = config::member(row, ipv6 ? "ipv6" : "ipv4");
            auto add = [&](const std::string& cidr) {
                if (cidr.empty()) return;
                const auto prefix = config::NetworkPrefix::parse(cidr, ipv6);
                const auto canonical = prefix.address() + "/" + std::to_string(prefix.prefix());
                if (unique.insert(canonical).second) vlan.addresses.push_back(canonical);
            };
            if (!ipv6 || config::string(ip, "source") != "dhcp_pd") add(config::string(ip, "cidr"));
            const auto& secondary = config::member(row, ipv6 ? "ipv6_secondary" : "ipv4_secondary");
            if (secondary.isArray()) for (const auto& cidr : secondary) if (cidr.isString()) add(cidr.asString());
        }
        vlans.push_back(std::move(vlan));
    }
    // Validate the whole requested topology before touching the kernel. The
    // inventory still checks atomically-created identities at each operation.
    const auto inventory = links_.inventory();
    for (const auto& row : inventory["links"]) {
        if (row["owner"] == owner || names.contains(row["name"].asString()))
            throw ServiceError(ErrorCode::conflict, "Linux topology has reserved resources");
    }
    for (const auto& row : netbox_.links()) if (names.contains(config::string(row, "ifname")))
        throw ServiceError(ErrorCode::conflict, "Linux topology interface already exists: " + config::string(row, "ifname"));
    owner_ = owner;
    try {
        links_.bridge(owner_, bridge); devices_.push_back(bridge);
        links_.require_owned(owner_, bridge); netbox_.mac(bridge, mac);
        links_.require_owned(owner_, bridge); netbox_.stp(bridge, config::boolean(configuration, "stp"));
        if (l3) disable_ra(bridge);
        point("main_configured");
        for (const auto& vlan : vlans) {
            if (vlan.id) {
                links_.bridge(owner_, vlan.device); devices_.push_back(vlan.device);
                links_.vlan(owner_, bridge, vlan.leg, vlan.id); devices_.push_back(vlan.leg);
                disable_ra(vlan.device); disable_ra(vlan.leg);
                links_.require_owned(owner_, vlan.leg); links_.require_owned(owner_, vlan.device);
                netbox_.master(vlan.leg, vlan.device);
                point("vlan_attached");
            }
            for (const auto& address : vlan.addresses) {
                links_.require_owned(owner_, vlan.device); netbox_.address(vlan.device, address, true);
                point("address_added");
            }
        }
        // Apply all RA policy/addressing first, then activate parents before
        // their VLAN children (the kernel rejects an UP leg on a DOWN parent).
        // DHCP/firewall are still caller work before network readiness.
        for (const auto& device : devices_) {
            links_.require_owned(owner_, device); netbox_.state(device, true);
        }
        verify();
        point("topology_ready");
    } catch (const std::exception& error) {
        const auto detail = std::string(error.what());
        try { stop(); }
        catch (const std::exception& cleanup) { throw ServiceError(ErrorCode::io_error, detail + "; cleanup: " + cleanup.what()); }
        throw;
    }
}
void LinuxTopology::verify() const {
    if (owner_.empty()) throw ServiceError(ErrorCode::unavailable, "Linux topology is stopped");
    for (const auto& name : devices_) links_.require_owned(owner_, name);
}
void LinuxTopology::stop() {
    if (owner_.empty()) return;
    const auto failures = links_.cleanup(owner_);
    if (!failures.empty()) throw ServiceError(ErrorCode::io_error, "Linux topology cleanup incomplete: " + wire::stringify(failures));
    devices_.clear(); owner_.clear();
}
}
