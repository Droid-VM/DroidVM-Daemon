// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_topology.h"
#include "linux_plan.h"
#include "store/network_config.h"
#include "services/context.h"
#include "common/wire.h"
#include <algorithm>
#include <bit>
#include <fcntl.h>
#include <regex>
#include <set>
#include <system_error>

namespace droidvm::network {
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
    const auto plan = linux_plan(configuration);
    if (!std::regex_match(mac, std::regex("([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")))
        throw ServiceError(ErrorCode::invalid_argument, "Linux topology requires a persisted bridge MAC");
    const auto& owner = plan.owner; const auto& bridge = plan.bridge;
    const bool l3 = plan.l3;
    const auto& vlans = plan.vlans;
    std::set<std::string> names{bridge};
    for (const auto& vlan : vlans) if (vlan.id) { names.insert(vlan.device); names.insert(vlan.leg); }
    // Validate the whole requested topology before touching the kernel. The
    // inventory still checks atomically-created identities at each operation.
    const auto inventory = links_.inventory();
    for (const auto& row : inventory["links"]) {
        if (row["owner"] == owner || names.contains(row["name"].asString()))
            throw ServiceError(ErrorCode::conflict, "Linux topology has reserved resources");
    }
    for (const auto& row : netbox_.links()) if (names.contains(config::string(row, "ifname")))
        throw ServiceError(ErrorCode::conflict, "Linux topology interface already exists: " + config::string(row, "ifname"));
    owner_ = owner; bridge_ = bridge;
    try {
        links_.bridge(owner_, bridge); devices_.push_back(bridge);
        links_.require_owned(owner_, bridge); netbox_.mac(bridge, mac);
        links_.require_owned(owner_, bridge); netbox_.stp(bridge, plan.stp);
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
            for (const auto& family : vlan.addresses) for (const auto& address : family) {
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
std::string LinuxTopology::ensure_vlan(int vid) {
    if (owner_.empty()) throw ServiceError(ErrorCode::unavailable, "Linux topology is stopped");
    const auto device = OwnedLinks::vlan_device(bridge_, vid), leg = OwnedLinks::vlan_leg(bridge_, vid);
    if (std::find(devices_.begin(), devices_.end(), device) != devices_.end()) return device;
    links_.bridge(owner_, device); devices_.push_back(device);
    links_.vlan(owner_, bridge_, leg, vid); devices_.push_back(leg);
    links_.require_owned(owner_, leg); links_.require_owned(owner_, device);
    netbox_.master(leg, device);
    netbox_.state(leg, true); netbox_.state(device, true);
    return device;
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
