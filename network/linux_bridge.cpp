// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_bridge.h"
#include "linux_plan.h"
#include "host_discovery.h"
#include "store/network_config.h"
#include "services/context.h"
#include "common/wire.h"
#include "vm/nic.h"
#include <bit>

namespace droidvm::network {
namespace {
// prepare_runtime persisted exactly one of these; L2 always generates.
std::string bridge_mac(const Json::Value& config) {
    const auto configured = config::string(config, "uplink_mode") == "l2" ? "" : config::string(config::member(config, "l3"), "mac_address");
    return configured.empty() ? config::string(config, "generated_mac") : configured;
}
struct L2Uplink { std::string name; bool pseudo; };
L2Uplink l2_uplink(const Json::Value& config) {
    const auto& l2 = config::member(config, "l2");
    const auto configured = config::string(l2, "uplink");
    const auto snapshot = UplinkSnapshot::scan();
    const auto uplink = snapshot.resolve(configured);
    if (!uplink) throw ServiceError(ErrorCode::unavailable, "Uplink \"" + configured + "\" not found");
    // Legacy: honor the toggle, but force pseudo-bridging for a device that
    // cannot be enslaved (Wi-Fi STA / non-Ethernet).
    return {*uplink, config::boolean(l2, "pseudo_bridge", true) || snapshot.assume_dont_bridge(*uplink)};
}
// Per-network veth names keep pbridge instances sharing an uplink apart.
std::string pbridge_port(const Json::Value& config, const char* suffix) {
    return config::string(config, "bridge_name").substr(0, 12) + suffix;
}
struct PdVlan { int vlan; uint32_t table; std::string uplink; };
std::vector<PdVlan> pd_vlans(const Json::Value& config) {
    std::vector<PdVlan> result;
    const auto& rows = config::member(config::member(config, "l3"), "vlans");
    if (!rows.isArray()) return result;
    for (const auto& row : rows) {
        const auto& ipv6 = config::member(row, "ipv6");
        if (config::string(ipv6, "source") != "dhcp_pd") continue;
        const auto& pd = config::member(ipv6, "pd");
        result.push_back({static_cast<int>(config::integer(row, "vlan_id")),
            static_cast<uint32_t>(config::integer(pd, "route_table")), config::string(pd, "uplink")});
    }
    return result;
}
// One fresh scan per operation, like the legacy UplinkResolver.
std::map<int, std::string> resolve(const Json::Value& config) {
    std::map<int, std::string> result;
    const auto vlans = pd_vlans(config);
    if (vlans.empty()) return result;
    const auto snapshot = UplinkSnapshot::scan();
    for (const auto& vlan : vlans)
        if (!vlan.uplink.empty()) if (const auto name = snapshot.resolve(vlan.uplink)) result[vlan.vlan] = *name;
    return result;
}
}
LinuxBridge::LinuxBridge(Resources resources)
    : resources_(std::move(resources)), topology_(resources_.netbox, resources_.links),
      dhcp_(resources_.dhcp_executable, resources_.runtime, resources_.dhcp_state_directory),
      pbridge_(resources_.pbridge_executable, resources_.runtime) {}
void LinuxBridge::start_pbridge() {
    const auto fwd0 = pbridge_port(config_, "-pi"), fwd1 = pbridge_port(config_, "-pb");
    pbridge_registered_ = true; resources_.pbridge.acquire(firewall_owner_, uplink_, fwd0, fwd1);
    pbridge_.start(firewall_owner_, uplink_, config::string(config_, "bridge_name"), fwd0, fwd1);
}
void LinuxBridge::start_dhcp(std::map<int, std::string> uplinks) {
    // Register every delegation durably before the helper can touch the host.
    for (const auto& vlan : pd_vlans(config_)) if (const auto at = uplinks.find(vlan.vlan); at != uplinks.end()) {
        pd_registered_ = true; resources_.pd.acquire(config::uuid(config_), vlan.vlan, vlan.table, at->second);
    }
    uplinks_ = uplinks;
    dhcp_needed_ = dhcp_.start(config_, resources_.statics ? resources_.statics(config_) : std::map<int, DhcpStatics>{}, std::move(uplinks));
}
void LinuxBridge::start(const Json::Value& config) {
    if (running_ || routing_ || !firewall_owner_.empty() || pd_registered_ || pbridge_registered_)
        throw ServiceError(ErrorCode::conflict, "Linux network requires cleanup before start");
    const auto plan = linux_plan(config);
    const auto uplink = plan.l3 ? L2Uplink{} : l2_uplink(config);
    try {
        // Guard bridge scopes before any guest-facing link comes up.
        config_ = config; pd_.clear(); l3_ = plan.l3; pseudo_ = uplink.pseudo; uplink_ = uplink.name;
        firewall_owner_ = plan.owner; resources_.firewall.set(config);
        topology_.start(config, bridge_mac(config));
        if (l3_) {
            routing_ = std::make_unique<LinuxRouting>(config, resources_.rules, resources_.routes);
            routing_->refresh({}, resources_.pd.tables());
            start_dhcp(resolve(config));
        } else if (pseudo_) start_pbridge();
        else resources_.ports.attach(plan.owner, uplink_, plan.bridge);
        running_ = true; rebuild_ = false;
        // A rebuild re-plugs the VM TAPs it kept (crosvm still holds them).
        for (const auto& [tap, nic] : attached_) plug(tap, nic);
        if (l3_ && !attached_.empty()) publish_leases();
    } catch (const std::exception& error) {
        const std::string detail = error.what();
        try { stop(); }
        catch (const std::exception& cleanup) { throw ServiceError(ErrorCode::io_error, detail + "; cleanup: " + cleanup.what()); }
        throw;
    }
}
bool LinuxBridge::healthy() const {
    return running_ && !rebuild_ && (!dhcp_needed_ || dhcp_.healthy()) && (!pseudo_ || pbridge_.healthy());
}
void LinuxBridge::refresh() {
    if (!running_) throw ServiceError(ErrorCode::unavailable, "Linux network is stopped");
    try { topology_.verify(); }
    catch (...) { rebuild_ = true; throw; }
    if (!l3_) {
        // A replugged uplink is a new device: retire the stale record, then
        // attach whatever the configured identifier resolves to now.
        if (!pseudo_ && !resources_.ports.attached(firewall_owner_)) {
            resources_.ports.release(firewall_owner_);
            resources_.ports.attach(firewall_owner_, l2_uplink(config_).name, config::string(config_, "bridge_name"));
        }
        resources_.firewall.refresh(); return;
    }
    // Legacy reconcilePdUplinks: reload when a PD uplink now resolves to a
    // different device; a still-unresolved one is left to the helper.
    const auto uplinks = resolve(config_);
    bool changed = false;
    for (const auto& [vlan, name] : uplinks) if (const auto at = uplinks_.find(vlan); at == uplinks_.end() || at->second != name) changed = true;
    if (changed) {
        dhcp_.stop(); // the old helper must be gone before its PD state is retired
        if (pd_registered_) { resources_.pd.release(config::uuid(config_)); pd_registered_ = false; }
        auto next = uplinks_;
        for (const auto& [vlan, name] : uplinks) next[vlan] = name;
        if (!pd_.empty()) { resources_.firewall.set(config_); pd_.clear(); }
        start_dhcp(std::move(next));
    }
    if (dhcp_needed_ && dhcp_.healthy()) {
        auto snapshot = dhcp_.poll_pd(true);
        if (snapshot.addresses != pd_) { resources_.firewall.set(config_, snapshot.addresses); pd_ = std::move(snapshot.addresses); }
    }
    routing_->refresh(pd_, resources_.pd.tables());
    resources_.firewall.refresh();
}
void LinuxBridge::recover(const Json::Value& config) {
    if (running_ && !rebuild_ && pseudo_ && !pbridge_.healthy()) {
        // Stateless forwarder: a fresh process rebuilds the data path once
        // the dead one's veth and proxies are retired.
        topology_.verify(); pbridge_.stop();
        resources_.pbridge.release(firewall_owner_); pbridge_registered_ = false;
        start_pbridge(); return;
    }
    if (running_ && !rebuild_ && dhcp_needed_ && !dhcp_.healthy()) {
        // The kernel bridge stays the data path; leases and the PD binding
        // survive in state, and the PD registration stays with the network.
        topology_.verify(); dhcp_.restart(); return;
    }
    retain_taps_ = true;
    try { stop(); } catch (...) { retain_taps_ = false; throw; }
    retain_taps_ = false;
    start(config);
}
void LinuxBridge::plug(const std::string& tap, const Json::Value& nic) {
    const auto bridge = config::string(config_, "bridge_name");
    std::string target = bridge;
    const auto& vlan = config::member(nic, "vlan_id");
    if (l3_ && (vlan.type() == Json::intValue || vlan.type() == Json::uintValue) && vlan.isInt64()) {
        const int vid = std::bit_cast<int32_t>(static_cast<uint32_t>(vlan.asInt64()));
        if (vid != 4095) target = vid == 0 ? bridge : topology_.ensure_vlan(vid);
    }
    resources_.links.require_owned(tap_owner(tap), tap);
    resources_.netbox.master(tap, target);
    // Port flags only warn in the legacy backend.
    if (config::boolean(nic, "isolated")) try { resources_.netbox.isolated(tap, true); } catch (const std::exception&) {}
    const auto mac = config::string(nic, "mac_address");
    if (config::boolean(nic, "mac_security") && !mac.empty()) {
        try { resources_.netbox.locked(tap, true); resources_.netbox.fdb(tap, mac); }
        catch (const std::exception&) { try { resources_.netbox.locked(tap, false); } catch (const std::exception&) {} }
    }
    try { resources_.netbox.state(tap, true); } catch (const std::exception&) {}
}
void LinuxBridge::publish_leases() {
    if (dhcp_needed_ && resources_.statics)
        for (auto& [vlan, statics] : resources_.statics(config_)) dhcp_.set_statics(vlan, std::move(statics));
    // installNicForwards: invalid forwards are skipped and reported per TAP.
    std::vector<LinuxPortForward> forwards;
    std::map<std::string, std::vector<std::string>> failures;
    for (auto [tap, nic] : attached_) {
        const auto* vlan = vm::nic_dhcp_vlan(nic, config_);
        if (!vlan) continue;
        const auto& ipv4 = config::member(*vlan, "ipv4");
        auto& lease = nic["dhcp4_lease"];
        if (!lease.isObject()) lease = Json::Value(Json::objectValue);
        if (!config::boolean(lease, "enabled") || config::string(ipv4, "cidr").empty() ||
            !config::boolean(config::member(ipv4, "dhcp"), "enabled") || !config::boolean(ipv4, "snat")) continue;
        const auto offset = config::integer(lease, "offset", 64);
        try {
            const auto prefix = config::NetworkPrefix::parse(config::string(ipv4, "cidr"), false);
            const int64_t total = int64_t(1) << (32 - prefix.prefix());
            if (offset <= 0 || offset >= total - 1) continue; // invalid lease offset skips its forwards
        } catch (const std::exception&) { continue; }
        for (const auto& forward : vm::nic_forwards(nic, "dhcp4_lease")) {
            try { vm::validate_forward(forward); }
            catch (const std::exception& error) { failures[tap].push_back(forward.host + ":" + forward.guest + " (" + error.what() + ")"); continue; }
            for (const auto& protocol : forward.protocols())
                forwards.push_back({tap, static_cast<int>(config::integer(*vlan, "vlan_id")), offset, protocol,
                    static_cast<uint16_t>(vm::forward_port(forward.host, true)), static_cast<uint16_t>(vm::forward_port(forward.host, false)),
                    static_cast<uint16_t>(vm::forward_port(forward.guest, true)), static_cast<uint16_t>(vm::forward_port(forward.guest, false))});
        }
    }
    failures_ = std::move(failures);
    try { resources_.firewall.set_forwards(firewall_owner_, std::move(forwards)); }
    catch (const std::exception& error) {
        // The coordinator keeps the desired forwards and retries on refresh.
        failures_["firewall"].push_back(error.what());
    }
}
void LinuxBridge::release_tap(const std::string& tap) {
    // The bridge belongs to the network owner: leave it before deleting.
    try { resources_.links.require_owned(tap_owner(tap), tap); resources_.netbox.nomaster(tap); } catch (const std::exception&) {}
    const auto rows = resources_.links.cleanup(tap_owner(tap));
    if (!rows.empty()) throw ServiceError(ErrorCode::io_error, "VM TAP cleanup incomplete: " + wire::stringify(rows));
}
void LinuxBridge::attach(const Json::Value& nic, const std::string& tap) {
    if (!running_) throw ServiceError(ErrorCode::unavailable, "Network " + config::string(config_, "name") + " is not running");
    if (attached_.contains(tap)) detach(attached_.at(tap), tap);
    for (const auto& row : resources_.netbox.links())
        if (config::string(row, "ifname") == tap) throw ServiceError(ErrorCode::conflict, "TAP " + tap + " already exists");
    resources_.links.tap(tap_owner(tap), tap);
    try {
        plug(tap, nic);
        attached_[tap] = nic;
        if (l3_) publish_leases();
    } catch (...) {
        attached_.erase(tap);
        try { release_tap(tap); } catch (const std::exception&) {}
        throw;
    }
}
void LinuxBridge::detach(const Json::Value&, const std::string& tap) {
    if (!attached_.erase(tap)) return;
    failures_.erase(tap);
    if (l3_ && running_) try { publish_leases(); } catch (const std::exception&) {}
    release_tap(tap);
}
Json::Value LinuxBridge::forward_failures() const {
    Json::Value result(Json::objectValue);
    for (const auto& [tap, rows] : failures_) for (const auto& row : rows) result[tap].append(row);
    return result;
}
void LinuxBridge::stop() {
    running_ = false;
    Json::Value failures(Json::arrayValue);
    auto attempt = [&](auto&& step) {
        try { step(); } catch (const std::exception& error) { failures.append(error.what()); }
    };
    // VM TAPs leave the bridge first; a rebuild keeps them for re-plugging.
    for (const auto& [tap, nic] : attached_) attempt([&] {
        if (retain_taps_) { resources_.netbox.nomaster(tap); return; }
        release_tap(tap);
    });
    if (!retain_taps_) attached_.clear();
    // Detach a foreign uplink first: it quiesces external traffic and must
    // leave before the bridge can be released.
    if (!l3_ && !firewall_owner_.empty()) attempt([&] { resources_.ports.release(firewall_owner_); });
    bool pbridge_stopped = false;
    attempt([&] { pbridge_.stop(); pbridge_stopped = true; });
    if (pbridge_stopped && pbridge_registered_)
        attempt([&] { resources_.pbridge.release(firewall_owner_); pbridge_registered_ = false; }); // after the process exited
    bool helper_stopped = false;
    attempt([&] { dhcp_.stop(); dhcp_needed_ = false; helper_stopped = true; });
    // A live helper could reinstall rules after a flush; retire PD state only
    // once it has exited.
    if (helper_stopped && pd_registered_) attempt([&] { resources_.pd.release(config::uuid(config_)); pd_registered_ = false; });
    attempt([&] { if (routing_) { routing_->stop(); routing_.reset(); } });
    bool quiesced = false;
    attempt([&] { topology_.stop(); quiesced = true; });
    if (quiesced && !firewall_owner_.empty())
        attempt([&] { resources_.firewall.remove(firewall_owner_); firewall_owner_.clear(); });
    if (failures.empty()) { uplinks_.clear(); pd_.clear(); }
    else throw ServiceError(ErrorCode::io_error, "Linux network cleanup incomplete: " + wire::stringify(failures));
}
Json::Value LinuxBridge::tools() const {
    if (pseudo_) return pbridge_.tools();
    return dhcp_needed_ ? dhcp_.tools() : Json::Value(Json::arrayValue);
}
Json::Value LinuxBridge::tool_log(const std::string& key) const {
    if (pseudo_ && key == "pbridge") return pbridge_.tool_log();
    return dhcp_needed_ && key == "bridgedhcp" ? dhcp_.tool_log() : Json::Value();
}
}
