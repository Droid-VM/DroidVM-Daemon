// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_bridge.h"
#include "linux_plan.h"
#include "host_discovery.h"
#include "store/network_config.h"
#include "services/context.h"
#include "common/wire.h"

namespace droidvm::network {
namespace {
// prepare_runtime persisted exactly one of these for a Linux L3 network.
std::string bridge_mac(const Json::Value& config) {
    const auto configured = config::string(config::member(config, "l3"), "mac_address");
    return configured.empty() ? config::string(config, "generated_mac") : configured;
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
      dhcp_(resources_.dhcp_executable, resources_.runtime, resources_.dhcp_state_directory) {}
void LinuxBridge::start_dhcp(std::map<int, std::string> uplinks) {
    // Register every delegation durably before the helper can touch the host.
    for (const auto& vlan : pd_vlans(config_)) if (const auto at = uplinks.find(vlan.vlan); at != uplinks.end()) {
        pd_registered_ = true; resources_.pd.acquire(config::uuid(config_), vlan.vlan, vlan.table, at->second);
    }
    uplinks_ = uplinks;
    dhcp_needed_ = dhcp_.start(config_, {}, std::move(uplinks));
}
void LinuxBridge::start(const Json::Value& config) {
    if (running_ || routing_ || !firewall_owner_.empty() || pd_registered_)
        throw ServiceError(ErrorCode::conflict, "Linux network requires cleanup before start");
    const auto plan = linux_plan(config);
    if (!plan.l3) throw ServiceError(ErrorCode::unavailable, "Native Linux L2 uplinks are not implemented yet");
    try {
        // Guard bridge scopes before any guest-facing link comes up.
        config_ = config; pd_.clear();
        firewall_owner_ = plan.owner; resources_.firewall.set(config);
        topology_.start(config, bridge_mac(config));
        routing_ = std::make_unique<LinuxRouting>(config, resources_.rules, resources_.routes);
        routing_->refresh({}, resources_.pd.tables());
        start_dhcp(resolve(config));
        running_ = true; rebuild_ = false;
    } catch (const std::exception& error) {
        const std::string detail = error.what();
        try { stop(); }
        catch (const std::exception& cleanup) { throw ServiceError(ErrorCode::io_error, detail + "; cleanup: " + cleanup.what()); }
        throw;
    }
}
bool LinuxBridge::healthy() const {
    return running_ && !rebuild_ && (!dhcp_needed_ || dhcp_.healthy());
}
void LinuxBridge::refresh() {
    if (!running_) throw ServiceError(ErrorCode::unavailable, "Linux network is stopped");
    try { topology_.verify(); }
    catch (...) { rebuild_ = true; throw; }
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
    if (running_ && !rebuild_ && dhcp_needed_ && !dhcp_.healthy()) {
        // The kernel bridge stays the data path; leases and the PD binding
        // survive in state, and the PD registration stays with the network.
        topology_.verify(); dhcp_.restart(); return;
    }
    stop(); start(config);
}
void LinuxBridge::stop() {
    running_ = false;
    Json::Value failures(Json::arrayValue);
    auto attempt = [&](auto&& step) {
        try { step(); } catch (const std::exception& error) { failures.append(error.what()); }
    };
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
    return dhcp_needed_ ? dhcp_.tools() : Json::Value(Json::arrayValue);
}
Json::Value LinuxBridge::tool_log(const std::string& key) const {
    return dhcp_needed_ && key == "bridgedhcp" ? dhcp_.tool_log() : Json::Value();
}
}
