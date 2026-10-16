// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_bridge.h"
#include "linux_plan.h"
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
}
LinuxBridge::LinuxBridge(Resources resources)
    : resources_(std::move(resources)), topology_(resources_.netbox, resources_.links),
      dhcp_(resources_.dhcp_executable, resources_.runtime, resources_.dhcp_state_directory) {}
void LinuxBridge::start(const Json::Value& config) {
    if (running_ || routing_ || !firewall_owner_.empty()) throw ServiceError(ErrorCode::conflict, "Linux network requires cleanup before start");
    const auto plan = linux_plan(config);
    if (!plan.l3) throw ServiceError(ErrorCode::unavailable, "Native Linux L2 uplinks are not implemented yet");
    for (const auto& vlan : plan.vlans)
        if (vlan.pd) throw ServiceError(ErrorCode::unavailable, "PD route ownership is not connected yet");
    try {
        // Guard bridge scopes before any guest-facing link comes up.
        firewall_owner_ = plan.owner; resources_.firewall.set(config);
        topology_.start(config, bridge_mac(config));
        routing_ = std::make_unique<LinuxRouting>(config, resources_.rules, resources_.routes);
        routing_->refresh({});
        dhcp_needed_ = dhcp_.start(config);
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
    routing_->refresh({});
    resources_.firewall.refresh();
}
void LinuxBridge::recover(const Json::Value& config) {
    if (running_ && !rebuild_ && dhcp_needed_ && !dhcp_.healthy()) {
        // The kernel bridge stays the data path; leases survive in state.
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
    attempt([&] { dhcp_.stop(); dhcp_needed_ = false; });
    attempt([&] { if (routing_) { routing_->stop(); routing_.reset(); } });
    bool quiesced = false;
    attempt([&] { topology_.stop(); quiesced = true; });
    if (quiesced && !firewall_owner_.empty())
        attempt([&] { resources_.firewall.remove(firewall_owner_); firewall_owner_.clear(); });
    if (!failures.empty()) throw ServiceError(ErrorCode::io_error, "Linux network cleanup incomplete: " + wire::stringify(failures));
}
Json::Value LinuxBridge::tools() const {
    return dhcp_needed_ ? dhcp_.tools() : Json::Value(Json::arrayValue);
}
Json::Value LinuxBridge::tool_log(const std::string& key) const {
    return dhcp_needed_ && key == "bridgedhcp" ? dhcp_.tool_log() : Json::Value();
}
}
