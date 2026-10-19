// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_bridge.h"
#include "linux_plan.h"
#include "host_discovery.h"
#include "store/network_config.h"
#include "services/context.h"
#include "common/wire.h"
#include "vm/nic.h"
#include <algorithm>
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
    if (config::boolean(nic, "mac_security")) {
        mac_security_[tap] = false;
        if (!mac.empty()) {
            try { resources_.netbox.locked(tap, true); resources_.netbox.fdb(tap, mac); mac_security_[tap] = true; }
            catch (const std::exception&) { try { resources_.netbox.locked(tap, false); } catch (const std::exception&) {} }
        }
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
    failures_.erase(tap); mac_security_.erase(tap);
    if (l3_ && running_) try { publish_leases(); } catch (const std::exception&) {}
    release_tap(tap);
}
namespace {
// LinuxNetwork.listAddresses: "local/prefixlen" of each row, empty on failure.
std::vector<std::string> device_addresses(const Netbox& netbox, const std::string& device, std::optional<uint32_t> metric = {}) {
    std::vector<std::string> result;
    try {
        for (const auto& row : netbox.addresses(device, metric)) {
            if (!row.isObject()) continue;
            const auto local = config::string(row, "local");
            if (!local.empty()) result.push_back(local + "/" + std::to_string(config::integer(row, "prefixlen", 0)));
        }
    } catch (const std::exception&) {}
    return result;
}
// canonAddr: config and live spellings of one address compare equal.
std::string canonical_cidr(const std::string& cidr) {
    try {
        const auto slash = cidr.find('/');
        if (slash == std::string::npos) return cidr;
        const auto prefix = config::NetworkPrefix::parse(cidr, cidr.find(':') != std::string::npos);
        return prefix.address() + "/" + std::to_string(prefix.prefix());
    } catch (const std::exception&) { return cidr; }
}
std::vector<std::string> configured_cidrs(const Json::Value& vlan) {
    std::vector<std::string> result;
    auto strings = [&](const char* key) {
        const auto& rows = config::member(vlan, key);
        if (rows.isArray()) for (const auto& row : rows) if (row.isString() && !row.asString().empty()) result.push_back(row.asString());
    };
    const auto v4 = config::string(config::member(vlan, "ipv4"), "cidr");
    if (!v4.empty()) result.push_back(v4);
    strings("ipv4_secondary");
    const auto v6 = config::string(config::member(vlan, "ipv6"), "cidr");
    if (static_ipv6(vlan) && !v6.empty()) result.push_back(v6);
    strings("ipv6_secondary");
    return result;
}
}
void LinuxBridge::live_details(Json::Value& data) const {
    const auto& netbox = resources_.netbox;
    const auto bridge = config::string(config_, "bridge_name");
    const auto vlans = l3_vlans(config_);
    auto device = [&](int vid) { return vid == 0 ? bridge : OwnedLinks::vlan_device(bridge, vid); };
    auto vid_of = [](const Json::Value& vlan) { return static_cast<int>(config::integer(vlan, "vlan_id")); };
    auto& addresses = data["live_addresses"] = Json::Value(Json::arrayValue);
    for (const auto& cidr : device_addresses(netbox, bridge)) addresses.append(cidr);
    for (const auto* vlan : vlans) if (vid_of(*vlan)) for (const auto& cidr : device_addresses(netbox, device(vid_of(*vlan)))) addresses.append(cidr);
    // listAddressEntries: VLAN 0, configured VLANs, then on-demand VLAN bridges.
    std::vector<int> vids{0};
    std::map<int, std::vector<std::string>> configured;
    for (const auto* vlan : vlans) {
        const int vid = vid_of(*vlan);
        if (!configured.contains(vid)) configured[vid] = configured_cidrs(*vlan);
        if (std::find(vids.begin(), vids.end(), vid) == vids.end()) vids.push_back(vid);
    }
    for (const int vid : topology_.extra_vlans()) if (std::find(vids.begin(), vids.end(), vid) == vids.end()) vids.push_back(vid);
    auto& entries = data["address_entries"] = Json::Value(Json::arrayValue);
    for (const int vid : vids) {
        std::vector<std::pair<std::string, std::string>> live;
        for (const auto& raw : device_addresses(netbox, device(vid))) {
            const auto key = canonical_cidr(raw);
            if (std::find_if(live.begin(), live.end(), [&](const auto& row) { return row.first == key; }) == live.end()) live.emplace_back(key, raw);
        }
        auto take = [&](const std::string& cidr) {
            const auto at = std::find_if(live.begin(), live.end(), [&](const auto& row) { return row.first == canonical_cidr(cidr); });
            if (at == live.end()) return false;
            live.erase(at); return true;
        };
        for (const auto& cidr : configured[vid]) { const bool bound = take(cidr); entries.append(address_entry(cidr, vid, bound, "configured")); }
        // The PD host address is listed by its own PD entry.
        if (const auto pd = pd_.find(vid); pd != pd_.end()) take(pd->second);
        for (const auto& [key, raw] : live) entries.append(address_entry(raw, vid, true, "auto"));
    }
    if (pseudo_ && !uplink_.empty())
        for (const auto& raw : device_addresses(netbox, uplink_, pbridge_offload_metric)) entries.append(address_entry(raw, 0, true, "pbridge_guest"));
    // listPdStatus: one row per DHCP-PD VLAN, synthesized without a client.
    Json::Value status;
    if (dhcp_needed_ && dhcp_.healthy()) try { status = dhcp_.status(); } catch (const std::exception&) {}
    std::map<int, Json::Value> clients;
    Json::Value pd_status(Json::arrayValue);
    const auto& ifaces = config::member(status, "ifaces");
    if (ifaces.isArray()) for (const auto& iface : ifaces) {
        if (!iface.isObject()) continue;
        const auto state = config::string(iface, "pd_state");
        if (state.empty()) continue;
        int tag;
        try { size_t used = 0; const auto text = config::string(iface, "tag"); tag = std::stoi(text, &used); if (used != text.size()) continue; }
        catch (const std::exception&) { continue; }
        Json::Value row;
        row["vlan"] = tag; row["state"] = state; row["prefix"] = config::string(iface, "pd_prefix"); row["address"] = config::string(iface, "pd_address");
        clients.emplace(tag, row);
        Json::Value legacy;
        legacy["vlan_id"] = tag; legacy["state"] = state;
        if (!config::string(iface, "pd_prefix").empty()) legacy["prefix"] = config::string(iface, "pd_prefix");
        pd_status.append(std::move(legacy));
    }
    auto& pd = data["pd"] = Json::Value(Json::arrayValue);
    std::map<int, std::string> resolvable;
    bool resolved = false;
    for (const auto* vlan : vlans) {
        if (static_ipv6(*vlan)) continue;
        const int vid = vid_of(*vlan);
        if (const auto at = clients.find(vid); at != clients.end()) { pd.append(at->second); continue; }
        if (!resolved) { try { resolvable = resolve(config_); } catch (const std::exception&) {} resolved = true; }
        Json::Value row;
        row["vlan"] = vid; row["state"] = resolvable.contains(vid) ? "searching" : "no_uplink"; row["prefix"] = "";
        pd.append(std::move(row));
    }
    auto& interfaces = data["live_interfaces"] = Json::Value(Json::arrayValue);
    try {
        for (const auto& row : netbox.links(bridge)) {
            if (!row.isObject()) continue;
            Json::Value item;
            item["name"] = config::string(row, "ifname");
            item["address"] = config::string(row, "address");
            item["state"] = row.isMember("operstate") ? config::string(row, "operstate") : "UNKNOWN";
            interfaces.append(std::move(item));
        }
    } catch (const std::exception&) {}
    auto& neighbors = data["neighbors"] = Json::Value(Json::arrayValue);
    auto add_neighbors = [&](const std::string& name) {
        try { for (const auto& row : netbox.neighbors(name)) neighbors.append(row); } catch (const std::exception&) {}
    };
    add_neighbors(bridge);
    for (const auto* vlan : vlans) if (vid_of(*vlan)) add_neighbors(device(vid_of(*vlan)));
    try { data["dhcp_leases"] = dhcp_leases(); } catch (const std::exception&) { data["dhcp_leases"] = Json::Value(); }
    if (!data["dhcp_leases"].isArray()) data["dhcp_leases"] = Json::Value(Json::arrayValue);
    // appendInfo.
    if (!pd_status.empty()) data["pd_status"] = std::move(pd_status);
    if (!l3_ && !uplink_.empty()) data["resolved_uplink"] = uplink_;
    if (!mac_security_.empty()) for (const auto& [tap, active] : mac_security_) data["mac_security_active"][tap] = active;
}
Json::Value LinuxBridge::dhcp_leases() const {
    Json::Value leases(Json::arrayValue);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    const auto vlans = l3_vlans(config_);
    if (!running_ || !l3_ || !dhcp_needed_ || !dhcp_.healthy() || vlans.size() > 16) return {};
    if (dhcp_needed_ && dhcp_.healthy()) for (const auto* vlan : vlans) for (const bool v6 : {false, true}) {
        const auto vid = static_cast<int>(config::integer(*vlan, "vlan_id"));
        if (!config::boolean(config::member(config::member(*vlan, v6 ? "ipv6" : "ipv4"), "dhcp"), "enabled")) continue;
        try {
            ControlOptions options;
            options.timeout = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
            if (options.timeout.count() <= 0) return {};
            const auto response = dhcp_.leases(vid, v6, std::move(options));
            const auto& rows = config::member(response, "leases");
            if (!rows.isArray()) return {};
            for (const auto& lease : rows) {
                if (!lease.isObject()) continue;
                if (leases.size() >= 4096) return {};
                Json::Value item;
                item["vlan"] = vid;
                item["expires"] = Json::Int64(rfc3339_seconds(config::string(lease, "expiry")));
                item["mac"] = config::string(lease, "mac");
                item["ip"] = config::string(lease, "ip");
                item["hostname"] = config::string(lease, "hostname");
                leases.append(std::move(item));
            }
        } catch (const std::exception&) { return {}; }
    }
    return leases;
}
bool LinuxBridge::manual_address(const std::string& cidr, bool add) {
    if (!running_) return false;
    const auto bridge = config::string(config_, "bridge_name");
    try { resources_.links.require_owned(firewall_owner_, bridge); resources_.netbox.address(bridge, cidr, add); return true; }
    catch (const std::exception&) { return false; }
}
bool LinuxBridge::manual_port(const std::string& name, bool add) {
    if (!add) {
        // Legacy nomaster'ed any interface; only ports this network enslaved leave here.
        if (!manual_ports_.contains(name)) return false;
        try { resources_.ports.release(manual_owner(name)); } catch (const std::exception&) { return false; }
        manual_ports_.erase(name);
        return true;
    }
    if (!running_ || manual_ports_.contains(name) || attached_.contains(name)) return false;
    try {
        Netbox::interface_name(name);
        const auto bridge = config::string(config_, "bridge_name");
        if (name == bridge || name == uplink_) return false;
        resources_.ports.attach(manual_owner(name), name, bridge);
        manual_ports_.insert(name);
        return true;
    } catch (const std::exception&) { return false; }
}
bool LinuxBridge::pd_action(int vlan, bool release) {
    return running_ && dhcp_needed_ && dhcp_.healthy() && dhcp_.pd_action(vlan, release);
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
    if (!retain_taps_) { attached_.clear(); mac_security_.clear(); }
    for (const auto& name : std::set(manual_ports_)) attempt([&] { resources_.ports.release(manual_owner(name)); manual_ports_.erase(name); });
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
