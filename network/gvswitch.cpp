// SPDX-License-Identifier: GPL-3.0-or-later
#include "gvswitch.h"
#include "helper_config.h"
#include "helper_ready.h"
#include "store/json_file.h"
#include "store/network_config.h"
#include "common/identity.h"
#include "common/wire.h"
#include "runtime/helper_identity.h"
#include "links.h"
#include "netbox.h"
#include "services/context.h"
#include "vm/nic.h"
#include <algorithm>
#include <bit>
#include <fcntl.h>
#include <sys/stat.h>
#include <system_error>

namespace droidvm::network {
Gvswitch::Gvswitch(std::string executable, SwitchRuntime& runtime, const Netbox* netbox, OwnedLinks* links)
    : executable_(std::move(executable)), runtime_(runtime), netbox_(netbox), links_(links) {
    if (executable_.empty() || executable_[0] != '/' || executable_.find('\0') != std::string::npos)
        throw std::invalid_argument("gvswitch executable must be an absolute path");
}
Gvswitch::~Gvswitch() { try { stop(); } catch (...) {} }
bool Gvswitch::healthy() const { return ready_ && process_.status().running; }
void Gvswitch::refresh() {
    try {
        if (!healthy() || !client_) throw std::runtime_error("gvswitch is not ready");
        const auto response = client_->request(HttpMethod::get, "/api/v1/ports", {}, {std::chrono::seconds(2), {}});
        if (!response.success() || !wire::parse(response.body).isArray() || !process_.status().running)
            throw std::runtime_error("gvswitch control plane is not ready");
    } catch (...) {
        ready_ = false;
        throw;
    }
}
Json::Value Gvswitch::tools() const {
    Json::Value result(Json::arrayValue), tool;
    const auto status = process_.status();
    tool["key"] = "gvswitch"; tool["running"] = status.running;
    tool["generation"] = std::to_string(status.generation);
    result.append(std::move(tool)); return result;
}
Json::Value Gvswitch::tool_log(const std::string& key) const {
    if (key != "gvswitch") return {};
    Json::Value result(Json::arrayValue);
    for (const auto& line : process_.log()) result.append(line.text);
    return result;
}
void Gvswitch::start(const Json::Value& config) {
    if (!allocation_.name.empty() || process_.status().running) throw std::logic_error("gvswitch requires cleanup before start");
    if (config::string(config, "bridge_type") != "gvisor") throw std::invalid_argument("gvswitch requires a gvisor network");
    const auto generated = gvswitch_config(config);
    config_ = config;
    runtime_.allocate(config::uuid(config), allocation_);
    config::JsonFile file(allocation_.directory.get(), "config.json", runtime_.owner());
    file.save(generated);
    // Both processes resolve the daemon's pinned FD, not a replaceable or
    // potentially overlong app-data path. The FD remains open until stop.
    const auto path = "/proc/" + std::to_string(getpid()) + "/fd/" + std::to_string(allocation_.directory.get());
    const auto token = random_id(false);
    client_ = std::make_unique<ControlHttp>(path + "/s", token);
    socket_ = path + "/s";
    ChildOptions options;
    options.argv = {executable_, "-listen", path + "/s", "-auth-token", token, "-config", path + "/config.json"};
    if (config::boolean(config, "stp")) options.argv.push_back("-stp");
    HelperIdentity identity(allocation_.directory.get(), runtime_.owner());
    identity.arm(options);
    process_.start(options);
    await_helper(process_, *client_, "/api/v1/ports", [](const Json::Value& ports) { return ports.isArray(); });
    ready_ = true;
}
void Gvswitch::recover(const Json::Value& config) {
    if (healthy()) return;
    // gvswitch is the data path: relaunch it and re-post the ports of the
    // TAPs crosvm still holds. Their old leases and forwards died with it.
    retain_taps_ = true;
    try { stop(); } catch (...) { retain_taps_ = false; throw; }
    retain_taps_ = false;
    start(config);
    for (const auto& [tap, nic] : std::map(attached_)) try { post_port(nic, tap); } catch (const std::exception&) {}
}
void Gvswitch::remove_directory() {
    if (allocation_.name.empty()) return;
    runtime_.cleanup(allocation_.name);
    allocation_.directory = Fd(); allocation_.name.clear();
}
void Gvswitch::stop() {
    ready_ = false;
    installed_.clear(); failures_.clear();
    process_.stop(); client_.reset();
    if (process_.status().running) throw std::runtime_error("gvswitch did not stop");
    remove_directory();
    if (retain_taps_) return;
    Json::Value failures(Json::arrayValue);
    for (const auto& [tap, nic] : attached_) try { release_tap(tap); } catch (const std::exception& error) { failures.append(error.what()); }
    attached_.clear();
    if (!failures.empty()) throw ServiceError(ErrorCode::io_error, "VM TAP cleanup incomplete: " + wire::stringify(failures));
}
std::string Gvswitch::tap_owner(const std::string& tap) const { return config::uuid(config_) + "/" + tap; }
ControlResponse Gvswitch::call(HttpMethod method, const std::string& path, const Json::Value* body, ControlOptions options) const {
    if (!client_) throw std::runtime_error("gvswitch not running");
    std::string text;
    if (body) text = wire::stringify(*body);
    return client_->request(method, path, body ? std::optional<std::string_view>(text) : std::nullopt, std::move(options));
}
void Gvswitch::release_tap(const std::string& tap) {
    const auto rows = links_->cleanup(tap_owner(tap));
    if (!rows.empty()) throw ServiceError(ErrorCode::io_error, "VM TAP cleanup incomplete: " + wire::stringify(rows));
}
void Gvswitch::attach(const Json::Value& nic, const std::string& tap) {
    if (!netbox_ || !links_) throw std::runtime_error("VM attachment is not supported by this network");
    if (!client_ || !ready_) throw std::runtime_error("gvswitch not running");
    if (attached_.contains(tap)) { const auto previous = attached_.at(tap); detach(previous, tap); }
    // A foreign link of this name is never deleted, unlike the legacy deleteTap.
    for (const auto& row : netbox_->links())
        if (config::string(row, "ifname") == tap) throw ServiceError(ErrorCode::conflict, "TAP " + tap + " already exists");
    links_->tap(tap_owner(tap), tap);
    try {
        try { links_->require_owned(tap_owner(tap), tap); netbox_->state(tap, true); }
        catch (const std::exception&) { throw std::runtime_error("Failed to bring up TAP " + tap); }
        post_port(nic, tap);
    } catch (...) {
        attached_.erase(tap);
        try { call(HttpMethod::remove, "/api/v1/ports/" + tap); } catch (const std::exception&) {}
        remove_leases(nic, tap);
        remove_forwards(tap);
        try { release_tap(tap); } catch (const std::exception&) {}
        throw;
    }
}
void Gvswitch::post_port(const Json::Value& nic, const std::string& tap) {
    Json::Value port;
    port["identifier"] = tap;
    const auto& vlan = config::member(nic, "vlan_id");
    // DataItem INTEGER only; (int) narrowing as getVlanId.
    port["vlan"] = (vlan.type() == Json::intValue || vlan.type() == Json::uintValue) && vlan.isInt64()
        ? std::bit_cast<int32_t>(static_cast<uint32_t>(vlan.asInt64())) : 4095;
    if (config::boolean(nic, "isolated")) port["isolated"] = true;
    const auto mac = config::string(nic, "mac_address");
    if (config::boolean(nic, "mac_security") && !mac.empty()) port["port_security"] = mac;
    port["mode"] = "client";
    port["transport"] = "af_xdp";
    port["interface"] = tap;
    port["bpdu_guard"] = true;
    const auto response = call(HttpMethod::post, "/api/v1/ports", &port);
    if (!response.success())
        throw std::runtime_error("gvswitch port create failed (" + std::to_string(response.code) + "): " + response.body);
    attached_[tap] = nic;
    apply_leases(nic, tap);
    install_forwards(nic, tap);
}
namespace {
struct LeaseNet { int vlan = 0; std::optional<config::NetworkPrefix> v4, v6; bool dhcp4 = false, dhcp6 = false, snat4 = false, snat6 = false; };
// VlanConfig.getIpv4Network/getIpv6Network (static source only) and the DHCP/SNAT flags.
LeaseNet lease_net(const Json::Value& vlan) {
    LeaseNet net;
    net.vlan = static_cast<int>(config::integer(vlan, "vlan_id"));
    const auto& ipv4 = config::member(vlan, "ipv4");
    const auto& ipv6 = config::member(vlan, "ipv6");
    const auto cidr4 = config::string(ipv4, "cidr"), cidr6 = config::string(ipv6, "cidr");
    const bool pd = config::string(ipv6, "source") == "dhcp_pd";
    net.dhcp4 = !cidr4.empty() && config::boolean(config::member(ipv4, "dhcp"), "enabled");
    net.dhcp6 = (pd || !cidr6.empty()) && config::boolean(config::member(ipv6, "dhcp"), "enabled");
    net.snat4 = config::boolean(ipv4, "snat"); net.snat6 = config::boolean(ipv6, "snat");
    try { if (!cidr4.empty()) net.v4 = config::NetworkPrefix::parse(cidr4, false); } catch (const std::exception&) {}
    try { if (!pd && !cidr6.empty()) net.v6 = config::NetworkPrefix::parse(cidr6, true); } catch (const std::exception&) {}
    return net;
}
const Json::Value& lease(const Json::Value& nic, const char* key) { return config::member(nic, key); }
std::string brief(const std::string& body) {
    const auto first = body.find_first_not_of(" \t\r\n"), last = body.find_last_not_of(" \t\r\n");
    return first == std::string::npos ? std::string() : body.substr(first, last - first + 1).substr(0, 80);
}
}
void Gvswitch::apply_leases(const Json::Value& nic, const std::string& tap) {
    const auto* vlan = vm::nic_dhcp_vlan(nic, config_);
    if (!vlan) return;
    const auto net = lease_net(*vlan);
    const auto mac = config::string(nic, "mac_address");
    auto put = [&](const char* family, const Json::Value& binding) {
        const auto response = call(HttpMethod::put, "/api/v1/gateways/" + std::to_string(net.vlan) + "/" + family + "/static/" + tap, &binding);
        if (!response.success())
            throw std::runtime_error(std::string("gvswitch ") + family + " static lease failed (" + std::to_string(response.code) + "): " + response.body);
    };
    if (config::boolean(lease(nic, "dhcp4_lease"), "enabled") && net.dhcp4 && !mac.empty() && net.v4) {
        Json::Value binding;
        binding["id"] = tap; binding["mac"] = mac;
        binding["ip"] = net.v4->address_at(config::integer(lease(nic, "dhcp4_lease"), "offset", 64));
        put("dhcp4", binding);
    }
    if (config::boolean(lease(nic, "dhcp6_lease"), "enabled") && net.dhcp6 && net.v6) {
        Json::Value binding;
        // Guest DUIDs are unknown; bind by port (and MAC when present).
        binding["id"] = tap; binding["port_identifier"] = tap;
        if (!mac.empty()) binding["mac"] = mac;
        binding["ip"] = net.v6->address_at(config::integer(lease(nic, "dhcp6_lease"), "offset", 64));
        put("dhcp6", binding);
    }
}
void Gvswitch::remove_leases(const Json::Value& nic, const std::string& tap) {
    const auto* vlan = vm::nic_dhcp_vlan(nic, config_);
    if (!vlan || !client_) return;
    const auto prefix = "/api/v1/gateways/" + std::to_string(lease_net(*vlan).vlan);
    try { call(HttpMethod::remove, prefix + "/dhcp4/static/" + tap); call(HttpMethod::remove, prefix + "/dhcp6/static/" + tap); }
    catch (const std::exception&) {}
}
void Gvswitch::install_forwards(Json::Value nic, const std::string& tap) {
    // One POST per concrete port so a single bind failure drops only that rule.
    constexpr int max_expansion = 128;
    std::vector<std::string> ids, failures;
    const auto* vlan = vm::nic_dhcp_vlan(nic, config_);
    if (vlan) {
        const auto net = lease_net(*vlan);
        for (const bool v6 : {false, true}) {
            const char* key = v6 ? "dhcp6_lease" : "dhcp4_lease";
            const auto& prefix = v6 ? net.v6 : net.v4;
            if (!config::boolean(lease(nic, key), "enabled") || !(v6 ? net.dhcp6 && net.snat6 : net.dhcp4 && net.snat4) || !prefix) continue;
            std::string guest;
            try { guest = prefix->address_at(config::integer(lease(nic, key), "offset", 64)); } catch (const std::exception&) { continue; }
            const std::string bind_host = v6 ? "[::]" : "0.0.0.0", guest_host = v6 ? "[" + guest + "]" : guest;
            for (const auto& forward : vm::nic_forwards(nic, key)) {
                try { vm::validate_forward(forward); }
                catch (const std::exception& error) { failures.push_back(forward.proto + " " + forward.host + ":" + forward.guest + " (" + error.what() + ")"); continue; }
                const int host = vm::forward_port(forward.host, true), guest_port = vm::forward_port(forward.guest, true);
                const int count = std::min(vm::forward_port(forward.host, false) - host + 1, max_expansion);
                for (const auto& protocol : forward.protocols()) {
                    for (int i = 0; i < count; ++i) {
                        const auto bind = bind_host + ":" + std::to_string(host + i);
                        try {
                            Json::Value rule;
                            rule["type"] = "local"; rule["network"] = protocol; rule["bind"] = bind;
                            rule["host"] = guest_host + ":" + std::to_string(guest_port + i);
                            const auto response = call(HttpMethod::post, "/api/v1/gateways/" + std::to_string(net.vlan) + "/forwards", &rule);
                            if (!response.success()) { failures.push_back(protocol + " " + bind + " (" + brief(response.body) + ")"); continue; }
                            const auto body = wire::parse(response.body);
                            const auto id = body.isObject() ? config::string(body, "id") : std::string();
                            if (!id.empty()) ids.push_back(std::to_string(net.vlan) + "/" + id);
                        } catch (const std::exception& error) { failures.push_back(protocol + " " + bind + " (" + error.what() + ")"); }
                    }
                }
            }
        }
    }
    if (!ids.empty()) installed_[tap] = std::move(ids);
    if (!failures.empty()) failures_[tap] = std::move(failures);
}
void Gvswitch::remove_forwards(const std::string& tap) {
    failures_.erase(tap);
    const auto at = installed_.find(tap);
    if (at == installed_.end()) return;
    const auto refs = std::move(at->second);
    installed_.erase(at);
    if (!client_) return;
    for (const auto& ref : refs) {
        const auto slash = ref.find('/');
        if (slash == std::string::npos) continue;
        try { call(HttpMethod::remove, "/api/v1/gateways/" + ref.substr(0, slash) + "/forwards/" + ref.substr(slash + 1)); }
        catch (const std::exception&) {}
    }
}
void Gvswitch::detach(const Json::Value& nic, const std::string& tap) {
    attached_.erase(tap);
    if (client_) {
        try { call(HttpMethod::remove, "/api/v1/ports/" + tap); } catch (const std::exception&) {}
        remove_leases(nic, tap);
        remove_forwards(tap);
    }
    if (links_) release_tap(tap);
}
void Gvswitch::live_details(Json::Value& data) const {
    // Gateway addresses live inside gvswitch: every configured one is bound.
    auto& addresses = data["live_addresses"] = Json::Value(Json::arrayValue);
    auto& entries = data["address_entries"] = Json::Value(Json::arrayValue);
    const auto vlans = l3_vlans(config_);
    for (const auto* vlan : vlans) {
        const int vid = static_cast<int>(config::integer(*vlan, "vlan_id"));
        for (const bool v6 : {false, true}) {
            const auto cidr = config::string(config::member(*vlan, v6 ? "ipv6" : "ipv4"), "cidr");
            if (cidr.empty() || (v6 && !static_ipv6(*vlan))) continue;
            try {
                const auto prefix = config::NetworkPrefix::parse(cidr, v6);
                const auto text = prefix.address() + "/" + std::to_string(prefix.prefix());
                addresses.append(text);
                entries.append(address_entry(text, vid, true, "configured"));
            } catch (const std::exception&) {}
        }
    }
    data["pd"] = Json::Value(Json::arrayValue);
    auto get = [&](const std::string& path) {
        try { const auto response = call(HttpMethod::get, path); if (response.success()) return wire::parse(response.body); }
        catch (const std::exception&) {}
        return Json::Value();
    };
    auto& interfaces = data["live_interfaces"] = Json::Value(Json::arrayValue);
    for (const auto& port : get("/api/v1/ports")) {
        if (!port.isObject()) continue;
        Json::Value row;
        row["name"] = config::string(port, "identifier");
        row["state"] = config::boolean(port, "online") ? "UP" : "DOWN";
        row["vlan"] = port.isMember("vlan") ? port["vlan"] : Json::Value();
        interfaces.append(std::move(row));
    }
    auto& neighbors = data["neighbors"] = Json::Value(Json::arrayValue);
    for (const auto& entry : get("/api/v1/fdb")) {
        if (!entry.isObject()) continue;
        Json::Value row;
        row["lladdr"] = config::string(entry, "mac"); row["dev"] = config::string(entry, "port"); row["dst"] = "";
        row["state"].append(config::boolean(entry, "static") ? "STATIC" : "LEARNED");
        neighbors.append(std::move(row));
    }
    try { data["dhcp_leases"] = dhcp_leases(); } catch (const std::exception&) { data["dhcp_leases"] = Json::Value(); }
    if (!data["dhcp_leases"].isArray()) data["dhcp_leases"] = Json::Value(Json::arrayValue);
    const auto status = process_.status();
    data["gvswitch_exit_code"] = status.exit_code.value_or(-1);
    data["gvswitch_socket"] = socket_;
}
Json::Value Gvswitch::dhcp_leases() const {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    auto get = [&](const std::string& path) {
        ControlOptions options;
        options.timeout = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        if (options.timeout.count() <= 0) throw std::runtime_error("DHCP lease observation timed out");
        const auto response = call(HttpMethod::get, path, nullptr, std::move(options));
        if (!response.success()) throw std::runtime_error("DHCP lease observation unavailable");
        const auto rows = wire::parse(response.body);
        if (!rows.isArray()) throw std::runtime_error("Invalid DHCP lease observation");
        return rows;
    };
    Json::Value leases(Json::arrayValue);
    const auto vlans = l3_vlans(config_);
    if (!healthy() || vlans.size() > 16) return {};
    for (const auto* vlan : vlans) {
        const int vid = static_cast<int>(config::integer(*vlan, "vlan_id"));
        for (const char* family : {"dhcp4", "dhcp6"}) {
            if (!config::boolean(config::member(config::member(*vlan, std::string(family) == "dhcp6" ? "ipv6" : "ipv4"), "dhcp"), "enabled")) continue;
            for (const auto& lease : get("/api/v1/gateways/" + std::to_string(vid) + "/" + family + "/leases")) {
                if (!lease.isObject()) continue;
                if (leases.size() >= 4096) return {};
                Json::Value row;
                row["ip"] = config::string(lease, "ip"); row["mac"] = config::string(lease, "mac");
                row["hostname"] = config::string(lease, "port_identifier"); row["expires"] = config::string(lease, "expires_at");
                row["vlan"] = vid;
                leases.append(std::move(row));
            }
        }
    }
    return leases;
}
Json::Value Gvswitch::forward_failures() const {
    Json::Value result(Json::objectValue);
    for (const auto& [tap, rows] : failures_) for (const auto& row : rows) result[tap].append(row);
    return result;
}
}
