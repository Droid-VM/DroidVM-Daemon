// SPDX-License-Identifier: GPL-3.0-or-later
#include "netbox.h"
#include "link_attributes.h"
#include "services/context.h"
#include <memory>
#include <system_error>

namespace droidvm::network {
namespace {
void argument(const std::string& value, size_t limit = 256) {
    if (value.empty() || value.size() > limit || value.front() == '-' || value.find('\0') != std::string::npos)
        throw ServiceError(ErrorCode::invalid_argument, "invalid netbox argument");
}
std::vector<std::string> host_args(const char* command, const std::vector<std::string>& prefixes,
                                  std::optional<uint32_t> metric) {
    if (prefixes.size() > 64) throw ServiceError(ErrorCode::invalid_argument, "too many host interface prefixes");
    std::vector<std::string> args{command};
    for (const auto& prefix : prefixes) {
        Netbox::interface_name(prefix);
        args.insert(args.end(), {"--iface", prefix});
    }
    if (metric) args.insert(args.end(), {"--exclude-metric", std::to_string(*metric)});
    return args;
}
}
Netbox::Netbox(std::string executable, std::chrono::milliseconds timeout, size_t capture_bytes)
    : executable_(std::move(executable)), timeout_(timeout), capture_bytes_(capture_bytes) {
    if (executable_.empty() || executable_.front() != '/' || executable_.find('\0') != std::string::npos ||
        timeout_.count() <= 0 || timeout_ > std::chrono::seconds(30) || !capture_bytes_ || capture_bytes_ > (4u << 20))
        throw std::invalid_argument("invalid netbox path or budget");
}
void Netbox::interface_name(const std::string& name) {
    argument(name, 15);
    if (name == "." || name == ".." || name.find_first_not_of(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-") != std::string::npos)
        throw ServiceError(ErrorCode::invalid_argument, "invalid network interface name");
}
ChildOptions Netbox::command(std::vector<std::string> args) const {
    args.insert(args.begin(), executable_);
    ChildOptions options;
    options.argv = std::move(args);
    return options;
}
std::string Netbox::run(std::vector<std::string> args) const {
    const auto operation = args.front();
    ChildOutput result;
    try { result = Child(command(std::move(args))).communicate({}, timeout_, capture_bytes_); }
    catch (const std::system_error& error) {
        throw ServiceError(ErrorCode::io_error, "netbox " + operation + ": " + error.what());
    }
    if (result.timed_out) throw ServiceError(ErrorCode::unavailable, "netbox " + operation + " timed out; effect may have occurred");
    if (result.exit_code != 0) throw ServiceError(ErrorCode::io_error, "netbox " + operation + " exited " +
        std::to_string(result.exit_code) + ": " + result.error.substr(0, 4096));
    if (result.truncated) throw ServiceError(ErrorCode::resource_exhausted, "netbox " + operation + " output exceeded budget");
    return result.output;
}
Json::Value Netbox::query(std::vector<std::string> args, bool object) const {
    auto bytes = run(std::move(args));
    Json::CharReaderBuilder builder;
    builder["failIfExtra"] = true; builder["stackLimit"] = 32;
    builder["rejectDupKeys"] = true; builder["allowComments"] = false;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    Json::Value value;
    std::string error;
    bool valid = false;
    try { valid = reader->parse(bytes.data(), bytes.data() + bytes.size(), &value, &error); }
    catch (const Json::Exception&) {}
    if (!valid || (object ? !value.isObject() : !value.isArray()))
        throw ServiceError(ErrorCode::io_error, "invalid netbox JSON response");
    if (!object) for (const auto& row : value) if (!row.isObject())
        throw ServiceError(ErrorCode::io_error, "invalid netbox JSON row");
    return value;
}
void Netbox::add_bridge(const std::string& name) const { interface_name(name); run({"link-add-bridge", name}); }
void Netbox::add_tap(const std::string& name) const { interface_name(name); run({"link-add-tap", name}); }
void Netbox::add_vlan(const std::string& parent, const std::string& name, int vid) const {
    interface_name(parent); interface_name(name);
    if (vid < 1 || vid > 4094) throw ServiceError(ErrorCode::invalid_argument, "invalid tagged VLAN id");
    run({"link-add-vlan", "--link", parent, "--name", name, "--id", std::to_string(vid)});
}
void Netbox::delete_link(const std::string& name) const { interface_name(name); run({"link-del", name}); }
void Netbox::state(const std::string& name, bool up) const { interface_name(name); run({"link-set-state", name, up ? "up" : "down"}); }
void Netbox::master(const std::string& name, const std::string& bridge) const {
    interface_name(name); interface_name(bridge); run({"link-set-master", name, bridge});
}
void Netbox::nomaster(const std::string& name) const { interface_name(name); run({"link-set-nomaster", name}); }
void Netbox::mac(const std::string& name, const std::string& address) const {
    interface_name(name); argument(address); run({"link-set-mac", name, address});
}
void Netbox::toggle(const std::string& name, bool on, const char* operation, BridgeFlag flag) const {
    interface_name(name);
    try { run({operation, name, on ? "on" : "off"}); }
    catch (const ServiceError& error) {
        // Bundled netbox c8d6cc62... declares these positional bools as Clap
        // SetTrue plus an on/off value parser. Both explicit values and the
        // default false fail before reaching netlink. Do not mask kernel/tool
        // failures: only this exact CLI parser rejection permits the fallback.
        const auto prefix = "netbox " + std::string(operation) +
            " exited 2: error: 0 values required for '[ON]' but 1 was provided";
        if (error.code() != ErrorCode::io_error || !std::string_view(error.what()).starts_with(prefix)) throw;
        bridge_flag(name, flag, on);
    }
}
void Netbox::stp(const std::string& name, bool on) const { toggle(name, on, "link-set-stp", BridgeFlag::stp); }
void Netbox::isolated(const std::string& name, bool on) const { toggle(name, on, "link-set-isolated", BridgeFlag::isolated); }
void Netbox::locked(const std::string& name, bool on) const { toggle(name, on, "link-set-locked", BridgeFlag::locked); }
void Netbox::address(const std::string& name, const std::string& cidr, bool add) const {
    interface_name(name); argument(cidr); run({add ? "addr-add" : "addr-del", name, cidr});
}
void Netbox::route(const std::string& name, const std::string& destination, uint32_t table, bool v6) const {
    interface_name(name); argument(destination);
    std::vector<std::string> args{"route-add", "--dev", name, "--dst", destination, "--table", std::to_string(table)};
    if (v6) args.push_back("--v6");
    run(std::move(args));
}
void Netbox::rule(const std::string& name, uint32_t table, uint32_t priority, bool v6, bool add) const {
    interface_name(name);
    std::vector<std::string> args{add ? "rule-add" : "rule-del", "--iif", name, "--table", std::to_string(table),
                                  "--priority", std::to_string(priority)};
    if (v6) args.push_back("--v6");
    run(std::move(args));
}
void Netbox::fdb(const std::string& name, const std::string& address) const {
    interface_name(name); argument(address); run({"fdb-add", address, name});
}
Json::Value Netbox::links(const std::string& master, bool bridges_only) const {
    std::vector<std::string> args{"link-list"};
    if (!master.empty()) { interface_name(master); args.insert(args.end(), {"--master", master}); }
    if (bridges_only) args.push_back("--type-bridge");
    return query(std::move(args));
}
Json::Value Netbox::addresses(const std::string& name, std::optional<uint32_t> metric) const {
    std::vector<std::string> args{"addr-list"};
    if (!name.empty()) { interface_name(name); args.insert(args.end(), {"--dev", name}); }
    if (metric) args.insert(args.end(), {"--metric", std::to_string(*metric)});
    return query(std::move(args));
}
Json::Value Netbox::neighbors(const std::string& name) const { interface_name(name); return query({"neigh-list", name}); }
Json::Value Netbox::rules(bool v6) const { return query(v6 ? std::vector<std::string>{"rule-list", "--v6"} : std::vector<std::string>{"rule-list"}); }
Json::Value Netbox::host_ips(const std::vector<std::string>& prefixes, std::optional<uint32_t> metric) const {
    auto value = query(host_args("host-ips", prefixes, metric), true);
    if (!value["v4"].isArray()) throw ServiceError(ErrorCode::io_error, "invalid netbox host IP response");
    for (const auto& ip : value["v4"]) if (!ip.isString())
        throw ServiceError(ErrorCode::io_error, "invalid netbox host IP entry");
    return value;
}
ChildOptions Netbox::monitor(const std::vector<std::string>& prefixes, std::optional<uint32_t> metric) const {
    return command(host_args("monitor-addr", prefixes, metric));
}
}
