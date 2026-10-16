// SPDX-License-Identifier: GPL-3.0-or-later
#include "bridgedhcp.h"
#include "helper_ready.h"
#include "runtime/helper_identity.h"
#include "common/identity.h"
#include "common/wire.h"
#include "services/context.h"
#include "store/network_config.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <system_error>

namespace droidvm::network {
namespace {
void require(bool ok, const char* detail) { if (!ok) throw std::system_error(errno, std::generic_category(), detail); }
std::string fd_path(int fd) { return "/proc/" + std::to_string(getpid()) + "/fd/" + std::to_string(fd); }
}
BridgeDhcp::BridgeDhcp(std::string executable, SwitchRuntime& runtime, int state_directory)
    : executable_(std::move(executable)), runtime_(runtime), state_directory_(fcntl(state_directory, F_DUPFD_CLOEXEC, 3)) {
    if (executable_.empty() || executable_.front() != '/' || executable_.find('\0') != std::string::npos)
        throw std::invalid_argument("bridgedhcp executable must be an absolute path");
    struct stat info{};
    require(state_directory_.get() >= 0 && fstat(state_directory_.get(), &info) == 0, "hold DHCP state directory");
    // Android app directories are 0771 with the app's own group; only a foreign
    // writer (world, or a group other than the app's) breaks privacy.
    if (!S_ISDIR(info.st_mode) || info.st_uid != runtime.owner() || (info.st_mode & 0002) ||
        ((info.st_mode & 0020) && info.st_gid != runtime.owner()))
        throw std::invalid_argument("DHCP state directory must be private to its owner");
}
BridgeDhcp::~BridgeDhcp() { try { stop(); } catch (...) {} }
std::string BridgeDhcp::state_file(const Json::Value& network) { return "dhcp-" + config::uuid(network) + ".json"; }
bool BridgeDhcp::start(Json::Value network, std::map<int, DhcpStatics> statics, std::map<int, std::string> uplinks) {
    if (!allocation_.name.empty() || process_.status().running) throw ServiceError(ErrorCode::conflict, "DHCP helper requires cleanup before start");
    const auto state_name = state_file(network);
    const auto persistent = fd_path(state_directory_.get()) + "/" + state_name;
    // Validate before allocating a directory or starting any kernel service.
    auto plan = bridgedhcp_config(network, {"/pending/s", "/pending/key", persistent}, uplinks, statics);
    if (config::string(network, "bridge_type") == "gvisor") throw ServiceError(ErrorCode::invalid_argument, "bridgedhcp requires Linux topology");
    std::map<int, std::string> pd_devices;
    for (const auto& vlan : linux_plan(network).vlans) if (vlan.pd) pd_devices.emplace(vlan.id, vlan.device);
    pd_.reset(std::move(pd_devices));
    if (!plan.needed) { network_ = std::move(network); statics_ = std::move(statics); uplinks_ = std::move(uplinks); return false; }
    struct stat info{};
    if (fstatat(state_directory_.get(), state_name.c_str(), &info, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISREG(info.st_mode) || info.st_nlink != 1 || (info.st_uid != runtime_.owner() && info.st_uid != geteuid()) || (info.st_mode & 0022))
            throw ServiceError(ErrorCode::conflict, "DHCP state file identity or permissions changed");
    } else require(errno == ENOENT, "inspect DHCP state file");
    network_ = std::move(network); statics_ = std::move(statics); uplinks_ = std::move(uplinks);
    try {
        runtime_.allocate(config::uuid(network_), allocation_, SwitchRuntime::Kind::bridgedhcp);
        const auto path = fd_path(allocation_.directory.get());
        const auto token = random_id(false);
        Fd key(openat(allocation_.directory.get(), "api.key", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
        require(key.get() >= 0 && fchown(key.get(), runtime_.owner(), runtime_.owner()) == 0 && fchmod(key.get(), 0600) == 0, "protect DHCP API key");
        size_t written = 0;
        while (written < token.size()) {
            const auto count = write(key.get(), token.data() + written, token.size() - written);
            if (count < 0 && errno == EINTR) continue;
            require(count > 0, "write DHCP API key"); written += static_cast<size_t>(count);
        }
        require(fsync(key.get()) == 0, "sync DHCP API key");
        plan = bridgedhcp_config(network_, {path + "/s", path + "/api.key", persistent}, uplinks_, statics_);
        config::JsonFile(allocation_.directory.get(), "config.json", runtime_.owner()).save(plan.config);
        devices_.clear();
        for (const auto& row : plan.config["interfaces"]) devices_.emplace(std::stoi(row["tag"].asString()), row["name"].asString());
        client_ = std::make_unique<ControlHttp>(path + "/s", token);
        ChildOptions options; options.argv = {executable_, "--config", path + "/config.json"};
        HelperIdentity identity(allocation_.directory.get(), runtime_.owner()); identity.arm(options);
        process_.start(options);
        await_helper(process_, *client_, "/v1/status", [&](const Json::Value& response) {
            if (!response.isObject() || !response["ifaces"].isArray() || response["ifaces"].size() != plan.config["interfaces"].size()) return false;
            for (const auto& expected : plan.config["interfaces"]) {
                bool found = false;
                for (const auto& actual : response["ifaces"]) if (actual["name"] == expected["name"] && actual["tag"] == expected["tag"]) {
                    found = actual["exists"] == true && actual["up"] == true &&
                        actual["dhcp4"] == expected.isMember("dhcp4") && actual["dhcp6"] == expected.isMember("dhcp6") &&
                        actual["slaac"] == expected.get("slaac", false);
                }
                if (!found) return false;
            }
            return true;
        });
        ready_ = true; return true;
    } catch (const std::exception& error) {
        const auto detail = std::string(error.what());
        try { stop(); }
        catch (const std::exception& cleanup) { throw ServiceError(ErrorCode::io_error, detail + "; cleanup: " + cleanup.what()); }
        throw;
    }
}
void BridgeDhcp::stop() {
    pd_.reset({});
    ready_ = false; process_.stop(); client_.reset();
    if (process_.status().running) throw std::runtime_error("DHCP helper did not stop");
    if (!allocation_.name.empty()) {
        runtime_.cleanup(allocation_.name);
        allocation_.directory = Fd(); allocation_.name.clear();
    }
    devices_.clear();
}
void BridgeDhcp::restart() {
    if (network_.isNull()) throw ServiceError(ErrorCode::conflict, "DHCP helper has no restart configuration");
    const auto network = network_; const auto statics = statics_; const auto uplinks = uplinks_;
    stop(); start(network, statics, uplinks);
}
std::string BridgeDhcp::endpoint(int vlan) const {
    const auto at = devices_.find(vlan);
    if (at == devices_.end()) throw ServiceError(ErrorCode::not_found, "DHCP VLAN not available");
    return "/v1/ifaces/" + ControlHttp::component(at->second);
}
Json::Value BridgeDhcp::request(HttpMethod method, const std::string& path, std::optional<std::string_view> body) const {
    if (!healthy() || !client_) throw ServiceError(ErrorCode::unavailable, "DHCP helper is not ready");
    const auto response = client_->request(method, path, body);
    if (!response.success()) throw ServiceError(ErrorCode::unavailable, "DHCP control request failed with HTTP " + std::to_string(response.code));
    return response.body.empty() ? Json::Value() : wire::parse(response.body);
}
Json::Value BridgeDhcp::status() const { return request(HttpMethod::get, "/v1/status"); }
Json::Value BridgeDhcp::leases(int vlan, bool ipv6) const { return request(HttpMethod::get, endpoint(vlan) + (ipv6 ? "/leases/6" : "/leases/4")); }
PdSnapshot BridgeDhcp::poll_pd(bool force) {
    if (!healthy()) throw ServiceError(ErrorCode::unavailable, "DHCP helper is not ready");
    return pd_.poll(process_.take_output(), [&] { return status(); }, force);
}
void BridgeDhcp::set_statics(int vlan, DhcpStatics statics) {
    const auto path = endpoint(vlan);
    auto desired = statics_; desired[vlan] = std::move(statics);
    bridgedhcp_config(network_, {"/pending/s", "/pending/key", "/pending/state"}, uplinks_, desired);
    // Both operations are idempotent. Retain the validated desired set even
    // if a disconnect makes a PUT's outcome uncertain, for restart/retry.
    statics_ = std::move(desired);
    for (const bool ipv6 : {false, true}) {
        Json::Value body; body["statics"] = ipv6 ? statics_.at(vlan).ipv6 : statics_.at(vlan).ipv4;
        request(HttpMethod::put, path + (ipv6 ? "/statics/6" : "/statics/4"), wire::stringify(body));
    }
}
bool BridgeDhcp::pd_action(int vlan, bool release) {
    try { request(HttpMethod::post, endpoint(vlan) + (release ? "/pd/release" : "/pd/renew")); return true; }
    catch (const std::exception&) { return false; }
}
Json::Value BridgeDhcp::tools() const {
    Json::Value rows(Json::arrayValue), row;
    const auto status = process_.status();
    row["key"] = "bridgedhcp"; row["running"] = status.running; row["generation"] = std::to_string(status.generation);
    rows.append(std::move(row)); return rows;
}
Json::Value BridgeDhcp::tool_log() const {
    Json::Value rows(Json::arrayValue);
    for (const auto& line : process_.log()) rows.append(line.text);
    return rows;
}
}
