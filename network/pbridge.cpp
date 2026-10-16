// SPDX-License-Identifier: GPL-3.0-or-later
#include "pbridge.h"
#include "host_discovery.h"
#include "links.h"
#include "runtime/helper_identity.h"
#include "services/context.h"
#include "common/wire.h"
#include <climits>
#include <net/if.h>
#include <set>
#include <thread>
#include <unistd.h>

namespace droidvm::network {
namespace {
[[noreturn]] void invalid(const char* detail) { throw ServiceError(ErrorCode::io_error, detail); }
std::string master_of(const std::string& link) {
    char target[PATH_MAX];
    const auto length = readlink(("/sys/class/net/" + link + "/master").c_str(), target, sizeof(target) - 1);
    if (length <= 0) return {};
    const std::string path(target, static_cast<size_t>(length));
    return path.substr(path.rfind('/') + 1);
}
}
PbridgeOwnership::PbridgeOwnership(int directory, uid_t uid, const Netbox& netbox)
    : netbox_(netbox), file_(directory, "network-pbridge.json", uid) {
    const auto loaded = file_.load();
    if (loaded && loaded->recovered) invalid("pbridge primary is damaged; recovery requires latest inventory");
    document_ = loaded ? loaded->value : Json::Value(Json::objectValue);
    if (!loaded) { document_["schema"] = 1; document_["entries"] = Json::Value(Json::arrayValue); }
    if (document_["schema"] != 1 || !document_["entries"].isArray() || document_["entries"].size() > 1024) invalid("invalid pbridge inventory");
    for (const auto& row : document_["entries"])
        if (!row.isObject() || !row["owner"].isString() || row["owner"].asString().empty() || !row["uplink"].isString() ||
            !row["fwd0"].isString() || !row["fwd1"].isString() || !row["scope"].isObject())
            invalid("invalid pbridge ownership record");
}
void PbridgeOwnership::save(Json::Value next) {
    try { file_.save(next); }
    catch (const config::CommitError& error) { if (error.installed) document_ = std::move(next); throw; }
    document_ = std::move(next);
}
std::string PbridgeOwnership::kind(const std::string& link) const {
    for (const auto& row : netbox_.links()) if (row["ifname"] == link) return row["kind"].asString().empty() ? "?" : row["kind"].asString();
    return {};
}
void PbridgeOwnership::acquire(const std::string& owner, const std::string& uplink, const std::string& fwd0, const std::string& fwd1) {
    for (const auto* name : {&uplink, &fwd0, &fwd1}) Netbox::interface_name(*name);
    if (owner.empty() || fwd0 == fwd1) throw ServiceError(ErrorCode::invalid_argument, "invalid pbridge ownership request");
    std::lock_guard guard(mutex_);
    for (const auto& row : document_["entries"])
        if (row["owner"] == owner || row["fwd0"] == fwd0 || row["fwd1"] == fwd1)
            throw ServiceError(ErrorCode::conflict, "pbridge resources require cleanup before start");
    // pbridge adopts an existing pair (EEXIST is success), so any link with
    // these names would silently become ours.
    for (const auto* name : {&fwd0, &fwd1})
        if (!kind(*name).empty()) throw ServiceError(ErrorCode::conflict, "pbridge interface already exists: " + *name);
    auto next = document_;
    Json::Value row; row["owner"] = owner; row["uplink"] = uplink; row["fwd0"] = fwd0; row["fwd1"] = fwd1; row["scope"] = network_scope();
    next["entries"].append(std::move(row));
    save(std::move(next));
}
void PbridgeOwnership::release_locked(const std::string* owner) {
    const auto scope = network_scope();
    Json::Value kept(Json::arrayValue);
    std::set<std::string> uplinks;
    bool any = false;
    for (const auto& row : document_["entries"]) {
        if (owner && row["owner"] != *owner) { kept.append(row); continue; }
        any = true;
        if (row["scope"]["boot"] != scope["boot"]) continue; // died with that boot
        if (!same_scope(row["scope"], scope)) throw ServiceError(ErrorCode::conflict, "pbridge record belongs to another network namespace");
        uplinks.insert(row["uplink"].asString());
        // Deleting either end removes the pair and frees fwd1's bridge port.
        for (const char* end : {"fwd0", "fwd1"}) {
            const auto name = row[end].asString(), type = kind(name);
            if (type.empty()) continue;
            if (type != "veth") throw ServiceError(ErrorCode::conflict, "pbridge interface " + name + " is not a veth");
            netbox_.delete_link(name);
        }
        for (const char* end : {"fwd0", "fwd1"})
            if (!kind(row[end].asString()).empty()) throw ServiceError(ErrorCode::io_error, "pbridge veth still exists");
    }
    if (!any) return;
    for (const auto& uplink : uplinks) {
        bool shared = false;
        for (const auto& row : kept) if (row["uplink"] == uplink) shared = true;
        // The magic metric is shared by every pbridge on this uplink, so only
        // its last user can tell that every proxy address is stale.
        if (shared || !if_nametoindex(uplink.c_str())) continue;
        for (const auto& row : netbox_.addresses(uplink, pbridge_offload_metric))
            netbox_.address(uplink, row["local"].asString() + "/" + std::to_string(row["prefixlen"].asUInt()), false);
        if (!netbox_.addresses(uplink, pbridge_offload_metric).empty()) throw ServiceError(ErrorCode::io_error, "pbridge proxy addresses remain");
    }
    // One clean helper exit deletes the shared rules; reassert them while any
    // other pbridge still needs host-originated traffic routed to its guests.
    for (const bool v6 : {false, true}) netbox_.rule("lo", vmroute_table, vmroute_priority, v6, !kept.empty());
    auto next = document_; next["entries"] = kept; save(std::move(next));
}
void PbridgeOwnership::release(const std::string& owner) { std::lock_guard guard(mutex_); release_locked(&owner); }
Json::Value PbridgeOwnership::recover_all() {
    std::lock_guard guard(mutex_);
    Json::Value failures(Json::arrayValue);
    try { release_locked(nullptr); }
    catch (const std::exception& error) { Json::Value row; row["error"] = error.what(); failures.append(std::move(row)); }
    return failures;
}
Json::Value PbridgeOwnership::inventory() const { std::lock_guard guard(mutex_); return document_; }
Pbridge::Pbridge(std::string executable, SwitchRuntime& runtime) : executable_(std::move(executable)), runtime_(runtime) {
    if (executable_.empty() || executable_.front() != '/' || executable_.find('\0') != std::string::npos)
        throw std::invalid_argument("pbridge executable must be an absolute path");
}
Pbridge::~Pbridge() { try { stop(); } catch (...) {} }
void Pbridge::start(const std::string& owner, const std::string& uplink, const std::string& bridge,
                    const std::string& fwd0, const std::string& fwd1) {
    if (!allocation_.name.empty() || process_.status().running) throw ServiceError(ErrorCode::conflict, "pbridge requires cleanup before start");
    try {
        runtime_.allocate(owner, allocation_, SwitchRuntime::Kind::pbridge);
        ChildOptions options;
        // Legacy LinuxBridgeBackend arguments plus explicit per-network veth
        // names, so networks sharing an uplink never adopt each other's pair.
        options.argv = {executable_, "-i", uplink, "-e", "ebpf", "-m", "fwd-with-offload", "-b", bridge,
            "--fwd-device-if", fwd0, "--fwd-device-br", fwd1, "--offload-workaround", "v4,v6",
            "--offload-workaround-magic", std::to_string(pbridge_offload_metric), "--arp-keepalive", "10", "--loglevel", "info"};
        HelperIdentity identity(allocation_.directory.get(), runtime_.owner()); identity.arm(options);
        process_.start(options);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (master_of(fwd1) != bridge) {
            if (!process_.status().running) throw ServiceError(ErrorCode::unavailable, "pbridge exited before attaching to the bridge");
            if (std::chrono::steady_clock::now() > deadline) throw ServiceError(ErrorCode::unavailable, "pbridge did not attach to the bridge");
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        ready_ = true;
    } catch (const std::exception& error) {
        const std::string detail = error.what();
        try { stop(); }
        catch (const std::exception& cleanup) { throw ServiceError(ErrorCode::io_error, detail + "; cleanup: " + cleanup.what()); }
        throw;
    }
}
void Pbridge::stop() {
    ready_ = false; process_.stop();
    if (process_.status().running) throw std::runtime_error("pbridge did not stop");
    if (!allocation_.name.empty()) {
        runtime_.cleanup(allocation_.name);
        allocation_.directory = Fd(); allocation_.name.clear();
    }
}
Json::Value Pbridge::tools() const {
    Json::Value rows(Json::arrayValue), row;
    const auto status = process_.status();
    row["key"] = "pbridge"; row["running"] = status.running; row["generation"] = std::to_string(status.generation);
    rows.append(std::move(row)); return rows;
}
Json::Value Pbridge::tool_log() const {
    Json::Value rows(Json::arrayValue);
    for (const auto& line : process_.log()) rows.append(line.text);
    return rows;
}
}
