// SPDX-License-Identifier: GPL-3.0-or-later
#include "ports.h"
#include "links.h"
#include "services/context.h"
#include <climits>
#include <fstream>
#include <unistd.h>

namespace droidvm::network {
namespace {
[[noreturn]] void invalid(const char* detail) { throw ServiceError(ErrorCode::io_error, detail); }
}
OwnedPorts::OwnedPorts(int directory, uid_t uid, const Netbox& netbox, std::string sysfs)
    : netbox_(netbox), file_(directory, "network-ports.json", uid), sysfs_(std::move(sysfs)) {
    const auto loaded = file_.load();
    if (loaded && loaded->recovered) invalid("network port primary is damaged; recovery requires latest inventory");
    document_ = loaded ? loaded->value : Json::Value(Json::objectValue);
    if (!loaded) { document_["schema"] = 1; document_["ports"] = Json::Value(Json::arrayValue); }
    if (document_["schema"] != 1 || !document_["ports"].isArray() || document_["ports"].size() > 1024) invalid("invalid port inventory");
    for (const auto& row : document_["ports"])
        if (!row.isObject() || !row["owner"].isString() || row["owner"].asString().empty() || !row["port"].isString() ||
            !row["bridge"].isString() || !row["index"].isUInt() || !row["index"].asUInt() || !row["scope"].isObject())
            invalid("invalid port ownership record");
}
void OwnedPorts::save(Json::Value next) {
    try { file_.save(next); }
    catch (const config::CommitError& error) { if (error.installed) document_ = std::move(next); throw; }
    document_ = std::move(next);
}
uint32_t OwnedPorts::index(const std::string& port) const {
    std::ifstream file(sysfs_ + "/" + port + "/ifindex");
    uint64_t value = 0;
    return file >> value && value && value <= UINT32_MAX ? static_cast<uint32_t>(value) : 0;
}
std::string OwnedPorts::master(const std::string& port) const {
    char target[PATH_MAX];
    const auto length = readlink((sysfs_ + "/" + port + "/master").c_str(), target, sizeof(target) - 1);
    if (length <= 0) return {};
    const std::string path(target, static_cast<size_t>(length));
    return path.substr(path.rfind('/') + 1);
}
void OwnedPorts::attach(const std::string& owner, const std::string& port, const std::string& bridge) {
    Netbox::interface_name(port); Netbox::interface_name(bridge);
    if (owner.empty()) throw ServiceError(ErrorCode::invalid_argument, "port owner required");
    std::lock_guard guard(mutex_);
    const auto device = index(port);
    if (!device) throw ServiceError(ErrorCode::unavailable, "Uplink " + port + " not found");
    for (const auto& row : document_["ports"]) if (row["port"] == port) {
        if (row["owner"] == owner && row["bridge"] == bridge && row["index"].asUInt() == device && master(port) == bridge) return;
        throw ServiceError(ErrorCode::conflict, "Uplink " + port + " is already registered");
    }
    if (!master(port).empty()) throw ServiceError(ErrorCode::conflict, "Uplink " + port + " is already attached to " + master(port));
    auto next = document_;
    Json::Value row; row["owner"] = owner; row["port"] = port; row["bridge"] = bridge; row["index"] = device; row["scope"] = network_scope();
    next["ports"].append(std::move(row));
    save(std::move(next)); // durable before the uplink changes master
    netbox_.master(port, bridge);
    if (master(port) != bridge || index(port) != device)
        throw ServiceError(ErrorCode::unavailable, "Uplink " + port + " cannot be bridged (IFF_DONT_BRIDGE?); enable pseudo-bridge");
}
bool OwnedPorts::attached(const std::string& owner) const {
    std::lock_guard guard(mutex_);
    for (const auto& row : document_["ports"])
        if (row["owner"] == owner && (index(row["port"].asString()) != row["index"].asUInt() || master(row["port"].asString()) != row["bridge"].asString()))
            return false;
    return true;
}
void OwnedPorts::release_locked(const std::string* owner) {
    const auto scope = network_scope();
    Json::Value kept(Json::arrayValue);
    for (const auto& row : document_["ports"]) {
        if (owner && row["owner"] != *owner) { kept.append(row); continue; }
        if (row["scope"]["boot"] != scope["boot"]) continue; // that enslavement ended with its boot
        if (!same_scope(row["scope"], scope)) throw ServiceError(ErrorCode::conflict, "port record belongs to another network namespace");
        const auto port = row["port"].asString();
        // A recreated or reattached device is no longer the one we enslaved.
        if (index(port) == row["index"].asUInt() && master(port) == row["bridge"].asString()) {
            netbox_.nomaster(port);
            if (master(port) == row["bridge"].asString()) throw ServiceError(ErrorCode::io_error, "Uplink " + port + " is still attached");
        }
    }
    if (kept.size() == document_["ports"].size()) return;
    auto next = document_; next["ports"] = kept; save(std::move(next));
}
void OwnedPorts::release(const std::string& owner) { std::lock_guard guard(mutex_); release_locked(&owner); }
Json::Value OwnedPorts::recover_all() {
    std::lock_guard guard(mutex_);
    Json::Value failures(Json::arrayValue);
    try { release_locked(nullptr); }
    catch (const std::exception& error) { Json::Value row; row["error"] = error.what(); failures.append(std::move(row)); }
    return failures;
}
Json::Value OwnedPorts::inventory() const { std::lock_guard guard(mutex_); return document_; }
}
