// SPDX-License-Identifier: GPL-3.0-or-later
#include "vm_config.h"
#include "common/identity.h"
#include "common/wire.h"
#include "store/network_config.h"
#include "store/vm_config.h"
#include <set>
#include <map>

namespace droidvm {
namespace {
void access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || caller.principal.empty())
        throw ServiceError(ErrorCode::permission_denied, "Administrator permission required");
}
}
Json::Value VmConfigService::normalize(Json::Value document) {
    if (!document.isObject()) throw ServiceError(ErrorCode::invalid_argument, "Invalid VM configuration document");
    // DataStore treats an absent list as empty; a supplied malformed list must
    // not silently erase an inventory during migration.
    if (!document.isMember("vms")) document["vms"] = Json::Value(Json::arrayValue);
    auto& rows = document["vms"];
    if (!rows.isArray()) throw ServiceError(ErrorCode::invalid_argument, "Invalid VM configuration list");
    try { config::encode_json(document, max_bytes); }
    catch (const std::exception&) { throw ServiceError(ErrorCode::resource_exhausted, "VM configuration storage limit exceeded"); }
    std::set<std::string> ids, names;
    for (auto& row : rows) {
        try {
            auto migrated = config::migrate_vm(row);
            auto id = config::uuid(migrated);
            const auto& name = config::member(migrated, "name");
            if (!name.isString()) throw std::invalid_argument("Missing name");
            if (!ids.insert(id).second || !names.insert(name.asString()).second)
                throw ServiceError(ErrorCode::conflict, "Duplicate VM ID or name");
            migrated["id"] = std::move(id);
            row = std::move(migrated);
        } catch (const std::invalid_argument&) {
            throw ServiceError(ErrorCode::invalid_argument, "Invalid VM configuration entry");
        }
    }
    try { return wire::parse(config::encode_json(document, max_bytes)); }
    catch (const std::exception&) { throw ServiceError(ErrorCode::resource_exhausted, "VM configuration storage limit exceeded"); }
}
VmConfigService::VmConfigService(int directory, uid_t owner, config::JsonFile::Observer observer, Prepare prepare)
    : file_(directory, "vms.json", owner, std::move(observer), max_bytes, config::JsonSyntax::strict), prepare_(std::move(prepare)) {
    auto loaded = file_.load();
    auto initial = std::make_shared<VmConfigSnapshot>();
    initial->document = normalize(loaded ? std::move(loaded->value) : Json::Value(Json::objectValue));
    initial->revision = random_id(true);
    initial->recovered = loaded && loaded->recovered;
    initial->persisted = loaded.has_value();
    initial->durability_uncertain = loaded.has_value();
    auto update = prepare_ ? prepare_(initial->document) : nullptr;
    if (update) update->commit();
    state_ = std::move(initial);
}
VmConfigService::Snapshot VmConfigService::state() const {
    std::lock_guard lock(state_mutex_);
    return state_;
}
void VmConfigService::publish(Snapshot next) {
    std::lock_guard lock(state_mutex_);
    state_ = std::move(next);
}
VmConfigService::Snapshot VmConfigService::snapshot(const CallContext& caller) const {
    access(caller);
    return state();
}
VmConfigService::Snapshot VmConfigService::apply(const CallContext& caller,
        const std::string& expected_revision, const Json::Value& operations) {
    access(caller);
    if (expected_revision.empty() || expected_revision.size() > 128)
        throw ServiceError(ErrorCode::invalid_argument, "Missing or invalid VM configuration revision");
    const auto previous = state();
    if (previous->revision != expected_revision)
        throw ServiceError(ErrorCode::conflict, "VM configuration changed; reload before saving");
    if (!operations.isArray()) throw ServiceError(ErrorCode::invalid_argument, "VM operations must be an array");
    try { config::encode_json(operations, max_bytes); }
    catch (const std::exception&) { throw ServiceError(ErrorCode::resource_exhausted, "VM operation storage limit exceeded"); }
    std::map<std::string, Json::ArrayIndex> positions;
    const auto& original = previous->document["vms"];
    for (Json::ArrayIndex i = 0; i < original.size(); ++i) positions.emplace(config::uuid(original[i]), i);
    std::set<std::string> touched, deleted;
    auto document = previous->document;
    auto& rows = document["vms"];
    for (const auto& operation : operations) {
        if (!operation.isObject() || !operation["op"].isString())
            throw ServiceError(ErrorCode::invalid_argument, "Invalid VM operation");
        const auto kind = operation["op"].asString();
        if (kind != "create" && kind != "replace" && kind != "delete")
            throw ServiceError(ErrorCode::invalid_argument, "Unknown VM operation");
        // Reject ambiguous/typo fields instead of silently dropping an edit.
        for (const auto& key : operation.getMemberNames())
            if (key != "op" && key != (kind == "delete" ? "id" : "config"))
                throw ServiceError(ErrorCode::invalid_argument, "Unexpected VM operation field");
        std::string id;
        Json::Value value;
        try {
            value = kind == "delete" ? operation : operation["config"];
            // Require an explicit target, even if legacy migration can invent one.
            id = config::uuid(value);
            if (kind != "delete") { value = config::migrate_vm(std::move(value)); value["id"] = id; }
        } catch (const std::invalid_argument&) {
            throw ServiceError(ErrorCode::invalid_argument, "Invalid VM operation target or configuration");
        }
        if (!touched.insert(id).second) throw ServiceError(ErrorCode::invalid_argument, "Repeated VM operation target");
        const auto found = positions.find(id);
        if (kind == "create") {
            if (found != positions.end()) throw ServiceError(ErrorCode::conflict, "VM already exists");
            rows.append(std::move(value));
        } else {
            if (found == positions.end()) throw ServiceError(ErrorCode::not_found, "VM not found");
            if (kind == "delete") deleted.insert(id);
            else rows[found->second] = std::move(value);
        }
    }
    if (!deleted.empty()) {
        Json::Value kept(Json::arrayValue);
        for (auto& row : rows) if (!deleted.contains(config::uuid(row))) kept.append(std::move(row));
        rows = std::move(kept);
    }
    // Recheck the original revision under the existing writer lock. No retry
    // against a newer document: even disjoint stale edits must report conflict.
    return replace(caller, expected_revision, std::move(document));
}
VmConfigService::Snapshot VmConfigService::replace(const CallContext& caller,
        const std::string& expected_revision, Json::Value document) {
    access(caller);
    if (expected_revision.empty() || expected_revision.size() > 128)
        throw ServiceError(ErrorCode::invalid_argument, "Missing or invalid VM configuration revision");
    // Check again after normalization: another writer may have committed while
    // the expensive migration/encoding ran. Stale clients never touch disk.
    if (state()->revision != expected_revision)
        throw ServiceError(ErrorCode::conflict, "VM configuration changed; reload before saving");
    if (!document.isObject() || !document.isMember("vms") || !document["vms"].isArray())
        throw ServiceError(ErrorCode::invalid_argument, "A complete VM configuration list is required");
    auto next = std::make_shared<VmConfigSnapshot>();
    next->document = normalize(std::move(document));
    next->revision = random_id(true);
    next->persisted = true;
    std::lock_guard writer(writer_mutex_);
    const auto previous = state();
    if (previous->revision != expected_revision)
        throw ServiceError(ErrorCode::conflict, "VM configuration changed; reload before saving");
    if (next->document == previous->document && previous->persisted && !previous->recovered && !previous->durability_uncertain)
        return previous;
    auto update = prepare_ ? prepare_(next->document) : nullptr;
    try { file_.save(next->document); }
    catch (const config::CommitError& error) {
        if (error.installed) {
            next->durability_uncertain = true;
            if (update) update->commit();
            publish(next);
        }
        throw ServiceError(error.installed ? ErrorCode::commit_uncertain : ErrorCode::io_error,
            error.installed ? "VM configuration installed; durability could not be confirmed" : "VM configuration could not be saved");
    } catch (const std::exception&) { throw ServiceError(ErrorCode::io_error, "VM configuration could not be saved"); }
    if (update) update->commit();
    publish(next);
    return next;
}
}
