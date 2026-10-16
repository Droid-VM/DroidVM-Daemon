// SPDX-License-Identifier: GPL-3.0-or-later
#include "disk_config.h"
#include "tasks.h"
#include "common/identity.h"
#include "store/network_config.h"
#include "store/vm_ownership.h"
#include <set>

namespace droidvm {
namespace {
void access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || caller.principal.empty())
        throw ServiceError(ErrorCode::permission_denied, "Administrator permission required");
}
std::shared_ptr<const std::string> encode(const Json::Value& document) {
    const auto bytes = config::encode_json(document, DiskConfigService::max_bytes);
    return std::make_shared<const std::string>(bytes.data(), bytes.size());
}
}
Json::Value DiskConfigService::normalize(Json::Value document) {
    if (!document.isObject() || !document["disks"].isArray())
        throw ServiceError(ErrorCode::invalid_argument, "A complete disk registry is required");
    // Match DiskStore: IDs unique, names may repeat across folders. Parent and
    // folder fields remain opaque here: historical broken links and future
    // fields must survive reads. The operation coordinator validates changes
    // against actual image paths/headers and VM references, not guessed paths.
    std::set<std::string> ids;
    for (auto& row : document["disks"]) {
        try {
            const auto id = config::uuid(row);
            if (!config::member(row, "name").isString()) throw std::invalid_argument("Missing disk name");
            if (!ids.insert(id).second) throw ServiceError(ErrorCode::conflict, "Duplicate disk ID");
            row["id"] = id;
        } catch (const std::invalid_argument&) {
            throw ServiceError(ErrorCode::invalid_argument, "Invalid disk registry entry");
        }
    }
    try { return config::parse_json(config::encode_json(document, max_bytes)); }
    catch (const std::exception&) { throw ServiceError(ErrorCode::resource_exhausted, "Disk registry storage limit exceeded"); }
}
DiskConfigService::DiskConfigService(int directory, uid_t owner, config::JsonFile::Observer observer,
        std::shared_ptr<ConfigurationGate> gate, Prepare prepare, TaskService* events)
    : file_(directory, "disks.json", owner, std::move(observer), max_bytes, config::JsonSyntax::strict),
      gate_(std::move(gate)), prepare_(std::move(prepare)), events_(events) {
    if (events_ && events_->config_gate_ != gate_)
        throw std::invalid_argument("Disk registry and events must share one configuration gate");
    config::claim_disk_config(directory, owner);
    auto loaded = file_.load();
    Json::Value empty; empty["disks"] = Json::Value(Json::arrayValue);
    auto initial = std::make_shared<DiskConfigSnapshot>();
    initial->document = normalize(loaded ? loaded->value : std::move(empty));
    initial->encoded = encode(initial->document);
    initial->revision = random_id(true);
    initial->persisted = loaded.has_value();
    initial->recovered = loaded && loaded->recovered;
    initial->durability_uncertain = loaded.has_value();
    publish(std::move(initial));
}
DiskConfigService::Snapshot DiskConfigService::state() const {
    std::lock_guard lock(state_mutex_);
    return state_;
}
void DiskConfigService::publish(Snapshot next) {
    std::lock_guard lock(state_mutex_);
    state_ = std::move(next);
    if (events_) events_->publish_disk_config(state_);
}
DiskConfigService::Snapshot DiskConfigService::snapshot(const CallContext& caller) const {
    access(caller);
    auto admission = ConfigurationGate::enter(gate_);
    return state();
}
DiskConfigService::Snapshot DiskConfigService::replace(const CallContext& caller, const std::string& revision, Json::Value document) {
    access(caller);
    auto admission = ConfigurationGate::enter(gate_);
    if (revision.empty() || revision.size() > 128)
        throw ServiceError(ErrorCode::invalid_argument, "Missing or invalid disk registry revision");
    if (state()->revision != revision)
        throw ServiceError(ErrorCode::conflict, "Disk registry changed; reload before saving");
    auto next = std::make_shared<DiskConfigSnapshot>();
    next->document = normalize(std::move(document));
    next->encoded = encode(next->document);
    next->revision = random_id(true);
    next->persisted = true;
    std::lock_guard writer(writer_mutex_);
    const auto before = state();
    if (before->revision != revision)
        throw ServiceError(ErrorCode::conflict, "Disk registry changed; reload before saving");
    if (next->document == before->document && before->persisted && !before->recovered && !before->durability_uncertain)
        return before;
    auto participant = prepare_ ? prepare_(before->document, next->document) : nullptr;
    try { file_.save(next->document); }
    catch (const config::CommitError& error) {
        if (error.installed) {
            next->durability_uncertain = true;
            if (participant) participant->commit();
            publish(next);
        }
        throw ServiceError(error.installed ? ErrorCode::commit_uncertain : ErrorCode::io_error,
            error.installed ? "Disk registry installed; durability could not be confirmed" : "Disk registry could not be saved");
    } catch (const std::exception&) { throw ServiceError(ErrorCode::io_error, "Disk registry could not be saved"); }
    if (participant) participant->commit();
    publish(next);
    return next;
}
}
