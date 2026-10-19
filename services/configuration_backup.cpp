// SPDX-License-Identifier: GPL-3.0-or-later
#include "configuration_backup.h"
#include "vm_config_upload.h"
#include "build_metadata.h"
#include "store/network_config.h"
#include "store/vm_config.h"
#include "store/disk_config.h"
#include <chrono>
#include <ctime>
#include <map>
#include <set>

namespace droidvm {
namespace {
void access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || caller.principal.empty())
        throw ServiceError(ErrorCode::permission_denied, "Administrator permission required");
}
struct Prepared {
    Json::Value vms, disks, networks{Json::arrayValue}, summary;
    bool has_vms = false, has_disks = false, has_networks = false;
};
struct Exported {
    std::string bytes;
    std::shared_ptr<std::atomic<bool>> slot;
    ~Exported() { if (slot) slot->store(false); }
};
Json::Value revisions(const ConfigurationService::Snapshot& snapshot) {
    Json::Value result;
    result["vms"] = snapshot.vms->revision; result["disks"] = snapshot.disks->revision;
    result["networks"] = snapshot.networks.revision;
    return result;
}
Json::Value normalize_row(const Json::Value& original, std::string_view category) {
    try {
        if (!original.isObject()) throw std::invalid_argument("Configuration entry must be an object");
        auto row = original;
        if (category == "vms") row = config::migrate_vm(std::move(row));
        else if (category == "networks") {
            auto migrated = config::migrate_network(row);
            if (!migrated) throw std::invalid_argument("Unsupported network configuration schema");
            row = std::move(*migrated);
            config::validate_network(row);
            config::encode_json(row, 256u << 10);
        }
        row["id"] = config::uuid(row);
        if (!config::member(row, "name").isString()) throw std::invalid_argument("Configuration entry name is missing");
        return row;
    } catch (const std::invalid_argument& error) { throw ServiceError(ErrorCode::invalid_argument, error.what()); }
    catch (const std::length_error&) { throw ServiceError(ErrorCode::resource_exhausted, "Backup configuration entry is too large"); }
}
void bounded(const Json::Value& document, size_t maximum) {
    try { config::encode_json(document, maximum); }
    catch (const std::exception&) { throw ServiceError(ErrorCode::resource_exhausted, "Merged backup exceeds configuration storage limit"); }
}
Prepared prepare(std::string_view bytes, const ConfigurationService::Snapshot& snapshot) {
    if (bytes.empty() || bytes.size() > ConfigUploads::max_backup_bytes)
        throw ServiceError(ErrorCode::invalid_argument, "Invalid backup size");
    Json::Value input;
    try { input = config::parse_json(bytes); }
    catch (const std::exception&) { throw ServiceError(ErrorCode::invalid_argument, "Invalid configuration backup JSON"); }
    if (!input.isObject() || !input["version"].isUInt64() || input["version"].asUInt64() != 1)
        throw ServiceError(ErrorCode::invalid_argument, "Unsupported configuration backup version (expected 1)");
    Prepared result;
    result.has_vms = input.isMember("vms"); result.has_disks = input.isMember("disks"); result.has_networks = input.isMember("networks");
    if (!result.has_vms && !result.has_disks && !result.has_networks)
        throw ServiceError(ErrorCode::invalid_argument, "Backup contains no configuration categories");
    result.vms = snapshot.vms->document; result.disks = snapshot.disks->document;
    auto network_document = snapshot.networks.config;
    for (const auto* category : {"vms", "disks", "networks"}) {
        const bool present = input.isMember(category);
        auto& summary = result.summary[category];
        summary["present"] = present; summary["count"] = 0; summary["added"] = 0; summary["replaced"] = 0;
        if (!present) continue;
        if (!input[category].isArray()) throw ServiceError(ErrorCode::invalid_argument, "Backup categories must be arrays");
        auto& document = std::string_view(category) == "vms" ? result.vms :
            std::string_view(category) == "disks" ? result.disks : network_document;
        auto& rows = document[category];
        std::map<std::string, Json::ArrayIndex> indices;
        for (Json::ArrayIndex i = 0; i < rows.size(); ++i) {
            try {
                if (!indices.emplace(config::uuid(rows[i]), i).second)
                    throw ServiceError(ErrorCode::conflict, "Existing configuration has ambiguous IDs");
            } catch (const std::invalid_argument&) {
                // Inactive network rows without an actionable ID remain opaque.
                if (std::string_view(category) != "networks") throw;
            }
        }
        std::set<std::string> imported;
        Json::UInt added = 0, replaced = 0;
        for (const auto& original : input[category]) {
            auto row = normalize_row(original, category);
            const auto id = row["id"].asString();
            if (!imported.insert(id).second) throw ServiceError(ErrorCode::conflict, "Repeated backup configuration ID");
            const auto found = indices.find(id);
            if (std::string_view(category) == "networks") {
                Json::Value operation;
                if (found != indices.end()) {
                    if (config::schema(rows[found->second]) != 2)
                        throw ServiceError(ErrorCode::conflict, "Network ID is reserved by an inactive configuration");
                    operation["expected"] = rows[found->second];
                } else operation["expected"] = Json::Value();
                operation["config"] = row; result.networks.append(std::move(operation));
            }
            if (found == indices.end()) { rows.append(std::move(row)); ++added; }
            else { rows[found->second] = std::move(row); ++replaced; }
        }
        if (std::string_view(category) != "disks") {
            std::set<std::string> names;
            for (const auto& row : rows) {
                const auto& name = config::member(row, "name");
                if (name.isString() && !names.insert(name.asString()).second)
                    throw ServiceError(ErrorCode::conflict, "Backup configuration name is already reserved");
            }
        }
        summary["count"] = input[category].size(); summary["added"] = added; summary["replaced"] = replaced;
    }
    if (network_document["networks"].size() > 1024)
        throw ServiceError(ErrorCode::resource_exhausted, "Network configuration limit exceeded");
    bounded(result.vms, VmConfigService::max_bytes); bounded(result.disks, DiskConfigService::max_bytes);
    bounded(network_document, config::JsonFile::max_bytes); bounded(result.networks, NetworkConfigService::max_import_bytes);
    try { config::validate_disk_transition(snapshot.disks->document, result.disks); }
    catch (const std::invalid_argument& error) { throw ServiceError(ErrorCode::conflict, error.what()); }
    return result;
}
void failure(Json::Value& receipt, const std::string& stage, ErrorCode code, const char* message) {
    receipt["failedStage"] = stage;
    receipt["error"]["code"] = error_code_name(code); receipt["error"]["message"] = message;
    if (code == ErrorCode::commit_uncertain || (code == ErrorCode::internal && stage != "validation")) {
        receipt["uncertainStage"] = stage; receipt["recoveryRequired"] = true;
    }
}
}
std::shared_ptr<const std::string> ConfigurationBackup::export_file(const CallContext& caller) {
    access(caller);
    bool expected = false;
    if (!exporting_->compare_exchange_strong(expected, true))
        throw ServiceError(ErrorCode::resource_exhausted, "Another configuration backup download is still active");
    try {
        const auto snapshot = configuration_.snapshot(caller);
        Json::Value document;
        document["version"] = 1;
        const auto now = std::chrono::system_clock::now();
        document["timestamp"] = Json::Int64(std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count());
        const auto timestamp = std::chrono::system_clock::to_time_t(now);
        std::tm utc{}; gmtime_r(&timestamp, &utc);
        char date[32]{}; std::strftime(date, sizeof(date), "%Y-%m-%d_%H:%M:%S", &utc); document["date"] = date;
        document["app_version"] = DROIDVM_VERSION_NAME; document["app_version_name"] = DROIDVM_VERSION_NAME;
        document["app_version_code"] = DROIDVM_VERSION_CODE; document["app_build_type"] = DROIDVM_BUILD_TYPE;
        document["app_id"] = DROIDVM_PACKAGE_NAME;
        document["vms"] = snapshot.vms->document["vms"]; document["disks"] = snapshot.disks->document["disks"];
        document["networks"] = snapshot.networks.config["networks"];
        // Additional root metadata is ignored by the App v1 importer.
        document["revisions"] = revisions(snapshot);
        auto output = std::make_shared<Exported>();
        output->bytes = config::encode_json(document, max_export_bytes);
        // Alias construction cannot allocate/throw after transferring the slot.
        output->slot = exporting_;
        return std::shared_ptr<const std::string>(output, &output->bytes);
    } catch (...) { exporting_->store(false); throw; }
}
Json::Value ConfigurationBackup::preview(const CallContext& caller, std::string_view bytes) {
    access(caller);
    std::lock_guard work(import_mutex_);
    const auto snapshot = configuration_.snapshot(caller);
    auto prepared = prepare(bytes, snapshot);
    Json::Value result; result["revisions"] = revisions(snapshot); result["categories"] = std::move(prepared.summary);
    return result;
}
Json::Value ConfigurationBackup::commit(const CallContext& caller, std::string_view bytes, const Json::Value& preview) {
    access(caller);
    std::lock_guard work(import_mutex_);
    Json::Value receipt; receipt["completed"] = Json::Value(Json::arrayValue); receipt["recoveryRequired"] = false;
    std::string stage = "validation";
    try {
        const auto snapshot = configuration_.snapshot(caller);
        if (preview["revisions"] != revisions(snapshot))
            throw ServiceError(ErrorCode::conflict, "Configuration changed; upload and preview the backup again");
        auto prepared = prepare(bytes, snapshot);
        if (prepared.summary != preview["categories"])
            throw ServiceError(ErrorCode::conflict, "Backup preview does not match uploaded bytes");
        if (prepared.has_networks) {
            stage = "networks";
            configuration_.networks().merge_if_matches(caller, prepared.networks, snapshot.networks.revision);
            receipt["completed"].append("networks");
        }
        if (prepared.has_vms || prepared.has_disks) {
            stage = "vm_disks";
            configuration_.replace_vm_disks(caller, snapshot.vms->revision, snapshot.disks->revision,
                std::move(prepared.vms), std::move(prepared.disks));
            if (prepared.has_disks) receipt["completed"].append("disks");
            if (prepared.has_vms) receipt["completed"].append("vms");
        }
    } catch (const ServiceError& error) { failure(receipt, stage, error.code(), error.what()); }
    catch (const std::exception&) { failure(receipt, stage, ErrorCode::internal, "Configuration backup import failed"); }
    if (receipt.isMember("failedStage") && configuration_.recovery_required()) receipt["recoveryRequired"] = true;
    return receipt;
}
}
