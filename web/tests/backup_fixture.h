// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "web/backup_config.h"
#include "common/identity.h"
#include "common/wire.h"
#include <map>
#include <mutex>

// In-memory protocol substitute only. Does not save daemon configuration.
struct FixtureBackup : std::enable_shared_from_this<FixtureBackup> {
    struct Upload { std::string owner, bytes, token; size_t total = 0; Json::Value summary; };
    std::mutex mutex;
    std::map<std::string, Upload> uploads;
    unsigned commits = 0;
    std::string imported;
    Upload& find(const droidvm::CallContext& caller, const std::string& id) {
        const auto row = uploads.find(id);
        if (row == uploads.end() || row->second.owner != caller.principal)
            throw droidvm::ServiceError(droidvm::ErrorCode::not_found, "Backup upload missing");
        return row->second;
    }
    droidvm::web::BackupConfigBindings bindings() {
        const auto self = shared_from_this();
        return {
            [self](const auto& caller, size_t total) {
                std::lock_guard lock(self->mutex);
                if (self->uploads.size() >= 4) throw droidvm::ServiceError(droidvm::ErrorCode::resource_exhausted, "Fixture quota");
                const auto id = droidvm::random_id(true);
                self->uploads.emplace(id, Upload{caller.principal, {}, {}, total, {}}); return id;
            },
            [self](const auto& caller, const auto& id, size_t offset, std::string_view bytes) {
                std::lock_guard lock(self->mutex); auto& upload = self->find(caller, id);
                if (!upload.token.empty() || offset != upload.bytes.size() || bytes.size() > upload.total - offset)
                    throw droidvm::ServiceError(droidvm::ErrorCode::conflict, "Backup offset changed");
                upload.bytes.append(bytes); return upload.bytes.size();
            },
            [self](const auto& caller, const auto& id) {
                std::lock_guard lock(self->mutex); auto& upload = self->find(caller, id);
                if (upload.bytes.size() != upload.total)
                    throw droidvm::ServiceError(droidvm::ErrorCode::invalid_argument, "Incomplete backup");
                if (!upload.token.empty()) return upload.summary;
                const auto document = droidvm::wire::parse(upload.bytes);
                if (document["version"].asUInt() != 1)
                    throw droidvm::ServiceError(droidvm::ErrorCode::invalid_argument, "Unsupported backup version");
                Json::Value result;
                upload.token = droidvm::random_id(true); result["previewToken"] = upload.token;
                for (const auto* name : {"vms", "disks", "networks"}) {
                    const bool present = document.isMember(name);
                    if (present && !document[name].isArray())
                        throw droidvm::ServiceError(droidvm::ErrorCode::invalid_argument, "Backup array required");
                    result["revisions"][name] = std::string("fixture-backup-") + name;
                    auto& row = result["categories"][name]; row["present"] = present;
                    row["count"] = present ? document[name].size() : 0;
                    row["added"] = row["count"]; row["replaced"] = 0;
                }
                result["private"] = "fixture-backup-proof"; upload.summary = result; return result;
            },
            [self](const auto& caller, const auto& id, const auto& token) {
                std::lock_guard lock(self->mutex); auto& upload = self->find(caller, id);
                if (upload.token.empty() || upload.token != token)
                    throw droidvm::ServiceError(droidvm::ErrorCode::conflict, "Backup preview changed");
                self->imported = upload.bytes; self->uploads.erase(id); ++self->commits;
                const auto document = droidvm::wire::parse(self->imported);
                Json::Value result;
                result["completed"] = Json::Value(Json::arrayValue); result["recoveryRequired"] = false;
                result["private"] = "fixture-backup-result";
                if (document.isMember("networks")) result["completed"].append("networks");
                if (document["fixture_outcome"] == "partial" || document["fixture_outcome"] == "uncertain") {
                    result["failedStage"] = "vm_disks";
                    if (document["fixture_outcome"] == "uncertain") {
                        result["uncertainStage"] = "vm_disks"; result["recoveryRequired"] = true;
                        result["error"]["code"] = "COMMIT_UNCERTAIN";
                    } else result["error"]["code"] = "CONFLICT";
                    return result;
                }
                for (const auto* name : {"disks", "vms"}) if (document.isMember(name)) result["completed"].append(name);
                return result;
            },
            [self](const auto& caller, const auto& id) {
                std::lock_guard lock(self->mutex); self->find(caller, id); self->uploads.erase(id);
            },
            [](const droidvm::CallContext&) {
                const auto bytes = std::make_shared<const std::string>(R"({"version":1,"app_version":"fixture","timestamp":1792357200000,"vms":[{"id":"native-http-vm","name":"备份测试","opaque":{"counter":18446744073709551615}}],"networks":[],"disks":[]})");
                auto stream = std::make_shared<droidvm::web::HttpStreamBody>(); stream->length = bytes->size();
                stream->read = [bytes](uint64_t offset, size_t maximum) { return bytes->substr(static_cast<size_t>(offset), maximum); };
                return stream;
            }
        };
    }
    Json::Value stats() {
        std::lock_guard lock(mutex); Json::Value result;
        result["commits"] = commits;
        result["uint64Preserved"] = imported.find("18446744073709551615") != std::string::npos;
        return result;
    }
};
