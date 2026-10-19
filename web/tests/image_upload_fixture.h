// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "web/image_uploads.h"
#include "common/wire.h"
#include <map>
#include <mutex>

// Metadata-only transfer fixture: chunk contents are never retained in memory.
struct FixtureImageUploads : std::enable_shared_from_this<FixtureImageUploads> {
    std::mutex mutex;
    std::map<std::pair<std::string, std::string>, Json::Value> uploads;
    uint64_t bytes = 0, chunks = 0, installs = 0;
    Json::Value& find(const droidvm::CallContext& caller, const std::string& id) {
        const auto found = uploads.find({caller.principal, id});
        if (found == uploads.end()) throw droidvm::ServiceError(droidvm::ErrorCode::not_found, "Image upload not found");
        return found->second;
    }
    droidvm::web::ImageUploadBindings bindings() {
        const auto self = shared_from_this();
        return {
            [self](const droidvm::CallContext& caller, const std::string& id, const droidvm::web::PackageTransferFile& file) {
                std::lock_guard lock(self->mutex);
                if (self->uploads.contains({caller.principal, id}))
                    throw droidvm::ServiceError(droidvm::ErrorCode::conflict, "Image upload exists");
                if (self->uploads.size() >= 8 || file.size > (64ull << 30))
                    throw droidvm::ServiceError(droidvm::ErrorCode::resource_exhausted, "Fixture transfer quota");
                auto row = droidvm::wire::parse(R"({"kind":"upload","purpose":"image","state":"receiving","files":[],"limits":{"max_files":1,"max_file_bytes":"68719476736","max_session_bytes":"137438953472","max_total_bytes":"137438953472","chunk_bytes":262144,"ttl_ms":7200000},"private":"fixture-private-upload"})");
                row["id"] = id; Json::Value selected;
                selected["index"] = 0; selected["name"] = file.name; selected["size_bytes"] = std::to_string(file.size); selected["offset_bytes"] = "0";
                row["files"].append(selected); self->uploads.emplace(std::make_pair(caller.principal, id), row); return row;
            },
            [self](const droidvm::CallContext& caller, const std::string& id) {
                std::lock_guard lock(self->mutex); return self->find(caller, id);
            },
            [self](const droidvm::CallContext& caller, const std::string& id) {
                std::lock_guard lock(self->mutex); auto& row = self->find(caller, id);
                if (row["files"][0]["offset_bytes"] != row["files"][0]["size_bytes"])
                    throw droidvm::ServiceError(droidvm::ErrorCode::conflict, "Incomplete image upload");
                row["state"] = "ready";
                // Intentionally present private paths to exercise allowlisted projection.
                row["master_path"] = "/cache/private/temporary.qcow2"; return row;
            },
            [self](const droidvm::CallContext& caller, const std::string& id, uint64_t offset, std::string_view data) {
                std::lock_guard lock(self->mutex); auto& row = self->find(caller, id); auto& file = row["files"][0];
                const auto size = std::stoull(file["size_bytes"].asString());
                if (row["state"] != "receiving" || file["offset_bytes"] != std::to_string(offset) || offset > size || data.size() > size - offset)
                    throw droidvm::ServiceError(droidvm::ErrorCode::conflict, "Image upload offset changed");
                file["offset_bytes"] = std::to_string(offset + data.size()); self->bytes += data.size(); ++self->chunks; return row;
            },
            [self](const droidvm::CallContext& caller, const std::string& id) {
                std::lock_guard lock(self->mutex); (void)self->find(caller, id); self->uploads.erase({caller.principal, id});
            },
            [self](const droidvm::CallContext& caller, const std::string& id, const std::string& folder, const std::string& name, droidvm::TaskControl& control) {
                std::lock_guard lock(self->mutex); auto& row = self->find(caller, id);
                if (row["state"] != "ready" || row.isMember("installation"))
                    throw droidvm::ServiceError(droidvm::ErrorCode::conflict, "Image upload was already installed");
                if (!control.enter_commit()) return droidvm::TaskCompletion::cancelled();
                ++self->installs;
                const bool uncertain = name.find("uncertain") != std::string::npos;
                Json::Value receipt;
                receipt["upload_id"] = id; receipt["path"] = (folder == "/" ? std::string() : folder) + "/" + name;
                receipt["installed"] = true; receipt["durability_confirmed"] = !uncertain;
                receipt["installation_uncertain"] = uncertain; receipt["recovery_required"] = uncertain;
                receipt["private"] = "fixture-private-install-receipt"; row["installation"] = receipt;
                if (uncertain) return droidvm::TaskCompletion::failure(droidvm::ErrorCode::commit_uncertain, "fixture-private-install-message", receipt);
                return droidvm::TaskCompletion::success(receipt);
            }
        };
    }
    Json::Value stats() {
        std::lock_guard lock(mutex); Json::Value result;
        result["uploadBytes"] = Json::UInt64(bytes); result["chunks"] = Json::UInt64(chunks); result["installs"] = Json::UInt64(installs);
        Json::UInt ready = 0; for (const auto& [key, row] : uploads) if (row["state"] == "ready") ++ready;
        result["readyUploads"] = ready; return result;
    }
};
