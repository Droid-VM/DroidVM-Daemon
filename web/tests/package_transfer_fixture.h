// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "web/package_transfers.h"
#include <algorithm>
#include <map>
#include <mutex>

// Synthetic bounded storage; exercises the real adapter and streaming transport,
// not POSIX temporary files, package contents or Android filesystem durability.
struct FixturePackageTransfers : std::enable_shared_from_this<FixturePackageTransfers> {
    struct Record { std::string owner; Json::Value value; };
    std::mutex mutex;
    std::map<std::string, Record> records;
    uint64_t received = 0, read_bytes = 0, read_calls = 0, max_read = 0;
    uint32_t upload_hash = 2166136261u;
    Record& find(const droidvm::CallContext& caller, const std::string& id) {
        const auto row = records.find(id);
        if (row == records.end() || row->second.owner != caller.principal)
            throw droidvm::ServiceError(droidvm::ErrorCode::not_found, "Transfer missing");
        return row->second;
    }
    static Json::Value value(const std::string& id, const std::string& kind,
            const std::vector<droidvm::web::PackageTransferFile>& files) {
        Json::Value result;
        result["id"] = id; result["kind"] = kind; result["state"] = kind == "upload" ? "receiving" : "ready";
        result["files"] = Json::Value(Json::arrayValue);
        for (const auto& file : files) {
            Json::Value row; row["index"] = result["files"].size(); row["name"] = file.name;
            row["size_bytes"] = std::to_string(file.size);
            row["offset_bytes"] = kind == "upload" ? "0" : row["size_bytes"];
            result["files"].append(std::move(row));
        }
        result["limits"]["max_files"] = 1000;
        result["limits"]["max_file_bytes"] = "68719476736";
        result["limits"]["max_session_bytes"] = "137438953472";
        result["limits"]["max_total_bytes"] = "137438953472";
        result["limits"]["chunk_bytes"] = 256u << 10;
        result["limits"]["ttl_ms"] = 7200000;
        result["private"] = "fixture-transfer-private";
        return result;
    }
    Json::Value insert(const droidvm::CallContext& caller, const std::string& id, Json::Value value) {
        if (records.contains(id)) throw droidvm::ServiceError(droidvm::ErrorCode::conflict, "Duplicate transfer");
        if (records.size() >= 8) throw droidvm::ServiceError(droidvm::ErrorCode::resource_exhausted, "Fixture quota");
        records.emplace(id, Record{caller.principal, value});
        return value;
    }
    droidvm::web::PackageTransferBindings bindings() {
        const auto self = shared_from_this();
        return {
            [self](const auto& caller, const auto& id, const std::vector<droidvm::web::PackageTransferFile>& files) {
                std::lock_guard lock(self->mutex);
                return self->insert(caller, id, value(id, "upload", files));
            },
            [self](const auto& caller, const auto& id) {
                std::lock_guard lock(self->mutex); return self->find(caller, id).value;
            },
            [self](const auto& caller, const auto& id) {
                std::lock_guard lock(self->mutex); auto& row = self->find(caller, id).value;
                for (const auto& file : row["files"]) if (file["size_bytes"] != file["offset_bytes"])
                    throw droidvm::ServiceError(droidvm::ErrorCode::conflict, "Incomplete upload");
                row["state"] = "ready";
                for (const auto& file : row["files"]) if (file["name"].asString().ends_with(".vmpkg"))
                    row["master_path"] = "/fixture/upload/" + file["name"].asString();
                return row;
            },
            [self](const auto& caller, const auto& id, size_t index, uint64_t offset, std::string_view bytes) {
                std::lock_guard lock(self->mutex); auto& row = self->find(caller, id).value;
                if (row["state"] != "receiving" || index >= row["files"].size())
                    throw droidvm::ServiceError(droidvm::ErrorCode::conflict, "Invalid upload state");
                auto& file = row["files"][static_cast<Json::ArrayIndex>(index)];
                if (std::to_string(offset) != file["offset_bytes"].asString() || bytes.size() > std::stoull(file["size_bytes"].asString()) - offset)
                    throw droidvm::ServiceError(droidvm::ErrorCode::conflict, "Offset changed");
                for (const unsigned char byte : bytes) { self->upload_hash ^= byte; self->upload_hash *= 16777619u; }
                self->received += bytes.size(); file["offset_bytes"] = std::to_string(offset + bytes.size());
                return row;
            },
            [self](const auto& caller, const auto& id) {
                std::lock_guard lock(self->mutex); self->find(caller, id); self->records.erase(id);
            },
            [self](const auto& caller, const auto& id, const Json::Value& exported) {
                std::lock_guard lock(self->mutex);
                std::vector<droidvm::web::PackageTransferFile> files{{"浏览器导出.vmpkg", (8u << 20) + 7}};
                const auto volumes = exported["volume_total"].asUInt();
                for (unsigned i = 1; i <= volumes; ++i) files.push_back({"浏览器导出.vmpkg.00" + std::to_string(i), 19 + i});
                return self->insert(caller, id, value(id, "download", files));
            },
            [self](const auto& caller, const auto& id, size_t index) {
                std::lock_guard lock(self->mutex); const auto& row = self->find(caller, id).value;
                if (row["kind"] != "download" || index >= row["files"].size())
                    throw droidvm::ServiceError(droidvm::ErrorCode::not_found, "File missing");
                auto stream = std::make_shared<droidvm::web::HttpStreamBody>();
                stream->length = std::stoull(row["files"][static_cast<Json::ArrayIndex>(index)]["size_bytes"].asString());
                stream->read = [self, caller, id, size = stream->length](uint64_t offset, size_t maximum) {
                    std::lock_guard read_lock(self->mutex); self->find(caller, id);
                    if (offset > size || maximum > (256u << 10))
                        throw droidvm::ServiceError(droidvm::ErrorCode::invalid_argument, "Unbounded read");
                    std::string bytes(static_cast<size_t>(std::min<uint64_t>(size - offset, maximum)), '\0');
                    for (size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<char>((offset + i) % 251);
                    ++self->read_calls; self->read_bytes += bytes.size(); self->max_read = std::max<uint64_t>(self->max_read, bytes.size());
                    return bytes;
                };
                return stream;
            }
        };
    }
    Json::Value stats() {
        std::lock_guard lock(mutex); Json::Value result;
        result["uploadBytes"] = std::to_string(received); result["uploadHash"] = upload_hash;
        result["downloadBytes"] = std::to_string(read_bytes); result["readCalls"] = Json::UInt64(read_calls);
        result["maxReadBytes"] = Json::UInt64(max_read); return result;
    }
};
