// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "web/resource_catalog.h"
#include "services/tasks.h"
#include "common/wire.h"
#include "common/identity.h"
#include <mutex>
#include <map>

// In-memory observations only: no qemu-img, leases, files or recovery simulation.
// New results are registered here so the browser can follow their returned ID.
struct FixtureDisks {
    std::mutex mutex;
    Json::Value added{Json::arrayValue};
    std::map<std::string, std::string> compression_overrides;
    size_t recovery_pending = 2; // Synthetic unfinished records, one cleared per explicit attempt.
    size_t pending() { std::lock_guard lock(mutex); return recovery_pending; }
    Json::Value recover() {
        std::lock_guard lock(mutex);
        if (recovery_pending) --recovery_pending;
        Json::Value result; result["pending"] = Json::UInt64(recovery_pending); return result;
    }
    Json::Value catalog_locked() {
        droidvm::DiskConfigSnapshot snapshot;
        snapshot.revision = "fixture-disk-revision";
        snapshot.persisted = true; snapshot.durability_uncertain = true;
        snapshot.document = droidvm::wire::parse(R"({"disks":[{"id":"fixture-disk","name":"测试磁盘.qcow2","test_path":"/fixture/registered.qcow2"},{"id":"fixture-broken","name":"失效磁盘","test_path":"/fixture/broken.qcow2"},{"id":"fixture-copy-disk","name":"副本磁盘.qcow2","test_path":"/fixture/copy.qcow2"}]})");
        std::set<std::string> paths{"/fixture/registered.qcow2", "/fixture/copy.qcow2"}, backing;
        for (const auto& row : added) { snapshot.document["disks"].append(row); paths.insert(row["test_path"].asString()); }
        for (const auto& row : snapshot.document["disks"])
            for (const auto& child : added)
                if (child["parent"] == row["id"]) backing.insert(row["test_path"].asString());
        auto result = droidvm::web::disk_catalog(snapshot, [](const Json::Value& row) { return row["test_path"].asString(); }, paths, backing);
        result["vmRevision"] = "fixture-reference-revision";
        return result;
    }
    Json::Value catalog() { std::lock_guard lock(mutex); return catalog_locked(); }
    Json::Value detail(const std::string& id, bool inspect_compression = false) {
        std::lock_guard lock(mutex);
        droidvm::VmConfigSnapshot vms; vms.revision = "fixture-reference-revision";
        vms.document = droidvm::wire::parse(R"({"vms":[{"id":"native-http-vm","name":"原生 HTTP 虚拟机","disks":[{"path":"/fixture/registered.qcow2","readonly":true}]}]})");
        auto image = droidvm::wire::parse(R"({"format":"qcow2","virtual-size":18446744073709551615,"actual-size":1048576,"cluster-size":65536,"encrypted":false,"dirty-flag":false,"filename":"/private/fd/7","format-specific":{"data":{"compression-type":"zstd"}}})");
        std::optional<std::string> compression = inspect_compression ? std::optional<std::string>("zstd") : std::nullopt;
        for (const auto& row : added) if (row["id"] == id) {
            image["format"] = row["format"];
            image["virtual-size"] = row["size"];
            if (inspect_compression) compression = row.get("compression", "none").asString();
        }
        if (inspect_compression && compression_overrides.contains(id)) compression = compression_overrides.at(id);
        if (image["format"] == "raw") image.removeMember("format-specific");
        return droidvm::web::disk_detail(catalog_locked(), vms, id, id == "fixture-broken" ? "invalid-chain" : "ready", image, compression);
    }
    droidvm::TaskCompletion execute(const Json::Value& request, droidvm::TaskControl& control) {
        std::lock_guard lock(mutex);
        if (request["disk_revision"] != "fixture-disk-revision" || request["vm_revision"] != "fixture-reference-revision")
            throw droidvm::ServiceError(droidvm::ErrorCode::conflict, "Fixture observation changed");
        if (!control.enter_commit()) return droidvm::TaskCompletion::cancelled();
        if (request["name"] == "fixture-uncertain.qcow2") {
            recovery_pending = 2;
            return droidvm::TaskCompletion::failure(droidvm::ErrorCode::commit_uncertain, "Synthetic uncertain commit");
        }
        Json::Value result;
        result["disk_id"] = request["disk_id"];
        if (request["action"] == "flatten" || request["action"] == "convert") {
            compression_overrides[request["disk_id"].asString()] = request.get("compress", "none").asString();
            for (auto& row : added) if (row["id"] == request["disk_id"]) {
                if (request["action"] == "flatten") row.removeMember("parent");
                row["format"] = request.get("format", row["format"]);
            }
        }
        if (request["action"] == "resize") {
            // Keep the synthetic image observation consistent for the browser's
            // second-stage autogrow confirmation; no host file is resized.
            for (auto& row : added)
                if (row["id"] == request["disk_id"]) row["size"] = request["size"];
        }
        if (request["action"] == "create" || request["action"] == "clone") {
            Json::Value row;
            row["id"] = droidvm::random_id(true); row["name"] = request["name"];
            row["test_path"] = request["folder"].asString() + "/" + request["name"].asString();
            row["format"] = request.get("format", "qcow2");
            row["size"] = request.get("size", Json::Value(Json::UInt64(8589934592ULL)));
            if (request["action"] == "clone") {
                // Native clone preserves source format, size and backing link.
                for (const auto& source : added) if (source["id"] == request["disk_id"]) {
                    row["format"] = source["format"]; row["size"] = source["size"];
                    if (source.isMember("parent")) row["parent"] = source["parent"];
                    break;
                }
            }
            if (request["action"] == "create" && request["backing_id"].isString()) row["parent"] = request["backing_id"];
            added.append(row); result["disk_id"] = row["id"];
        }
        return droidvm::TaskCompletion::success(result);
    }
};
