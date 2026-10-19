// SPDX-License-Identifier: GPL-3.0-or-later
#include "disk_inspection.h"
#include "plan.h"
#include "services/configuration.h"
#include "store/disk_config.h"
#include "store/network_config.h"
#include <chrono>

namespace droidvm::pkg {
DiskInspection DiskInspectionService::read(const CallContext& caller, const std::string& id, bool inspect_compression) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Session required");
    if (!caller.administrator) throw ServiceError(ErrorCode::permission_denied, "Disk permission required");
    std::unique_lock lock(mutex_, std::try_to_lock);
    if (!lock.owns_lock()) throw ServiceError(ErrorCode::resource_exhausted, "Disk inspection in progress");
    if (!configuration_.disks()) throw ServiceError(ErrorCode::unavailable, "Disk registry unavailable");
    DiskInspection result;
    result.disks = *configuration_.disks()->snapshot(caller);
    result.vms = *configuration_.vms().snapshot(caller);
    // Registry reads preserve legacy parent spellings. Project the same UUID
    // identity used by native chain resolution, without rewriting the store.
    for (auto& row : result.disks.document["disks"]) {
        Json::Value parent; parent["id"] = config::member(row, "parent");
        try { row["parent"] = config::uuid(parent); }
        catch (const std::invalid_argument&) {}
    }
    const auto& rows = result.disks.document["disks"];
    if (!rows.isArray() || rows.size() > 4096)
        throw ServiceError(ErrorCode::resource_exhausted, "Disk registry too large");
    const Json::Value* selected = nullptr;
    for (const auto& row : rows) if (row["id"].isString() && row["id"].asString() == id) selected = &row;
    if (!selected) throw ServiceError(ErrorCode::not_found, "Disk not registered");
    const auto path = config::disk_path(*selected);
    if (!config::valid_disk_paths(result.disks.document).contains(path)) {
        result.state = "invalid-chain";
    } else {
        Json::Value vm, slot;
        slot["path"] = path; slot["readonly"] = true;
        vm["disks"].append(slot);
        const auto files = config::disk_start_files(vm, result.disks.document);
        if (files.size() > 64) throw ServiceError(ErrorCode::resource_exhausted, "Disk ancestry too deep");
        std::set<std::string> paths, ids;
        for (const auto& file : files) paths.insert(file.path);
        for (const auto& row : rows)
            if (paths.contains(config::disk_path(row))) ids.insert(row["id"].asString());
        // A stale registry is a conflict, not a busy image. Reserve before IO.
        try {
            const auto reservation = configuration_.reserve_disks(result.disks.revision, {}, ids);
            const auto lease = configuration_.disk_files()->acquire(files);
            const Images images(tool_, {}, std::chrono::seconds(5));
            result.image = images.leased_info(*lease, path);
            if (inspect_compression)
                result.effective_compression = images.effective_compression(*lease, path, result.image);
            result.state = "ready";
        } catch (const ServiceError& error) {
            if (error.code() == ErrorCode::conflict) result.state = "busy";
            else if (error.code() != ErrorCode::io_error && error.code() != ErrorCode::unavailable) throw;
        } catch (const std::runtime_error&) {
            // Missing/unsupported image, image-tool failure or timeout is unknown.
        }
    }
    if (configuration_.disks()->snapshot(caller)->revision != result.disks.revision ||
        configuration_.vms().snapshot(caller)->revision != result.vms.revision)
        throw ServiceError(ErrorCode::conflict, "Disk references changed during inspection");
    return result;
}
}
