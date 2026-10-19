// SPDX-License-Identifier: GPL-3.0-or-later
#include "image_import.h"
#include "import_preview.h"
#include "io.h"
#include "common/identity.h"
#include "common/wire.h"
#include "store/network_config.h"
#include <algorithm>
#include <chrono>
#include <climits>
#include <map>
#include <set>
#include <sys/stat.h>

namespace droidvm::pkg {
namespace {
using Clock = std::chrono::steady_clock;
using Inode = std::pair<std::string, std::string>;
void access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || !caller.manage_tasks || caller.principal.empty())
        throw ServiceError(ErrorCode::permission_denied, "Image import permission required");
}
void valid_path(const std::string& path) {
    if (path.empty() || path.front() != '/' || path.size() > 4096 || path.find('\0') != std::string::npos || !valid_utf8(path))
        throw ServiceError(ErrorCode::invalid_argument, "An absolute host image path is required");
}
Inode identity(const Json::Value& observed) { return {observed["device"].asString(), observed["inode"].asString()}; }
struct Budget {
    Clock::time_point deadline = Clock::now() + std::chrono::seconds(30);
    std::function<bool()> cancelled;
    void check() const {
        if ((cancelled && cancelled()) || Clock::now() >= deadline)
            throw ServiceError(ErrorCode::unavailable, "Image inspection was cancelled or reached its deadline");
    }
    Images images(const std::string& tool) const {
        check();
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
        return Images(tool, [stop = cancelled, end = deadline] { return (stop && stop()) || Clock::now() >= end; },
            std::max(std::chrono::milliseconds(1), std::min(std::chrono::milliseconds(5000), remaining)));
    }
};
struct File {
    std::shared_ptr<config::DiskFileLeases::Lease> lease;
    Json::Value observed;
};
struct Prepared {
    Json::Value plan, vms, disks;
    std::map<std::string, File> files;
    std::set<std::string> reserve;
    Json::UInt added = 0;
    void verify() const {
        for (const auto& [path, file] : files) {
            file.lease->verify();
            if (observe_package_file(file.lease->read_fd(path)) != file.observed)
                throw ServiceError(ErrorCode::conflict, "Image changed since it was inspected");
        }
    }
};
Prepared prepare(ConfigurationService& configuration, const ConfigurationService::Snapshot& snapshot,
        const std::string& tool, const std::string& source, const Budget& budget, const Json::Value* expected,
        const std::function<void(const std::string&, int)>& persistent_source) {
    valid_path(source); budget.check();
    const auto& original = snapshot.disks->document["disks"];
    if (!original.isArray() || original.size() > 4096)
        throw ServiceError(ErrorCode::resource_exhausted, "Disk registry is too large for image import");
    if (expected && (!(*expected)["members"].isArray() || (*expected)["members"].empty() || (*expected)["members"].size() > max_chain))
        throw ServiceError(ErrorCode::invalid_argument, "Invalid retained image import plan");
    Prepared result; result.disks = snapshot.disks->document;
    auto& plan = result.plan;
    plan["source"] = source; plan["vmRevision"] = snapshot.vms->revision; plan["diskRevision"] = snapshot.disks->revision;
    plan["members"] = Json::Value(Json::arrayValue); plan["attachments"] = Json::Value(Json::arrayValue);
    plan["_files"] = Json::Value(Json::objectValue);
    const auto hold = [&](const std::string& path) -> const File& {
        valid_path(path); budget.check();
        const auto found = result.files.find(path);
        if (found != result.files.end()) return found->second;
        auto lease = configuration.disk_files()->acquire({{path, false}});
        if (persistent_source) persistent_source(path, lease->read_fd(path));
        auto observed = observe_package_file(lease->read_fd(path));
        if (expected && (!(*expected)["_files"].isObject() || (*expected)["_files"][path] != observed))
            throw ServiceError(ErrorCode::conflict, "Image source changed; preview again");
        plan["_files"][path] = observed;
        return result.files.emplace(path, File{std::move(lease), std::move(observed)}).first->second;
    };
    // Existing inode aliases identify the same disk. Never register a second
    // row merely because the browser supplied a symlink or hardlink spelling.
    std::map<Inode, std::vector<Json::ArrayIndex>> registered;
    std::set<std::string> registered_ids;
    for (Json::ArrayIndex i = 0; i < original.size(); ++i) {
        budget.check();
        if (!registered_ids.insert(config::uuid(original[i])).second)
            throw ServiceError(ErrorCode::conflict, "Disk registry contains repeated IDs");
        const auto path = config::disk_path(original[i]);
        struct stat value{};
        if (!path.empty() && path.front() == '/' && path.find('\0') == std::string::npos &&
            stat(path.c_str(), &value) == 0 && S_ISREG(value.st_mode))
            registered[{std::to_string(value.st_dev), std::to_string(value.st_ino)}].push_back(i);
    }
    const auto source_identity = identity(hold(source).observed);
    auto current = canonical_path(source);
    if (identity(hold(current).observed) != source_identity)
        throw ServiceError(ErrorCode::conflict, "Image source alias changed");
    std::set<Inode> seen;
    std::set<std::string> planned_ids;
    std::vector<std::optional<Json::ArrayIndex>> indices;
    for (size_t depth = 0;; ++depth) {
        budget.check();
        if (depth >= max_chain) throw ServiceError(ErrorCode::resource_exhausted, "Image backing chain is too deep");
        const auto& source_file = hold(current);
        const auto inode = identity(source_file.observed);
        if (!seen.insert(inode).second) throw ServiceError(ErrorCode::conflict, "Image backing chain is cyclic");
        std::optional<Json::ArrayIndex> index;
        std::string path = current;
        const auto match = registered.find(inode);
        if (match != registered.end()) {
            if (match->second.size() != 1) throw ServiceError(ErrorCode::conflict, "Multiple registered disks alias one image");
            index = match->second.front(); path = config::disk_path(original[*index]);
        }
        const auto& file = hold(path);
        if (identity(file.observed) != inode) throw ServiceError(ErrorCode::conflict, "Registered image alias changed");
        auto parent = budget.images(tool).backing_of(*file.lease, path);
        if (path != current) {
            const auto original_parent = budget.images(tool).backing_of(*source_file.lease, current);
            if (parent.has_value() != original_parent.has_value() ||
                (parent && identity(hold(*parent).observed) != identity(hold(*original_parent).observed)))
                throw ServiceError(ErrorCode::conflict, "Image aliases resolve different backing files");
        }
        const auto info = budget.images(tool).leased_info(*file.lease, path);
        if (!info["format"].isString() || (info["format"] != "raw" && info["format"] != "qcow2") ||
            !info["virtual-size"].isUInt64() || info["virtual-size"].asUInt64() > uint64_t(INT64_MAX))
            throw ServiceError(ErrorCode::invalid_argument, "Only inspected raw and qcow2 images are supported");
        result.verify();
        std::string id;
        if (index) id = config::uuid(original[*index]);
        else if (expected && depth < (*expected)["members"].size()) id = config::uuid((*expected)["members"][static_cast<Json::ArrayIndex>(depth)]);
        else if (expected) throw ServiceError(ErrorCode::conflict, "Image backing chain changed; preview again");
        else id = random_id(true);
        if (!planned_ids.insert(id).second || (!index && registered_ids.contains(id)))
            throw ServiceError(ErrorCode::conflict, "Image import IDs are ambiguous");
        Json::Value member;
        member["id"] = id; member["path"] = path; member["name"] = basename(path);
        member["parentId"] = Json::Value(); member["existing"] = index.has_value(); member["format"] = info["format"];
        member["virtualSizeBytes"] = std::to_string(info["virtual-size"].asUInt64());
        if (member["name"].asString().empty() || member["name"].asString().size() > 255)
            throw ServiceError(ErrorCode::invalid_argument, "Image filename is invalid");
        plan["members"].append(std::move(member)); indices.push_back(index); result.reserve.insert(id);
        if (!index) ++result.added;
        if (!parent) break;
        current = *parent;
    }
    auto& members = plan["members"];
    plan["diskId"] = members[0]["id"];
    auto& rows = result.disks["disks"];
    std::set<std::string> chain_paths;
    for (Json::ArrayIndex i = 0; i < members.size(); ++i) {
        auto& member = members[i];
        if (i + 1 < members.size()) member["parentId"] = members[i + 1]["id"];
        Json::Value row = indices[i] ? rows[*indices[i]] : Json::Value(Json::objectValue);
        if (!indices[i]) {
            row["id"] = member["id"]; row["name"] = member["name"]; row["folder"] = dirname(member["path"].asString());
        }
        if (member["parentId"].isNull()) row.removeMember("parent"); else row["parent"] = member["parentId"];
        if (indices[i]) rows[*indices[i]] = std::move(row); else rows.append(std::move(row));
        chain_paths.insert(member["path"].asString());
    }
    try {
        config::validate_disk_transition(snapshot.disks->document, result.disks);
        result.vms = config::reattach_disk_slots(snapshot.vms->document, snapshot.disks->document, result.disks, false);
    } catch (const std::invalid_argument&) { throw ServiceError(ErrorCode::conflict, "Imported image chain conflicts with the disk registry"); }
    // Historical VM slots can already name newly registered paths; the shared
    // reattachment helper intentionally handles only previously known rows.
    const auto references = config::disk_references(result.vms, result.disks);
    for (auto& vm : result.vms["vms"]) {
        if (!config::member(vm, "disks").isArray()) continue;
        auto& slots = vm["disks"];
        for (auto& slot : slots) {
            const auto path = config::string(slot, "path");
            const auto holders = references.holders.find(path);
            if (chain_paths.contains(path) && (references.bases.contains(path) ||
                (holders != references.holders.end() && holders->second > 1))) slot["readonly"] = true;
        }
    }
    const auto affected = config::affected_disk_paths(snapshot.disks->document, result.disks);
    for (const auto& row : original) if (affected.contains(config::disk_path(row))) result.reserve.insert(config::uuid(row));
    const auto& before_vms = snapshot.vms->document["vms"];
    for (Json::ArrayIndex v = 0; v < before_vms.size(); ++v) {
        const auto& before = config::member(before_vms[v], "disks");
        const auto& after = config::member(result.vms["vms"][v], "disks");
        if (!before.isArray()) continue;
        if (before.size() != after.size()) throw ServiceError(ErrorCode::internal, "Image registration unexpectedly removed a VM attachment");
        for (Json::ArrayIndex s = 0; s < before.size(); ++s) if (before[s] != after[s]) {
            if (plan["attachments"].size() >= 512) throw ServiceError(ErrorCode::resource_exhausted, "Too many affected VM attachments");
            Json::Value change;
            change["vmId"] = config::uuid(before_vms[v]); change["slot"] = s;
            change["beforePath"] = config::string(before[s], "path"); change["afterPath"] = config::string(after[s], "path");
            change["beforeReadOnly"] = config::boolean(before[s], "readonly"); change["afterReadOnly"] = config::boolean(after[s], "readonly");
            plan["attachments"].append(std::move(change));
        }
    }
    try {
        wire::stringify_bounded(plan, ImageImportService::max_plan_bytes);
        config::encode_json(result.vms, VmConfigService::max_bytes); config::encode_json(result.disks, DiskConfigService::max_bytes);
    } catch (const std::length_error&) { throw ServiceError(ErrorCode::resource_exhausted, "Image import plan exceeds its size limit"); }
    result.verify(); budget.check();
    if (expected && plan != *expected) throw ServiceError(ErrorCode::conflict, "Image import plan changed; preview again");
    return result;
}
}
Json::Value ImageImportService::preview(const CallContext& caller, const std::string& source, std::function<bool()> cancelled) {
    access(caller);
    std::unique_lock work(mutex_, std::try_to_lock);
    if (!work) throw ServiceError(ErrorCode::resource_exhausted, "Image import inspection is already active");
    Budget budget; budget.cancelled = std::move(cancelled);
    try {
        const auto snapshot = configuration_.snapshot(caller);
        auto prepared = prepare(configuration_, snapshot, qemu_img_, source, budget, nullptr, persistent_source_);
        const auto latest = configuration_.snapshot(caller);
        if (latest.vms->revision != snapshot.vms->revision || latest.disks->revision != snapshot.disks->revision)
            throw ServiceError(ErrorCode::conflict, "VM or disk configuration changed during image inspection");
        prepared.verify();
        return std::move(prepared.plan);
    } catch (const ServiceError&) { throw; }
    catch (const std::exception&) { throw ServiceError(ErrorCode::io_error, "Image or backing chain could not be inspected"); }
}
TaskCompletion ImageImportService::commit(const CallContext& caller, const Json::Value& retained_plan, TaskControl& control) {
    access(caller);
    Json::Value receipt;
    receipt["diskId"] = retained_plan["diskId"]; receipt["registered"] = false; receipt["registrationUncertain"] = false;
    receipt["recoveryRequired"] = false; receipt["added"] = 0;
    bool submitting = false;
    try {
        std::unique_lock work(mutex_, std::try_to_lock);
        if (!work) throw ServiceError(ErrorCode::resource_exhausted, "Image import inspection is already active");
        if (!retained_plan.isObject() || !retained_plan["source"].isString())
            throw ServiceError(ErrorCode::invalid_argument, "Invalid retained image import plan");
        wire::stringify_bounded(retained_plan, max_plan_bytes);
        const auto snapshot = configuration_.snapshot(caller);
        if (retained_plan["vmRevision"] != snapshot.vms->revision || retained_plan["diskRevision"] != snapshot.disks->revision)
            throw ServiceError(ErrorCode::conflict, "VM or disk configuration changed; preview again");
        Budget budget; budget.cancelled = [&control] { return control.cancellation_requested(); };
        auto prepared = prepare(configuration_, snapshot, qemu_img_, retained_plan["source"].asString(), budget, &retained_plan, persistent_source_);
        auto reservation = configuration_.reserve_disks(snapshot.disks->revision, prepared.reserve, {}, snapshot.vms->revision);
        prepared.verify(); budget.check();
        if (!control.enter_commit()) return TaskCompletion::cancelled(std::move(receipt));
        submitting = true;
        configuration_.replace_vm_disks(caller, snapshot.vms->revision, snapshot.disks->revision,
            std::move(prepared.vms), std::move(prepared.disks), reservation);
        receipt["registered"] = true; receipt["added"] = prepared.added;
        return TaskCompletion::success(std::move(receipt));
    } catch (const ServiceError& error) {
        receipt["registrationUncertain"] = error.code() == ErrorCode::commit_uncertain || (submitting && error.code() == ErrorCode::internal);
        receipt["recoveryRequired"] = receipt["registrationUncertain"].asBool() || configuration_.recovery_required();
        if (!submitting && control.cancellation_requested()) return TaskCompletion::cancelled(std::move(receipt));
        return TaskCompletion::failure(error.code(), "Image registration failed; inspect the operation result", std::move(receipt));
    } catch (const std::exception&) {
        receipt["registrationUncertain"] = submitting;
        receipt["recoveryRequired"] = submitting || configuration_.recovery_required();
        if (!submitting && control.cancellation_requested()) return TaskCompletion::cancelled(std::move(receipt));
        return TaskCompletion::failure(submitting ? ErrorCode::internal : ErrorCode::io_error, "Image registration could not be confirmed", std::move(receipt));
    }
}
}
