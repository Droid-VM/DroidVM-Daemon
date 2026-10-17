// SPDX-License-Identifier: GPL-3.0-or-later
#include "vm_config_upload.h"
#include "common/identity.h"
#include "store/network_config.h"
#include <algorithm>

namespace droidvm {
namespace {
constexpr size_t upload_overhead = 1024;
void access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || caller.principal.empty()) throw ServiceError(ErrorCode::permission_denied, "Administrator permission required");
    if (caller.principal.size() > 128) throw ServiceError(ErrorCode::invalid_argument, "Invalid principal");
}
}
void ConfigUploads::reap() {
    const auto now = now_();
    for (auto it = uploads_.begin(); it != uploads_.end();) {
        if (!it->second->committing && now >= it->second->expires) {
            reserved_ -= it->second->reservation;
            it = uploads_.erase(it);
        } else ++it;
    }
}
std::shared_ptr<ConfigUploads::Upload> ConfigUploads::find(const CallContext& caller, const std::string& id, Kind kind) {
    if (id.empty() || id.size() > 128) throw ServiceError(ErrorCode::invalid_argument, "Invalid upload ID");
    reap();
    auto found = uploads_.find(id);
    if (found == uploads_.end()) throw ServiceError(ErrorCode::not_found, "Upload expired, consumed or unknown");
    if (found->second->principal != caller.principal) throw ServiceError(ErrorCode::permission_denied, "Upload belongs to another principal");
    if (found->second->kind != kind) throw ServiceError(ErrorCode::not_found, "Upload belongs to another resource");
    if (found->second->committing) throw ServiceError(ErrorCode::conflict, "Upload commit in progress");
    return found->second;
}
std::string ConfigUploads::begin(const CallContext& caller, const std::string& revision, size_t bytes) {
    access(caller);
    if (revision.empty() || revision.size() > 128 || !bytes || bytes > VmConfigService::max_bytes)
        throw ServiceError(ErrorCode::invalid_argument, "Invalid upload revision or size");
    if (!store_) throw ServiceError(ErrorCode::unavailable, "VM configuration is unavailable");
    if (store_->snapshot(caller)->revision != revision) throw ServiceError(ErrorCode::conflict, "VM configuration changed; reload before saving");
    return begin_impl(caller, revision, bytes, Kind::vm);
}
std::string ConfigUploads::begin_network(const CallContext& caller, size_t bytes) {
    access(caller);
    if (!networks_) throw ServiceError(ErrorCode::unavailable, "Network configuration is unavailable");
    if (!bytes || bytes > NetworkConfigService::max_import_bytes)
        throw ServiceError(ErrorCode::invalid_argument, "Invalid network import size");
    return begin_impl(caller, "", bytes, Kind::network);
}
std::string ConfigUploads::begin_disk(const CallContext& caller, const std::string& revision, size_t bytes) {
    access(caller);
    if (!disks_) throw ServiceError(ErrorCode::unavailable, "Disk configuration is unavailable");
    if (revision.empty() || revision.size() > 128 || !bytes || bytes > DiskConfigService::max_bytes)
        throw ServiceError(ErrorCode::invalid_argument, "Invalid disk upload revision or size");
    if (disks_->snapshot(caller)->revision != revision)
        throw ServiceError(ErrorCode::conflict, "Disk registry changed; reload before saving");
    return begin_impl(caller, revision, bytes, Kind::disk);
}
size_t ConfigUploads::append_disk(const CallContext& caller, const std::string& id, size_t offset, std::string_view bytes) {
    return append_impl(caller, id, offset, bytes, Kind::disk);
}
DiskConfigService::Snapshot ConfigUploads::commit_disk(const CallContext& caller, const std::string& id) {
    DiskConfigService::Snapshot result;
    consume(caller, id, Kind::disk, [&](const std::string& revision, std::string_view bytes) {
        if (disks_->snapshot(caller)->revision != revision)
            throw ServiceError(ErrorCode::conflict, "Disk registry changed; reload before saving");
        Json::Value document;
        try { document = config::parse_json(bytes); }
        catch (const std::invalid_argument&) { throw ServiceError(ErrorCode::invalid_argument, "Invalid uploaded disk registry JSON"); }
        result = disks_->replace(caller, revision, std::move(document));
    });
    return result;
}
void ConfigUploads::abort_disk(const CallContext& caller, const std::string& id) {
    abort_impl(caller, id, Kind::disk);
}
std::string ConfigUploads::begin_delete(const CallContext& caller, const std::string& revision, size_t bytes) {
    access(caller);
    if (!deletion_ || !store_) throw ServiceError(ErrorCode::unavailable, "Coordinated network deletion is unavailable");
    // Full 8 MiB stored target plus its JSON envelope, not a transport frame.
    if (revision.empty() || revision.size() > 128 || !bytes || bytes > (9u << 20))
        throw ServiceError(ErrorCode::invalid_argument, "Invalid network deletion revision or size");
    if (store_->snapshot(caller)->revision != revision) throw ServiceError(ErrorCode::conflict, "VM configuration changed; reload before deleting");
    return begin_impl(caller, revision, bytes, Kind::network_delete);
}
size_t ConfigUploads::append_delete(const CallContext& caller, const std::string& id, size_t offset, std::string_view bytes) {
    return append_impl(caller, id, offset, bytes, Kind::network_delete);
}
ConfigUploads::DeletedNetwork ConfigUploads::commit_delete(const CallContext& caller, const std::string& id) {
    DeletedNetwork result;
    consume(caller, id, Kind::network_delete, [&](const std::string& revision, std::string_view bytes) {
        Json::Value document;
        try { document = config::parse_json(bytes); }
        catch (const std::invalid_argument&) { throw ServiceError(ErrorCode::invalid_argument, "Invalid network deletion JSON"); }
        if (document.size() != 1 || !document["expected"].isObject())
            throw ServiceError(ErrorCode::invalid_argument, "Expected complete network configuration");
        try { result.id = config::uuid(document["expected"]); }
        catch (const std::invalid_argument&) { throw ServiceError(ErrorCode::invalid_argument, "Invalid expected network ID"); }
        result.vms = deletion_(caller, revision, document["expected"]);
    });
    return result;
}
void ConfigUploads::abort_delete(const CallContext& caller, const std::string& id) {
    abort_impl(caller, id, Kind::network_delete);
}
std::string ConfigUploads::begin_vm_disks(const CallContext& caller, const std::string& vm_revision,
        const std::string& disk_revision, size_t bytes) {
    access(caller);
    if (!replacement_) throw ServiceError(ErrorCode::unavailable, "Joint VM/disk configuration is unavailable");
    if (vm_revision.empty() || vm_revision.size() > 128 || disk_revision.empty() || disk_revision.size() > 128
            || !bytes || bytes > max_vm_disk_bytes)
        throw ServiceError(ErrorCode::invalid_argument, "Invalid joint configuration revisions or size");
    if (store_->snapshot(caller)->revision != vm_revision || disks_->snapshot(caller)->revision != disk_revision)
        throw ServiceError(ErrorCode::conflict, "VM or disk configuration changed; reload before saving");
    return begin_impl(caller, vm_revision, bytes, Kind::vm_disks, disk_revision);
}
size_t ConfigUploads::append_vm_disks(const CallContext& caller, const std::string& id, size_t offset, std::string_view bytes) {
    return append_impl(caller, id, offset, bytes, Kind::vm_disks);
}
ConfigUploads::VmDisks ConfigUploads::commit_vm_disks(const CallContext& caller, const std::string& id) {
    VmDisks result;
    consume_impl(caller, id, Kind::vm_disks, [&](const Upload& upload) {
        if (store_->snapshot(caller)->revision != upload.revision || disks_->snapshot(caller)->revision != upload.disk_revision)
            throw ServiceError(ErrorCode::conflict, "VM or disk configuration changed; reload before saving");
        Json::Value document;
        try { document = config::parse_json({upload.data.data(), upload.data.size()}); }
        catch (const std::invalid_argument&) { throw ServiceError(ErrorCode::invalid_argument, "Invalid joint configuration JSON"); }
        if (!document.isObject() || document.size() != 2 || !document["vms"].isObject() || !document["disks"].isObject())
            throw ServiceError(ErrorCode::invalid_argument, "Complete VM and disk documents are required");
        result = replacement_(caller, upload.revision, upload.disk_revision, std::move(document["vms"]), std::move(document["disks"]));
    });
    return result;
}
void ConfigUploads::abort_vm_disks(const CallContext& caller, const std::string& id) {
    abort_impl(caller, id, Kind::vm_disks);
}
std::string ConfigUploads::begin_impl(const CallContext& caller, const std::string& revision, size_t bytes, Kind kind,
        const std::string& disk_revision) {
    std::lock_guard lock(mutex_);
    reap();
    if (uploads_.size() >= max_uploads || bytes + upload_overhead > max_reserved - reserved_)
        throw ServiceError(ErrorCode::resource_exhausted, "Upload capacity exhausted");
    auto upload = std::make_shared<Upload>();
    upload->principal = caller.principal; upload->revision = revision; upload->total = bytes;
    upload->disk_revision = disk_revision;
    upload->kind = kind;
    upload->data.reserve(bytes);
    upload->reservation = upload->data.capacity() + upload_overhead;
    if (upload->reservation > max_reserved - reserved_) throw ServiceError(ErrorCode::resource_exhausted, "Upload capacity exhausted");
    upload->expires = now_() + lifetime;
    auto id = random_id(true);
    if (!uploads_.emplace(id, upload).second) throw ServiceError(ErrorCode::internal, "Upload ID collision");
    reserved_ += upload->reservation;
    return id;
}
size_t ConfigUploads::append(const CallContext& caller, const std::string& id, size_t offset, std::string_view bytes) {
    return append_impl(caller, id, offset, bytes, Kind::vm);
}
size_t ConfigUploads::append_network(const CallContext& caller, const std::string& id, size_t offset, std::string_view bytes) {
    return append_impl(caller, id, offset, bytes, Kind::network);
}
size_t ConfigUploads::append_impl(const CallContext& caller, const std::string& id, size_t offset, std::string_view bytes, Kind kind) {
    access(caller);
    if (bytes.empty() || bytes.size() > chunk_bytes) throw ServiceError(ErrorCode::invalid_argument, "Invalid upload chunk size");
    std::lock_guard lock(mutex_);
    auto upload = find(caller, id, kind);
    if (offset > upload->total || bytes.size() > upload->total - offset)
        throw ServiceError(ErrorCode::invalid_argument, "Chunk exceeds declared document size");
    if (offset < upload->data.size()) {
        if (bytes.size() <= upload->data.size() - offset && std::equal(bytes.begin(), bytes.end(), upload->data.begin() + offset))
            return upload->data.size();
        throw ServiceError(ErrorCode::conflict, "Chunk conflicts with previously uploaded bytes");
    }
    if (offset != upload->data.size()) throw ServiceError(ErrorCode::invalid_argument, "Non-contiguous upload offset");
    upload->data.insert(upload->data.end(), bytes.begin(), bytes.end());
    return upload->data.size();
}
void ConfigUploads::finish(const std::string& id) noexcept {
    std::lock_guard lock(mutex_);
    const auto found = uploads_.find(id);
    if (found != uploads_.end()) { reserved_ -= found->second->reservation; uploads_.erase(found); }
}
VmConfigService::Snapshot ConfigUploads::commit(const CallContext& caller, const std::string& id) {
    VmConfigService::Snapshot result;
    consume(caller, id, Kind::vm, [&](const std::string& revision, std::string_view bytes) {
        if (store_->snapshot(caller)->revision != revision)
            throw ServiceError(ErrorCode::conflict, "VM configuration changed; reload before saving");
        Json::Value document;
        try { document = config::parse_json(bytes); }
        catch (const std::invalid_argument&) { throw ServiceError(ErrorCode::invalid_argument, "Invalid uploaded configuration JSON"); }
        result = store_->replace(caller, revision, std::move(document));
    });
    return result;
}
Json::Value ConfigUploads::commit_network(const CallContext& caller, const std::string& id) {
    Json::Value result;
    consume(caller, id, Kind::network, [&](const std::string&, std::string_view bytes) {
        Json::Value operations;
        try { operations = config::parse_json(bytes); }
        catch (const std::invalid_argument&) { throw ServiceError(ErrorCode::invalid_argument, "Invalid uploaded network import JSON"); }
        if (operations.getMemberNames().size() != 1 || !operations.isMember("operations"))
            throw ServiceError(ErrorCode::invalid_argument, "Expected network import operations");
        result = networks_->merge_if_matches(caller, operations["operations"]);
    });
    return result;
}
void ConfigUploads::consume(const CallContext& caller, const std::string& id, Kind kind,
        const std::function<void(const std::string&, std::string_view)>& apply) {
    consume_impl(caller, id, kind, [&](const Upload& upload) {
        apply(upload.revision, {upload.data.data(), upload.data.size()});
    });
}
void ConfigUploads::consume_impl(const CallContext& caller, const std::string& id, Kind kind,
        const std::function<void(const Upload&)>& apply) {
    access(caller);
    std::shared_ptr<Upload> upload;
    {
        std::lock_guard lock(mutex_);
        upload = find(caller, id, kind);
        if (upload->data.size() != upload->total) throw ServiceError(ErrorCode::invalid_argument, "Upload is incomplete");
        upload->committing = true;
    }
    // Keep both reservation and immutable bytes until parsing/persistence finish.
    // Neither expiry nor abort can release a commit's budget or mutate its bytes.
    try {
        apply(*upload);
        upload.reset(); finish(id);
    } catch (...) { upload.reset(); finish(id); throw; }
}
void ConfigUploads::abort(const CallContext& caller, const std::string& id) {
    abort_impl(caller, id, Kind::vm);
}
void ConfigUploads::abort_network(const CallContext& caller, const std::string& id) {
    abort_impl(caller, id, Kind::network);
}
void ConfigUploads::abort_impl(const CallContext& caller, const std::string& id, Kind kind) {
    access(caller);
    std::lock_guard lock(mutex_);
    auto upload = find(caller, id, kind);
    reserved_ -= upload->reservation;
    uploads_.erase(id);
}
}
