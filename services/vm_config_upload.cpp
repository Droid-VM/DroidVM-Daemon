// SPDX-License-Identifier: GPL-3.0-or-later
#include "vm_config_upload.h"
#include "common/identity.h"
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
void VmConfigUploads::reap() {
    const auto now = now_();
    for (auto it = uploads_.begin(); it != uploads_.end();) {
        if (!it->second->committing && now >= it->second->expires) {
            reserved_ -= it->second->reservation;
            it = uploads_.erase(it);
        } else ++it;
    }
}
std::shared_ptr<VmConfigUploads::Upload> VmConfigUploads::find(const CallContext& caller, const std::string& id) {
    if (id.empty() || id.size() > 128) throw ServiceError(ErrorCode::invalid_argument, "Invalid upload ID");
    reap();
    auto found = uploads_.find(id);
    if (found == uploads_.end()) throw ServiceError(ErrorCode::not_found, "Upload expired, consumed or unknown");
    if (found->second->principal != caller.principal) throw ServiceError(ErrorCode::permission_denied, "Upload belongs to another principal");
    if (found->second->committing) throw ServiceError(ErrorCode::conflict, "Upload commit in progress");
    return found->second;
}
std::string VmConfigUploads::begin(const CallContext& caller, const std::string& revision, size_t bytes) {
    access(caller);
    if (revision.empty() || revision.size() > 128 || !bytes || bytes > VmConfigService::max_bytes)
        throw ServiceError(ErrorCode::invalid_argument, "Invalid upload revision or size");
    if (store_.snapshot(caller)->revision != revision) throw ServiceError(ErrorCode::conflict, "VM configuration changed; reload before saving");
    std::lock_guard lock(mutex_);
    reap();
    if (uploads_.size() >= max_uploads || bytes + upload_overhead > max_reserved - reserved_)
        throw ServiceError(ErrorCode::resource_exhausted, "Upload capacity exhausted");
    auto upload = std::make_shared<Upload>();
    upload->principal = caller.principal; upload->revision = revision; upload->total = bytes;
    upload->data.reserve(bytes);
    upload->reservation = upload->data.capacity() + upload_overhead;
    if (upload->reservation > max_reserved - reserved_) throw ServiceError(ErrorCode::resource_exhausted, "Upload capacity exhausted");
    upload->expires = now_() + lifetime;
    auto id = random_id(true);
    if (!uploads_.emplace(id, upload).second) throw ServiceError(ErrorCode::internal, "Upload ID collision");
    reserved_ += upload->reservation;
    return id;
}
size_t VmConfigUploads::append(const CallContext& caller, const std::string& id, size_t offset, std::string_view bytes) {
    access(caller);
    if (bytes.empty() || bytes.size() > chunk_bytes) throw ServiceError(ErrorCode::invalid_argument, "Invalid upload chunk size");
    std::lock_guard lock(mutex_);
    auto upload = find(caller, id);
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
void VmConfigUploads::finish(const std::string& id) noexcept {
    std::lock_guard lock(mutex_);
    const auto found = uploads_.find(id);
    if (found != uploads_.end()) { reserved_ -= found->second->reservation; uploads_.erase(found); }
}
VmConfigService::Snapshot VmConfigUploads::commit(const CallContext& caller, const std::string& id) {
    access(caller);
    std::shared_ptr<Upload> upload;
    {
        std::lock_guard lock(mutex_);
        upload = find(caller, id);
        if (upload->data.size() != upload->total) throw ServiceError(ErrorCode::invalid_argument, "Upload is incomplete");
        upload->committing = true;
    }
    // Keep both reservation and immutable bytes until parsing/persistence finish.
    // Neither expiry nor abort can release a commit's budget or mutate its bytes.
    try {
        if (store_.snapshot(caller)->revision != upload->revision)
            throw ServiceError(ErrorCode::conflict, "VM configuration changed; reload before saving");
        Json::Value document;
        try { document = config::parse_json({upload->data.data(), upload->data.size()}); }
        catch (const std::invalid_argument&) { throw ServiceError(ErrorCode::invalid_argument, "Invalid uploaded configuration JSON"); }
        auto result = store_.replace(caller, upload->revision, std::move(document));
        upload.reset(); finish(id);
        return result;
    } catch (...) { upload.reset(); finish(id); throw; }
}
void VmConfigUploads::abort(const CallContext& caller, const std::string& id) {
    access(caller);
    std::lock_guard lock(mutex_);
    auto upload = find(caller, id);
    reserved_ -= upload->reservation;
    uploads_.erase(id);
}
}
