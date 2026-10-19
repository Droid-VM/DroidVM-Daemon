// SPDX-License-Identifier: GPL-3.0-or-later
#include "agent/rescue_sessions.h"
#include "agent/plan.h"
#include "common/identity.h"
#include "vm/console_busy.h"
#include <atomic>
#include <utility>

namespace droidvm::agent {
struct RescueSessions::Entry {
    std::string id, owner, disk_id;
    vm::Observation expected;
    RunnerDeadline created, expires;
    std::shared_ptr<RescueTarget> target;
    std::mutex mutex;
    std::atomic<bool> closing{false};
    bool removed = false; // entry mutex
    std::optional<CleanupReport> cleanup; // entry mutex
};
RescueSessions::RescueSessions() : RescueSessions(Limits{}) {}
RescueSessions::RescueSessions(Limits limits, Now now) : limits_(limits), now_(std::move(now)) {
    if (!now_ || !limits_.capacity || limits_.ttl <= std::chrono::milliseconds::zero() ||
        limits_.ttl > std::chrono::minutes(15))
        throw std::invalid_argument("Invalid rescue session limits");
}
RescueSessions::~RescueSessions() = default;
void RescueSessions::access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || !caller.manage_tasks || caller.principal.empty())
        throw ServiceError(ErrorCode::permission_denied, "Rescue session permission required");
}
std::string RescueSessions::publish(const CallContext& caller, std::string disk_id, std::shared_ptr<RescueTarget> target) {
    access(caller);
    if (!target) throw ServiceError(ErrorCode::invalid_argument, "Missing rescue target");
    Json::Value disk;
    disk["action"] = "autogrow"; disk["diskId"] = disk_id;
    (void)parse_request(disk); // Reuse canonical registered-disk identity validation.
    auto entry = std::make_shared<Entry>();
    entry->expected = target->observation(); // No registry lock during target calls.
    if (entry->expected.instance.empty()) throw ServiceError(ErrorCode::invalid_argument, "Missing rescue incarnation");
    entry->owner = caller.principal;
    entry->disk_id = std::move(disk_id);
    entry->created = now_(); entry->expires = entry->created + limits_.ttl;
    entry->target = std::move(target);
    std::string id = random_secret(); // Preconstruct everything that can throw.
    entry->id = id;
    {
        std::lock_guard lock(mutex_);
        if (stopping_) throw ServiceError(ErrorCode::unavailable, "Rescue sessions are shutting down");
        if (entries_.size() >= limits_.capacity)
            throw ServiceError(ErrorCode::resource_exhausted, "Rescue session capacity exceeded");
        for (const auto& [key, current] : entries_) {
            (void)key;
            if (current->target.get() == entry->target.get() || current->expected.instance == entry->expected.instance)
                throw ServiceError(ErrorCode::conflict, "Rescue target already has an owner");
        }
        if (!entries_.emplace(id, entry).second)
            throw ServiceError(ErrorCode::resource_exhausted, "Rescue identity collision");
    }
    // std::string's move is noexcept; no view/projection work after publication.
    return id;
}
std::shared_ptr<RescueSessions::Entry> RescueSessions::find(const CallContext& caller, const std::string& id) const {
    access(caller);
    std::lock_guard lock(mutex_);
    const auto at = entries_.find(id);
    if (at == entries_.end() || at->second->owner != caller.principal)
        throw ServiceError(ErrorCode::not_found, "Rescue session not found");
    return at->second;
}
std::vector<std::shared_ptr<RescueSessions::Entry>> RescueSessions::snapshot() const {
    std::vector<std::shared_ptr<Entry>> result;
    std::lock_guard lock(mutex_);
    result.reserve(entries_.size());
    for (const auto& [id, entry] : entries_) { (void)id; result.push_back(entry); }
    return result;
}
RescueSessionView RescueSessions::project(const std::shared_ptr<Entry>& entry, RunnerDeadline now) const {
    RescueSessionView result{entry->id, entry->disk_id, entry->expected, entry->created, entry->expires,
        entry->closing.load(), now >= entry->expires, {}};
    // Metadata stays readable while a slow close waits for the process. Never
    // hold the registry lock, block on target IO, or invent a cleanup receipt.
    std::unique_lock lock(entry->mutex, std::try_to_lock);
    if (lock.owns_lock()) result.cleanup = entry->cleanup;
    return result;
}
RescueSessionView RescueSessions::view(const CallContext& caller, const std::string& id) const {
    return project(find(caller, id), now_());
}
std::vector<RescueSessionView> RescueSessions::list(const CallContext& caller) const {
    access(caller);
    const auto now = now_();
    std::vector<RescueSessionView> result;
    for (const auto& entry : snapshot()) if (entry->owner == caller.principal) result.push_back(project(entry, now));
    return result;
}
void RescueSessions::require_live(const Entry& entry, const vm::Observation& expected) const {
    if (stopping_ || entry.closing || now_() >= entry.expires)
        throw ServiceError(ErrorCode::unavailable, "Rescue console is closed or expired");
    if (expected != entry.expected || entry.target->observation() != entry.expected)
        throw ServiceError(ErrorCode::conflict, "Rescue console incarnation changed");
    // A target observation may have taken time or raced with a close request.
    if (stopping_ || entry.closing || now_() >= entry.expires)
        throw ServiceError(ErrorCode::unavailable, "Rescue console is closed or expired");
}
vm::Observation RescueSessions::observe(const CallContext& caller, const std::string& id) const {
    auto entry = find(caller, id);
    std::unique_lock lock(entry->mutex, std::try_to_lock);
    if (!lock.owns_lock()) throw vm::ConsoleBusy();
    require_live(*entry, entry->expected);
    return entry->expected;
}
vm::LogSlice RescueSessions::read(const CallContext& caller, const std::string& id, const vm::Observation& expected,
        const std::optional<vm::LogCursor>& cursor, bool tail) {
    auto entry = find(caller, id);
    std::unique_lock lock(entry->mutex, std::try_to_lock);
    if (!lock.owns_lock()) throw vm::ConsoleBusy();
    require_live(*entry, expected);
    return entry->target->read(expected, cursor, tail);
}
size_t RescueSessions::write(const CallContext& caller, const std::string& id, const vm::Observation& expected,
        std::string_view bytes) {
    auto entry = find(caller, id);
    if (bytes.empty() || bytes.size() > 512)
        throw ServiceError(ErrorCode::invalid_argument, "Rescue input must contain 1 to 512 bytes");
    std::unique_lock lock(entry->mutex, std::try_to_lock);
    if (!lock.owns_lock()) throw ServiceError(ErrorCode::unavailable, "Rescue console is busy");
    try {
        require_live(*entry, expected);
        const auto accepted = entry->target->write(expected, bytes); // Never replay partial/unknown progress.
        if (accepted > bytes.size()) throw ServiceError(ErrorCode::internal, "Invalid rescue write receipt");
        return accepted;
    } catch (const vm::ConsoleBusy&) {
        // Observation contention must not expose the read-only retry signal on
        // a writer's path. Callers never retry any write exception.
        throw ServiceError(ErrorCode::unavailable, "Rescue console is busy");
    }
}
CleanupReport RescueSessions::close_entry(const std::shared_ptr<Entry>& entry) {
    entry->closing = true; // Reject new console input before waiting for in-flight IO.
    std::unique_lock lock(entry->mutex);
    if (entry->removed) return *entry->cleanup;
    entry->cleanup.reset();
    const auto result = entry->target->close();
    if (!result.stopped && (result.removed || result.disk_synced))
        throw ServiceError(ErrorCode::internal, "Invalid rescue cleanup receipt");
    entry->cleanup = result;
    if (result.stopped && result.removed) {
        entry->removed = true;
        std::lock_guard registry(mutex_);
        const auto at = entries_.find(entry->id);
        if (at != entries_.end() && at->second == entry) entries_.erase(at);
    }
    return result;
}
CleanupReport RescueSessions::close(const CallContext& caller, const std::string& id) {
    return close_entry(find(caller, id));
}
void RescueSessions::expire() {
    const auto now = now_();
    for (const auto& entry : snapshot()) if (now >= entry->expires) {
        try { (void)close_entry(entry); } catch (...) { /* Retain ownership for explicit retry. */ }
    }
}
void RescueSessions::shutdown() {
    { std::lock_guard lock(mutex_); stopping_ = true; }
    const auto entries = snapshot();
    for (const auto& entry : entries) entry->closing = true;
    for (const auto& entry : entries) {
        try { (void)close_entry(entry); } catch (...) { /* A later shutdown can retry. */ }
    }
}
bool RescueSessions::empty() const {
    std::lock_guard lock(mutex_);
    return entries_.empty();
}
}
