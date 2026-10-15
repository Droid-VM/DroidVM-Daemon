// SPDX-License-Identifier: GPL-3.0-or-later
#include "events.h"
#include "common/identity.h"
#include "common/wire.h"
#include <charconv>
#include <limits>

namespace droidvm {
namespace {
void validate_scope(const EventScope& scope) {
    if (scope.principal.empty() || scope.principal.size() > 128)
        throw ServiceError(ErrorCode::invalid_argument, "Invalid event scope");
}
void same_scope(const EventScope& actual, const EventScope& expected) {
    if (actual.principal != expected.principal || actual.administrator != expected.administrator)
        throw ServiceError(ErrorCode::permission_denied, "Stream belongs to another authorization scope");
}
}
EventCursor EventCursor::parse(std::string epoch, std::string_view decimal) {
    if (decimal.empty() || decimal.size() > 20)
        throw ServiceError(ErrorCode::invalid_argument, "Invalid event sequence");
    uint64_t sequence = 0;
    const auto [end, error] = std::from_chars(decimal.data(), decimal.data() + decimal.size(), sequence);
    if ((decimal.size() > 1 && decimal.front() == '0') || error != std::errc() || end != decimal.data() + decimal.size())
        throw ServiceError(ErrorCode::invalid_argument, "Invalid event sequence");
    return {std::move(epoch), sequence};
}
EventJournal::EventJournal(EventLimits limits, Now now, uint64_t initial_sequence)
    : limits_(limits), now_(std::move(now)), epoch_(random_id(true)), sequence_(initial_sequence), floor_(initial_sequence) {
    if (!limits.events || limits.max_event_bytes < 512 || limits.max_event_bytes > (512u << 10) ||
        limits.event_bytes < limits.max_event_bytes + 512 || limits.event_age <= Clock::duration::zero() ||
        !limits.subscriptions || limits.subscription_age <= Clock::duration::zero() ||
        !limits.snapshots || limits.max_snapshot_bytes < limits.max_event_bytes + 512 ||
        limits.snapshot_bytes < limits.max_snapshot_bytes || limits.snapshot_age <= Clock::duration::zero() || !now_)
        throw ServiceError(ErrorCode::invalid_argument, "Invalid event limits");
}
void EventJournal::available() const {
    if (exhausted_) throw ServiceError(ErrorCode::unavailable, "Event sequence exhausted; restart required");
}
bool EventJournal::advance() noexcept {
    if (sequence_ == std::numeric_limits<uint64_t>::max()) { exhausted_ = true; clear_history(); return false; }
    ++sequence_;
    return true;
}
void EventJournal::clear_history() noexcept {
    events_.clear();
    event_bytes_ = 0;
    floor_ = sequence_;
}
void EventJournal::missed() noexcept { advance(); clear_history(); }
void EventJournal::prune() {
    const auto time = now_();
    while (!events_.empty() && (events_.size() > limits_.events || event_bytes_ > limits_.event_bytes ||
                               time - events_.front().created >= limits_.event_age)) {
        floor_ = events_.front().item.sequence;
        event_bytes_ -= events_.front().bytes;
        events_.pop_front();
    }
    for (auto it = subscriptions_.begin(); it != subscriptions_.end();) {
        if (time - it->second.touched >= limits_.subscription_age) it = subscriptions_.erase(it);
        else ++it;
    }
    for (auto it = snapshots_.begin(); it != snapshots_.end();) {
        if (time - it->second.created >= limits_.snapshot_age) {
            snapshot_bytes_ -= it->second.bytes;
            it = snapshots_.erase(it);
        } else ++it;
    }
}
void EventJournal::publish(std::string_view kind, std::string_view resource, std::string_view owner, const Json::Value& data) noexcept {
    if (!advance()) return;
    try {
        if (kind.empty() || kind.size() > 64 || resource.size() > 256 || owner.empty() || owner.size() > 128)
            throw ServiceError(ErrorCode::invalid_argument, "Invalid event metadata");
        Json::Value value;
        value["epoch"] = epoch_;
        value["seq"] = std::to_string(sequence_);
        value["kind"] = std::string(kind);
        value["resource"] = std::string(resource);
        value["data"] = data;
        auto encoded = wire::stringify_bounded(value, limits_.max_event_bytes);
        // Compact reserved serialization storage; account actual retained capacity.
        std::string compact(encoded.data(), encoded.size());
        EventItem item{sequence_, std::string(owner), std::move(compact)};
        const auto bytes = item.encoded.capacity() + item.owner.capacity() + 256;
        events_.push_back({std::move(item), now_(), bytes});
        event_bytes_ += bytes;
        prune();
    } catch (...) { clear_history(); }
}
void EventJournal::validate_cursor(const EventCursor& cursor) const {
    available();
    if (cursor.epoch != epoch_ || cursor.sequence < floor_ || cursor.sequence > sequence_)
        throw ServiceError(ErrorCode::resync_required, "Event history unavailable; get a new snapshot");
}
void EventJournal::validate_page_size(size_t bytes) const {
    if (bytes < limits_.max_event_bytes + 64 || bytes > (1u << 20))
        throw ServiceError(ErrorCode::invalid_argument, "Invalid stream page budget");
}
std::string EventJournal::subscribe(const EventScope& scope, const EventCursor& cursor) {
    validate_scope(scope);
    prune();
    validate_cursor(cursor);
    if (subscriptions_.size() >= limits_.subscriptions)
        throw ServiceError(ErrorCode::resource_exhausted, "Subscription capacity exhausted");
    auto id = random_id(true);
    if (!subscriptions_.emplace(id, Subscription{scope, cursor.sequence, now_()}).second)
        throw ServiceError(ErrorCode::internal, "Subscription ID collision");
    return id;
}
EventBatch EventJournal::poll(const EventScope& scope, const std::string& id, size_t max_events, size_t max_bytes) {
    validate_scope(scope);
    validate_page_size(max_bytes);
    if (!max_events || max_events > 128) throw ServiceError(ErrorCode::invalid_argument, "Invalid event batch size");
    available();
    prune();
    auto found = subscriptions_.find(id);
    if (found == subscriptions_.end()) throw ServiceError(ErrorCode::resync_required, "Subscription expired or closed");
    auto& subscription = found->second;
    same_scope(scope, subscription.scope);
    try { validate_cursor({epoch_, subscription.sequence}); }
    catch (const ServiceError&) { subscriptions_.erase(found); throw; }
    EventBatch batch{{epoch_, subscription.sequence}, {}, false};
    size_t bytes = 0;
    for (const auto& cached : events_) {
        const auto& item = cached.item;
        if (item.sequence <= subscription.sequence) continue;
        if (scope.administrator || item.owner == scope.principal) {
            const auto size = item.encoded.size() + 64;
            if (batch.events.size() == max_events || size > max_bytes - bytes) break;
            batch.events.push_back(item);
            bytes += size;
        }
        batch.covered.sequence = item.sequence; // Hidden events still advance coverage.
    }
    batch.more = batch.covered.sequence < sequence_;
    subscription.sequence = batch.covered.sequence;
    subscription.touched = now_();
    return batch;
}
void EventJournal::unsubscribe(const EventScope& scope, const std::string& id) {
    validate_scope(scope);
    auto found = subscriptions_.find(id);
    if (found == subscriptions_.end()) return;
    same_scope(scope, found->second.scope);
    subscriptions_.erase(found);
}
std::string EventJournal::snapshot(const EventScope& scope, std::vector<std::string> items) {
    validate_scope(scope);
    available();
    prune();
    if (snapshots_.size() >= limits_.snapshots) throw ServiceError(ErrorCode::resource_exhausted, "Snapshot capacity exhausted");
    size_t bytes = 256 + scope.principal.size();
    if (items.capacity() > (limits_.max_snapshot_bytes - bytes) / sizeof(std::string))
        throw ServiceError(ErrorCode::resource_exhausted, "Snapshot container exceeds reserved capacity");
    bytes += items.capacity() * sizeof(std::string);
    for (const auto& item : items) {
        if (item.size() > limits_.max_event_bytes || item.capacity() + 32 > limits_.max_snapshot_bytes - bytes)
            throw ServiceError(ErrorCode::resource_exhausted, "Snapshot exceeds reserved capacity");
        bytes += item.capacity() + 32;
    }
    if (bytes > limits_.snapshot_bytes - snapshot_bytes_)
        throw ServiceError(ErrorCode::resource_exhausted, "Snapshot byte capacity exhausted");
    auto id = random_id(true);
    if (!snapshots_.emplace(id, Snapshot{scope, sequence_, now_(), std::move(items), bytes}).second)
        throw ServiceError(ErrorCode::internal, "Snapshot ID collision");
    snapshot_bytes_ += bytes;
    return id;
}
SnapshotPage EventJournal::page(const EventScope& scope, const std::string& id, size_t offset, size_t max_bytes) {
    validate_scope(scope);
    validate_page_size(max_bytes);
    available();
    prune();
    const auto found = snapshots_.find(id);
    if (found == snapshots_.end()) throw ServiceError(ErrorCode::snapshot_expired, "Snapshot expired or released");
    const auto& snapshot = found->second;
    same_scope(scope, snapshot.scope);
    if (offset > snapshot.items.size()) throw ServiceError(ErrorCode::invalid_argument, "Invalid snapshot offset");
    SnapshotPage page{id, {epoch_, snapshot.sequence}, {}, snapshot.items.size(), {}};
    size_t bytes = 0;
    for (; offset < snapshot.items.size(); ++offset) {
        const auto& item = snapshot.items[offset];
        if (item.size() + 64 > max_bytes - bytes) break;
        page.items.push_back(item);
        bytes += item.size() + 64;
    }
    if (offset < snapshot.items.size()) page.next = offset;
    return page;
}
void EventJournal::release_snapshot(const EventScope& scope, const std::string& id) {
    validate_scope(scope);
    auto found = snapshots_.find(id);
    if (found == snapshots_.end()) return;
    same_scope(scope, found->second.scope);
    snapshot_bytes_ -= found->second.bytes;
    snapshots_.erase(found);
}
}
