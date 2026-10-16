// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "context.h"
#include <json/json.h>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace droidvm {
struct EventCursor {
    std::string epoch;
    uint64_t sequence = 0;
    static EventCursor parse(std::string epoch, std::string_view decimal);
};
// This is a trusted authorization scope, never copied from business JSON.
struct EventScope { std::string principal; bool administrator = false; };
struct EventLimits {
    size_t events = 4096, event_bytes = 8u << 20, max_event_bytes = 16u << 10;
    std::chrono::milliseconds event_age = std::chrono::seconds(60);
    size_t subscriptions = 64;
    std::chrono::milliseconds subscription_age = std::chrono::minutes(5);
    size_t snapshots = 8, snapshot_bytes = 32u << 20, max_snapshot_bytes = 16u << 20;
    std::chrono::milliseconds snapshot_age = std::chrono::seconds(30);
    // Configuration rows can exceed an event; still fit one maximum-size page.
    size_t max_snapshot_item_bytes = (1u << 20) - 64;
    // A full 16 MiB configuration plus metadata; charged to snapshot_bytes too.
    size_t max_document_snapshot_bytes = 17u << 20;
};
struct EventItem {
    uint64_t sequence;
    std::string owner;
    // Encoded once with decimal-string seq. Only explicit subscribers receive it.
    std::string encoded;
    bool administrator_only = false;
};
struct EventBatch {
    EventCursor covered;
    std::vector<EventItem> events;
    bool more = false;
};
struct SnapshotPage {
    std::string id;
    EventCursor cursor;
    std::vector<std::string> items;
    size_t total = 0;
    std::optional<size_t> next;
};

// Low-level journal: its owning service MUST hold the same state mutex for
// every call, including state mutation, publish, and snapshot row collection.
// It owns no sockets, worker threads, domain state or callbacks into services.
class EventJournal {
public:
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;
    explicit EventJournal(EventLimits limits = {}, Now now = [] { return Clock::now(); }, uint64_t initial_sequence = 0);
    EventJournal(const EventJournal&) = delete;
    EventJournal& operator=(const EventJournal&) = delete;
    const std::string& epoch() const { return epoch_; }
    uint64_t sequence() const { return sequence_; }
    const EventLimits& limits() const { return limits_; }
    // Publication cannot undo a committed domain operation. Allocation/encoding
    // failure creates a replay gap instead of silently losing a state change.
    void publish(std::string_view kind, std::string_view resource, std::string_view owner, const Json::Value& data, bool administrator_only = false) noexcept;
    void missed() noexcept;
    std::string subscribe(const EventScope& scope, const EventCursor& cursor);
    EventBatch poll(const EventScope& scope, const std::string& subscription, size_t max_events = 64, size_t max_bytes = 256u << 10);
    void unsubscribe(const EventScope& scope, const std::string& subscription);
    std::string snapshot(const EventScope& scope, std::vector<std::string> items);
    // Raw immutable JSON is retained once; page encodes bounded base64 chunks.
    // metadata is an encoded JSON row describing the revision and byte count.
    std::string snapshot_document(const EventScope& scope, std::shared_ptr<const std::string> document, std::string metadata);
    SnapshotPage page(const EventScope& scope, const std::string& snapshot, size_t offset = 0, size_t max_bytes = 256u << 10);
    void release_snapshot(const EventScope& scope, const std::string& snapshot);
private:
    struct CachedEvent { EventItem item; Clock::time_point created; size_t bytes; };
    struct Subscription { EventScope scope; uint64_t sequence; Clock::time_point touched; };
    struct Snapshot { EventScope scope; uint64_t sequence; Clock::time_point created; std::vector<std::string> items; size_t bytes;
        std::shared_ptr<const std::string> document; };
    EventLimits limits_;
    Now now_;
    const std::string epoch_;
    uint64_t sequence_, floor_;
    bool exhausted_ = false;
    size_t event_bytes_ = 0, snapshot_bytes_ = 0;
    std::deque<CachedEvent> events_;
    std::unordered_map<std::string, Subscription> subscriptions_;
    std::unordered_map<std::string, Snapshot> snapshots_;
    void available() const;
    bool advance() noexcept;
    void clear_history() noexcept;
    void prune();
    void validate_cursor(const EventCursor& cursor) const;
    void validate_page_size(size_t bytes) const;
};
}
