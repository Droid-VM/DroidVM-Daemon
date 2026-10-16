// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include <atomic>
#include <limits>
#include <unordered_map>

using namespace droidvm;
using namespace droidvm::test;
using namespace std::chrono_literals;
namespace {
const EventScope own_scope{"owner", false}, other_scope{"other", false}, admin_scope{"admin", true};
struct FakeClock {
    std::atomic<int64_t> ms{0};
    EventJournal::Now now() { return [this] { return EventJournal::Clock::time_point(std::chrono::milliseconds(ms.load())); }; }
};
void sequence_precision() {
    const uint64_t high = uint64_t(1) << 53;
    EventJournal journal({}, [] { return EventJournal::Clock::now(); }, high);
    auto snapshot = journal.snapshot(own_scope, {});
    check(journal.page(own_scope, snapshot).cursor.sequence == high, "snapshot exact uint64 cursor");
    auto subscription = journal.subscribe(own_scope, {journal.epoch(), high});
    journal.publish("changed", "resource", "owner", "Unicode 🧪");
    auto batch = journal.poll(own_scope, subscription);
    check(batch.events.size() == 1 && batch.covered.sequence == high + 1, "uint64 event sequence");
    auto event = wire::parse(batch.events[0].encoded);
    check(event["seq"].isString() && event["seq"] == "9007199254740993", "JSON sequence must be decimal text");
    check(EventCursor::parse(journal.epoch(), event["seq"].asString()).sequence == high + 1, "cursor round trip");
    for (const char* invalid : {"", "+1", "01", "-1", "1x", "18446744073709551616"})
        error(ErrorCode::invalid_argument, [&] { EventCursor::parse(journal.epoch(), invalid); });
    error(ErrorCode::resync_required, [&] { journal.subscribe(own_scope, {"old-epoch", high}); });
    error(ErrorCode::resync_required, [&] { journal.subscribe(own_scope, {journal.epoch(), high + 2}); });

    const auto max = std::numeric_limits<uint64_t>::max();
    EventJournal end({}, [] { return EventJournal::Clock::now(); }, max - 1);
    auto last = end.subscribe(own_scope, {end.epoch(), max - 1});
    end.publish("changed", "resource", "owner", {});
    check(wire::parse(end.poll(own_scope, last).events[0].encoded)["seq"] == "18446744073709551615", "UINT64_MAX preserved");
    end.publish("changed", "resource", "owner", {});
    error(ErrorCode::unavailable, [&] { end.poll(own_scope, last); });
    error(ErrorCode::unavailable, [&] { end.snapshot(own_scope, {}); });
    check(end.sequence() == max, "sequence never wraps");
}
void replay_filter_and_scope() {
    EventJournal journal;
    const EventCursor initial{journal.epoch(), 0};
    auto own = journal.subscribe(own_scope, initial), another = journal.subscribe(other_scope, initial), all = journal.subscribe(admin_scope, initial);
    journal.publish("changed", "one", "other", 1);
    journal.publish("changed", "two", "owner", 2);
    journal.publish("changed", "three", "other", 3);
    journal.publish("changed", "four", "owner", 4);
    auto first = journal.poll(own_scope, own, 1);
    check(first.events.size() == 1 && first.events[0].sequence == 2 && first.covered.sequence == 3 && first.more, "filtered coverage cursor");
    auto second = journal.poll(own_scope, own, 1);
    check(second.events.size() == 1 && second.events[0].sequence == 4 && !second.more, "ordered bounded tail");
    auto hidden = journal.poll(other_scope, another);
    check(hidden.events.size() == 2 && hidden.covered.sequence == 4, "hidden trailing events advance coverage");
    check(journal.poll(admin_scope, all).events.size() == 4, "administrator sees all events");
    // Simulate a lost response: reconnect using the client's last processed cursor.
    auto replay = journal.subscribe(own_scope, initial);
    auto repeated = journal.poll(own_scope, replay);
    check(repeated.events[0].encoded == first.events[0].encoded && repeated.events[1].encoded == second.events[0].encoded, "replay identical event identities");
    error(ErrorCode::permission_denied, [&] { journal.poll(other_scope, own); });
    error(ErrorCode::permission_denied, [&] { journal.poll({"owner", true}, own); });
    error(ErrorCode::permission_denied, [&] { journal.unsubscribe(other_scope, own); });
    journal.unsubscribe(own_scope, own);
    journal.unsubscribe(own_scope, own);
    error(ErrorCode::resync_required, [&] { journal.poll(own_scope, own); });
    check(journal.poll(own_scope, replay).events.empty(), "no duplicate within one subscription");
}
void eviction_and_publication_gap() {
    FakeClock time;
    EventLimits limits;
    limits.events = 2;
    limits.subscriptions = 1;
    EventJournal journal(limits, time.now());
    auto lag = journal.subscribe(own_scope, {journal.epoch(), 0});
    error(ErrorCode::resource_exhausted, [&] { journal.subscribe(own_scope, {journal.epoch(), 0}); });
    for (int i = 0; i < 3; ++i) journal.publish("changed", "resource", "owner", i);
    error(ErrorCode::resync_required, [&] { journal.poll(own_scope, lag); });
    error(ErrorCode::resync_required, [&] { journal.subscribe(own_scope, {journal.epoch(), 0}); });
    auto recovered = journal.subscribe(own_scope, {journal.epoch(), 1});
    check(journal.poll(own_scope, recovered).events.size() == 2, "eviction boundary preserves complete suffix");
    journal.unsubscribe(own_scope, recovered);
    time.ms = 60000;
    error(ErrorCode::resync_required, [&] { journal.subscribe(own_scope, {journal.epoch(), 2}); });
    auto tail = journal.subscribe(own_scope, {journal.epoch(), 3});
    check(journal.poll(own_scope, tail).events.empty(), "current cursor remains valid after age eviction");
    time.ms += 300000;
    error(ErrorCode::resync_required, [&] { journal.poll(own_scope, tail); });
    check(!journal.subscribe(own_scope, {journal.epoch(), 3}).empty(), "expired subscription releases slot");

    limits.events = 4096;
    limits.max_event_bytes = 1024;
    limits.event_bytes = 1536;
    EventJournal bytes(limits);
    bytes.publish("changed", "resource", "owner", std::string(500, 'x'));
    bytes.publish("changed", "resource", "owner", std::string(500, 'y'));
    error(ErrorCode::resync_required, [&] { bytes.subscribe(own_scope, {bytes.epoch(), 0}); });
    auto suffix = bytes.subscribe(own_scope, {bytes.epoch(), 1});
    check(bytes.poll(own_scope, suffix).events.size() == 1, "byte eviction");
    bytes.publish("changed", "resource", "owner", std::string(2000, 'z'));
    error(ErrorCode::resync_required, [&] { bytes.poll(own_scope, suffix); });
    auto snapshot = bytes.snapshot(own_scope, {"{}"});
    auto fresh = bytes.subscribe(own_scope, bytes.page(own_scope, snapshot).cursor);
    bytes.publish("changed", "resource", "owner", "after gap");
    check(bytes.poll(own_scope, fresh).events[0].sequence == 4, "recover after publication gap");
    bytes.missed();
    error(ErrorCode::resync_required, [&] { bytes.poll(own_scope, fresh); });
}
void snapshot_pages_and_limits() {
    FakeClock time;
    EventLimits limits;
    limits.max_event_bytes = 1024;
    limits.snapshots = 2;
    EventJournal journal(limits, time.now());
    std::vector<std::string> rows;
    for (int i = 0; i < 4; ++i) rows.push_back(wire::stringify(std::string(700, char('a' + i))));
    auto id = journal.snapshot(own_scope, rows);
    auto first = journal.page(own_scope, id, 0, 1088);
    check(first.items.size() == 1 && first.next == 1 && first.total == 4, "bounded first page");
    journal.publish("changed", "resource", "owner", "newer state");
    check(journal.page(own_scope, id, 0, 1088).items == first.items, "repeat page retains exact view");
    for (size_t i = 1; i < 4; ++i) {
        auto page = journal.page(own_scope, id, i, 1088);
        check(page.cursor.sequence == first.cursor.sequence && page.items[0] == rows[i], "pages share immutable cursor and data");
    }
    error(ErrorCode::permission_denied, [&] { journal.page(other_scope, id); });
    error(ErrorCode::permission_denied, [&] { journal.page({"owner", true}, id); });
    error(ErrorCode::permission_denied, [&] { journal.release_snapshot(other_scope, id); });
    error(ErrorCode::invalid_argument, [&] { journal.page(own_scope, id, 5); });
    error(ErrorCode::invalid_argument, [&] { journal.page(own_scope, id, 0, 1); });
    journal.snapshot(own_scope, {});
    error(ErrorCode::resource_exhausted, [&] { journal.snapshot(own_scope, {}); });
    time.ms = 30000;
    error(ErrorCode::snapshot_expired, [&] { journal.page(own_scope, id); });
    auto replacement = journal.snapshot(own_scope, {});
    journal.release_snapshot(own_scope, replacement);
    journal.release_snapshot(own_scope, replacement);

    limits.max_snapshot_bytes = 2048;
    limits.snapshot_bytes = 2048;
    EventJournal bytes(limits);
    auto full = bytes.snapshot(own_scope, {wire::stringify(std::string(999, 'x'))});
    error(ErrorCode::resource_exhausted, [&] { bytes.snapshot(own_scope, {wire::stringify(std::string(999, 'y'))}); });
    bytes.release_snapshot(own_scope, full);
    std::vector<std::string> oversized;
    oversized.reserve(1000);
    error(ErrorCode::resource_exhausted, [&] { bytes.snapshot(own_scope, std::move(oversized)); });
    check(!bytes.snapshot(own_scope, {}).empty(), "rejected view does not consume quota");
}
void snapshot_larger_than_frame() {
    EventJournal journal;
    std::vector<std::string> rows(1100, wire::stringify(std::string(8192, 'x')));
    check(rows.size() * rows[0].size() > wire::max_payload, "fixture exceeds protocol frame");
    auto id = journal.snapshot(own_scope, std::move(rows));
    size_t offset = 0, received = 0, pages = 0;
    do {
        auto page = journal.page(own_scope, id, offset);
        size_t bytes = 0;
        for (const auto& row : page.items) bytes += row.size() + 64;
        check(bytes <= (256u << 10) && page.cursor.sequence == 0 && page.total == 1100, "large snapshot page bound");
        received += page.items.size();
        ++pages;
        if (!page.next) break;
        check(*page.next > offset, "pagination must progress");
        offset = *page.next;
        journal.publish("changed", "resource", "owner", "concurrent mutation");
    } while (pages < 100);
    check(received == 1100 && pages > 1, "large snapshot complete without oversized frame");
}
Json::Value task_row(const SnapshotPage& page, const TaskRef& task) {
    for (const auto& row : page.items) {
        auto value = wire::parse(row);
        if (value["task_id"] == task.id) return value;
    }
    throw std::runtime_error("task missing from snapshot page");
}
void task_handoff_and_expiration() {
    FakeClock time;
    TaskLimits limits;
    limits.retention = 10ms;
    Gate started, progress, progressed, finish;
    TaskService service(limits, time.now());
    auto ref = service.submit(owner, spec(), [&](TaskControl& control) {
        started.release(); progress.wait();
        control.progress({"copy", "bytes", 5, {}});
        progressed.release(); finish.wait();
        check(control.enter_commit(), "handoff commit");
        return TaskCompletion::success("large result retrieved separately");
    });
    started.wait();
    auto snapshot = service.snapshot(owner);
    auto row = task_row(snapshot, ref);
    check(row == task_summary(service.get(owner, ref)), "snapshot and state cursor captured together");
    progress.release(); progressed.wait();
    auto subscription = service.subscribe(owner, snapshot.cursor);
    auto replay = service.poll(owner, subscription);
    check(replay.events.size() == 1 && wire::parse(replay.events[0].encoded)["data"]["completed"] == "5", "mutation between snapshot and registration replayed");
    check(task_row(service.snapshot_page(owner, snapshot.id, 0), ref) == row, "active snapshot never changes");
    finish.release();
    auto final = finished(service, ref);
    auto tail = service.poll(owner, subscription);
    check(tail.events.size() == 2, "commit and terminal event delivered live");
    check(wire::parse(tail.events.back().encoded)["data"] == task_summary(final), "event reconstructs current task state");
    check(!wire::parse(tail.events.back().encoded)["data"].isMember("result"), "large results excluded from event history");
    service.cancel(owner, ref);
    check(service.poll(owner, subscription).events.empty(), "terminal state published once");
    time.ms = 10;
    auto removed = service.poll(owner, subscription);
    check(removed.events.size() == 1 && wire::parse(removed.events[0].encoded)["kind"] == "task.removed", "retention expiry emits tombstone");
    error(ErrorCode::task_not_found, [&] { service.get(owner, ref); });
    check(service.poll(owner, subscription).events.empty(), "expiry tombstone only once");
    check(service.snapshot(owner).items.empty(), "expired task absent from current snapshot");
    check(task_row(service.snapshot_page(owner, snapshot.id, 0), ref) == row, "old fixed view survives resource expiry");
    error(ErrorCode::unauthenticated, [&] { service.snapshot({}); });
    error(ErrorCode::permission_denied, [&] { service.subscribe({"owner", true, false, false}, snapshot.cursor); });
    error(ErrorCode::permission_denied, [&] { service.poll(other, subscription); });
    error(ErrorCode::permission_denied, [&] { service.snapshot_page(other, snapshot.id, 0); });
    auto theirs = service.submit(other, spec(), ok);
    finished(service, theirs, other);
    check(service.snapshot(owner).items.empty(), "snapshot applies owner filter");
    check(service.snapshot(admin).items.size() == 1, "administrator snapshot scope");
}
void concurrent_snapshot_subscription() {
    TaskService service;
    for (int i = 0; i < 64; ++i) {
        Gate started, race;
        auto ref = service.submit(owner, spec(), [&](TaskControl& control) {
            started.release(); race.wait();
            for (uint64_t n = 1; n <= 3; ++n) control.progress({"copy", "bytes", n, 3});
            check(control.enter_commit(), "race commit");
            return TaskCompletion::success();
        });
        started.wait(); race.release();
        auto snapshot = service.snapshot(owner);
        auto state = task_row(snapshot, ref);
        auto id = service.subscribe(owner, snapshot.cursor);
        auto final = finished(service, ref);
        auto batch = service.poll(owner, id, 1);
        uint64_t cursor = snapshot.cursor.sequence;
        for (;;) {
            for (const auto& event : batch.events) {
                check(event.sequence > cursor, "strict replay order");
                auto data = wire::parse(event.encoded);
                if (data["resource"] == ref.id) state = data["data"];
                cursor = event.sequence;
            }
            if (!batch.more) break;
            batch = service.poll(owner, id, 1);
        }
        check(state == task_summary(final), "no snapshot-subscription race loses a transition");
        service.unsubscribe(owner, id);
        service.release_snapshot(owner, snapshot.id);
    }
}
void cancellation_and_shutdown_events() {
    TaskLimits limits;
    limits.workers = 1;
    Gate started;
    TaskService service(limits);
    auto snapshot = service.snapshot(owner);
    auto id = service.subscribe(owner, snapshot.cursor);
    auto running = service.submit(owner, spec(), [&](TaskControl& control) {
        started.release();
        const auto deadline = TaskService::Clock::now() + 5s;
        while (!control.cancellation_requested() && TaskService::Clock::now() < deadline) std::this_thread::sleep_for(1ms);
        check(control.cancellation_requested(), "shutdown cancellation requested");
        return TaskCompletion::cancelled();
    });
    started.wait();
    auto pending = service.submit(owner, spec(), ok);
    service.shutdown();
    auto batch = service.poll(owner, id);
    std::unordered_map<std::string, int> terminals;
    bool cancelling = false;
    for (const auto& event : batch.events) {
        const auto data = wire::parse(event.encoded)["data"];
        if (data["state"] == "cancelled") ++terminals[data["task_id"].asString()];
        if (data["state"] == "cancelling") cancelling = true;
        check(data["state"] != "succeeded", "shutdown queue cannot succeed");
    }
    check(cancelling && terminals[running.id] == 1 && terminals[pending.id] == 1, "shutdown emits exactly one terminal state per task");
}
void document_snapshot_limits_and_encoding() {
    FakeClock clock;
    EventLimits limits; limits.snapshots = 1;
    EventJournal journal(limits, clock.now());
    for (const auto& [raw, encoded] : std::vector<std::pair<std::string, std::string>>{{"f", "Zg=="}, {"fo", "Zm8="}, {"foo", "Zm9v"}, {std::string("\0\xff\x80", 3), "AP+A"}}) {
        auto id = journal.snapshot_document(admin_scope, std::make_shared<const std::string>(raw), "{}");
        auto page = journal.page(admin_scope, id);
        check(page.items.size() == 2 && wire::parse(page.items[1])["data"] == encoded, "base64 known vectors including padding and high bytes");
        error(ErrorCode::resource_exhausted, [&] { journal.snapshot(admin_scope, {}); });
        error(ErrorCode::permission_denied, [&] { journal.release_snapshot(own_scope, id); });
        error(ErrorCode::invalid_argument, [&] { journal.page(admin_scope, id, 3); });
        check(journal.page(admin_scope, id, 2).items.empty(), "end-of-document offset");
        journal.release_snapshot(admin_scope, id);
    }
    auto large = std::make_shared<const std::string>(100000, 'x');
    auto id = journal.snapshot_document(admin_scope, large, "{}");
    error(ErrorCode::resource_exhausted, [&] { journal.page(admin_scope, id, 1, 32u << 10); });
    clock.ms = 30001;
    error(ErrorCode::snapshot_expired, [&] { journal.page(admin_scope, id); });
    auto ordinary = journal.snapshot(admin_scope, {});
    journal.release_snapshot(admin_scope, ordinary);
    limits.max_document_snapshot_bytes = 1024;
    EventJournal tiny(limits);
    error(ErrorCode::resource_exhausted, [&] { tiny.snapshot_document(admin_scope, large, "{}"); });
    check(!tiny.snapshot(admin_scope, {}).empty(), "rejected document does not consume snapshot capacity");
}
}
int main() {
    return run({
        {"uint64_sequences_epoch_exhaustion", sequence_precision},
        {"replay_filter_scope_coverage", replay_filter_and_scope},
        {"cache_count_bytes_age_publication_gap", eviction_and_publication_gap},
        {"snapshot_pages_scope_expiry_quotas", snapshot_pages_and_limits},
        {"snapshot_larger_than_8MiB_frame", snapshot_larger_than_frame},
        {"task_snapshot_replay_live_expiration", task_handoff_and_expiration},
        {"snapshot_subscribe_64_races", concurrent_snapshot_subscription},
        {"cancellation_shutdown_event_terminals", cancellation_and_shutdown_events},
        {"document_snapshot_limits_encoding", document_snapshot_limits_and_encoding}});
}
