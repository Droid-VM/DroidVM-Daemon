// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "agent/rescue_sessions.h"
#include "vm/console_busy.h"
#include <atomic>
#include <future>
#include <limits>

using namespace droidvm;
using namespace droidvm::agent;
using namespace droidvm::test;
namespace {
const CallContext alice{"alice", true, true, true}, bob{"bob", true, true, true};
const std::string disk = "12345678-1234-1234-1234-123456789abc";
struct Target final : RescueTarget {
    vm::Observation observed{"incarnation", 4};
    std::atomic<size_t> reads{0}, writes{0}, closes{0};
    size_t accepted = std::numeric_limits<size_t>::max();
    bool fail_observation = false, busy_observation = false, fail_write = false, fail_close = false;
    CleanupReport cleanup{true, true, true};
    std::function<void()> on_write, on_close;
    vm::Observation observation() override {
        if (fail_observation) throw std::runtime_error("observation failure");
        if (busy_observation) throw vm::ConsoleBusy();
        return observed;
    }
    vm::LogSlice read(const vm::Observation& expected, const std::optional<vm::LogCursor>& cursor, bool tail) override {
        check(expected == observed, "target retains expected incarnation");
        ++reads;
        vm::LogSlice result; result.generation = "history"; result.bytes = tail ? "tail" : "bytes";
        result.start = cursor ? cursor->offset : 0; result.next = result.start + result.bytes.size();
        return result;
    }
    size_t write(const vm::Observation& expected, std::string_view bytes) override {
        check(expected == observed, "target atomically checks expected at write");
        ++writes;
        if (on_write) on_write();
        if (fail_write) throw std::runtime_error("unknown write progress");
        return accepted == std::numeric_limits<size_t>::max() ? bytes.size() : accepted;
    }
    CleanupReport close() override {
        ++closes;
        if (on_close) on_close();
        if (fail_close) throw std::runtime_error("cleanup incomplete");
        return cleanup;
    }
};
template<class Work> void throws(Work work) {
    try { work(); } catch (const std::exception&) { return; }
    throw std::runtime_error("expected operation failure");
}
void owned_bounded_console() {
    RescueSessions sessions;
    auto target = std::make_shared<Target>();
    const auto id = sessions.publish(alice, disk, target);
    const auto view = sessions.view(alice, id);
    check(id != target->observed.instance && id.size() == 64, "independent random session identity");
    check(view.disk_id == disk && view.expected == target->observed && !view.closing && !view.expired,
        "published target has pinned metadata");
    check(sessions.list(bob).empty(), "administration does not cross owner boundary");
    error(ErrorCode::not_found, [&] { (void)sessions.view(bob, id); });
    error(ErrorCode::not_found, [&] { (void)sessions.read(bob, id, view.expected); });
    error(ErrorCode::not_found, [&] { (void)sessions.write(bob, id, view.expected, "secret"); });
    error(ErrorCode::not_found, [&] { (void)sessions.close(bob, id); });
    error(ErrorCode::unauthenticated, [&] { (void)sessions.read({}, id, view.expected); });
    auto revoked = alice; revoked.manage_tasks = false;
    error(ErrorCode::permission_denied, [&] { (void)sessions.write(revoked, id, view.expected, "x"); });
    revoked = alice; revoked.administrator = false;
    error(ErrorCode::permission_denied, [&] { (void)sessions.list(revoked); });
    check(target->reads == 0 && target->writes == 0 && target->closes == 0, "denied calls never reach target");
    const auto slice = sessions.read(alice, id, view.expected, vm::LogCursor{"history", 17}, true);
    check(slice.bytes == "tail" && slice.start == 17, "history uses original cursor and target");
    error(ErrorCode::invalid_argument, [&] { (void)sessions.write(alice, id, view.expected, ""); });
    error(ErrorCode::invalid_argument, [&] { (void)sessions.write(alice, id, view.expected, std::string(513, 'a')); });
    check(sessions.write(alice, id, view.expected, std::string(512, 'a')) == 512, "bounded console write");
    target->accepted = 2;
    check(sessions.write(alice, id, view.expected, "partial") == 2 && target->writes == 2, "partial write is never replayed");
    target->fail_write = true;
    throws([&] { (void)sessions.write(alice, id, view.expected, "unknown"); });
    check(target->writes == 3, "unknown write progress is never retried");
    target->busy_observation = true;
    bool writer_busy = false;
    try { (void)sessions.write(alice, id, view.expected, "busy"); }
    catch (const vm::ConsoleBusy&) { throw std::runtime_error("writer exposed observation retry signal"); }
    catch (const ServiceError& error) { writer_busy = error.code() == ErrorCode::unavailable; }
    check(writer_busy && target->writes == 3, "observation busy becomes a non-retryable write error");
    target->busy_observation = false;
    auto stale = view.expected; ++stale.revision;
    error(ErrorCode::conflict, [&] { (void)sessions.read(alice, id, stale); });
    ++target->observed.revision;
    error(ErrorCode::conflict, [&] { (void)sessions.write(alice, id, view.expected, "new-run"); });
    check(target->writes == 3, "changed target cannot receive old session input");
    sessions.shutdown();
}
void publication_and_capacity() {
    RescueSessions sessions;
    auto target = std::make_shared<Target>();
    target->fail_observation = true;
    throws([&] { (void)sessions.publish(alice, disk, target); });
    check(sessions.list(alice).empty() && target->closes == 0, "failed publication leaves custody with host");
    target->fail_observation = false;
    const auto first = sessions.publish(alice, disk, target);
    error(ErrorCode::conflict, [&] { (void)sessions.publish(alice, disk, target); });
    auto alias = std::make_shared<Target>();
    error(ErrorCode::conflict, [&] { (void)sessions.publish(bob, disk, alias); });
    alias->observed.instance = "another-incarnation";
    (void)sessions.publish(bob, disk, alias);
    auto extra = std::make_shared<Target>(); extra->observed.instance = "third-incarnation";
    error(ErrorCode::resource_exhausted, [&] { (void)sessions.publish(alice, disk, extra); });
    check(sessions.list(alice).size() == 1 && sessions.list(bob).size() == 1 && extra->closes == 0,
        "capacity failure publishes nothing and does not clean caller-owned target");
    (void)sessions.close(alice, first);
    (void)sessions.publish(alice, disk, extra);
    sessions.shutdown();
    check(sessions.list(alice).empty() && sessions.list(bob).empty(), "shutdown closes all principals");
    error(ErrorCode::unavailable, [&] { (void)sessions.publish(alice, disk, target); });
}
void absolute_expiry_and_cleanup_retry() {
    auto now = RunnerDeadline{};
    RescueSessions sessions({2, 100ms}, [&] { return now; });
    auto target = std::make_shared<Target>();
    const auto id = sessions.publish(alice, disk, target);
    const auto expected = sessions.view(alice, id).expected;
    now += 99ms;
    (void)sessions.list(alice); (void)sessions.read(alice, id, expected);
    check(sessions.view(alice, id).expires == RunnerDeadline{} + 100ms, "reads do not refresh absolute TTL");
    now += 1ms;
    error(ErrorCode::unavailable, [&] { (void)sessions.read(alice, id, expected); });
    error(ErrorCode::unavailable, [&] { (void)sessions.write(alice, id, expected, "expired"); });
    check(target->closes == 0 && sessions.view(alice, id).expired, "expiry denies IO before sweep without implicit cleanup");
    target->fail_close = true;
    sessions.expire();
    check(target->closes == 1 && sessions.view(alice, id).closing, "failed sweep retains ownership for retry");
    target->fail_close = false; target->cleanup = {true, false, false};
    const auto incomplete = sessions.close(alice, id);
    check(incomplete.stopped && !incomplete.removed && sessions.list(alice).size() == 1,
        "incomplete explicit close remains registered");
    target->cleanup = {true, true, false};
    const auto closed = sessions.close(alice, id);
    check(closed.stopped && closed.removed && !closed.disk_synced && sessions.list(alice).empty(),
        "completed ownership removal never invents durability or reopens a disk");
}
void serialized_write_and_close_without_global_blocking() {
    RescueSessions sessions;
    auto target = std::make_shared<Target>();
    Gate writing, release;
    target->on_write = [&] { writing.release(); release.wait(); };
    const auto id = sessions.publish(alice, disk, target);
    const auto expected = target->observed;
    auto writer = std::async(std::launch::async, [&] { return sessions.write(alice, id, expected, "one"); });
    writing.wait();
    struct Unblock { Gate& gate; ~Unblock() { gate.release(); } } unblock{release};
    bool busy = false;
    try { (void)sessions.read(alice, id, expected); } catch (const vm::ConsoleBusy&) { busy = true; }
    check(busy, "concurrent read fails without blocking or progress");
    auto closer = std::async(std::launch::async, [&] { return sessions.close(alice, id); });
    const auto deadline = RunnerClock::now() + 2s;
    while (!sessions.view(alice, id).closing && RunnerClock::now() < deadline) std::this_thread::yield();
    check(sessions.view(alice, id).closing && target->closes == 0, "close marks closing before waiting for existing write");
    busy = false;
    try { (void)sessions.write(alice, id, expected, "two"); }
    catch (const vm::ConsoleBusy&) { throw std::runtime_error("writer exposed a read-only retry signal"); }
    catch (const ServiceError& error) { busy = error.code() == ErrorCode::unavailable; }
    check(busy && target->writes == 1, "closing entry never starts another input write");
    auto unrelated = std::make_shared<Target>(); unrelated->observed.instance = "unrelated";
    const auto other_id = sessions.publish(bob, disk, unrelated);
    check(sessions.write(bob, other_id, unrelated->observed, "other") == 5, "slow cleanup does not hold global registry lock");
    release.release();
    check(writer.get() == 3 && closer.get().removed && target->closes == 1, "close runs only after the accepted write finishes");
    sessions.shutdown();
}
void destruction_and_shutdown_failures() {
    {
        RescueSessions sessions;
        auto first = std::make_shared<Target>(), second = std::make_shared<Target>();
        second->observed.instance = "second";
        const auto first_id = sessions.publish(alice, disk, first);
        const auto second_id = sessions.publish(alice, disk, second);
        auto input_blocked = [&](const std::string& id, const vm::Observation& expected) {
            try { (void)sessions.write(alice, id, expected, "after shutdown"); }
            catch (const ServiceError& error) {
                check(error.code() == ErrorCode::unavailable || error.code() == ErrorCode::not_found,
                    "shutdown rejects every remaining entry before target cleanup");
                return;
            }
            throw std::runtime_error("shutdown left another target writable");
        };
        first->on_close = [&] { input_blocked(second_id, second->observed); };
        second->on_close = [&] { input_blocked(first_id, first->observed); };
        sessions.shutdown();
        check(first->writes == 0 && second->writes == 0 && first->closes == 1 && second->closes == 1,
            "shutdown disables all entries before its first target callback");
    }
    auto target = std::make_shared<Target>();
    {
        RescueSessions sessions;
        const auto id = sessions.publish(alice, disk, target);
        target->fail_close = true;
        sessions.shutdown();
        check(sessions.view(alice, id).closing && target->closes == 1, "shutdown failure retains closing target");
        sessions.shutdown();
        check(target->closes == 2, "explicit shutdown retries retained cleanup");
    }
    check(target->closes == 2, "destructor performs no target cleanup IO");
}
}
int main() {
    return run({{"owned_bounded_console", owned_bounded_console},
        {"publication_and_capacity", publication_and_capacity},
        {"absolute_expiry_and_cleanup_retry", absolute_expiry_and_cleanup_retry},
        {"serialized_write_and_close_without_global_blocking", serialized_write_and_close_without_global_blocking},
        {"destruction_and_shutdown_failures", destruction_and_shutdown_failures}});
}
