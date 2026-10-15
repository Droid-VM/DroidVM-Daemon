// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include <atomic>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>

using namespace droidvm;
using namespace droidvm::test;
using namespace std::chrono_literals;
namespace {
void identity_and_access() {
    TaskService service, restarted;
    check(service.epoch().size() == 36 && service.epoch() != restarted.epoch(), "unique epoch");
    auto ref = service.submit(owner, spec(), [](TaskControl&) {
        Json::Value result;
        result["unicode"] = "任务🧪";
        result["integer"] = Json::Int64(INT64_MAX);
        result["empty"] = Json::Value(Json::arrayValue);
        return TaskCompletion::success(result);
    });
    const auto value = finished(service, ref);
    check(ref.id.size() == 36 && ref.epoch == service.epoch(), "task identity");
    check(value.state == TaskState::succeeded && !value.cancellable, "success terminal state");
    check(value.finished && *value.finished >= value.created, "monotonic timestamps");
    check(value.result["unicode"] == "任务🧪" && value.result["integer"].asInt64() == INT64_MAX, "result fidelity");
    check(value.result["empty"].isArray() && value.result["empty"].empty(), "empty array");
    error(ErrorCode::unauthenticated, [&] { service.get({}, ref); });
    error(ErrorCode::permission_denied, [&] { service.submit({"owner", true, false, true}, spec(), ok); });
    error(ErrorCode::permission_denied, [&] { service.get(other, ref); });
    error(ErrorCode::permission_denied, [&] { service.cancel(other, ref); });
    check(service.get(admin, ref).state == TaskState::succeeded, "administrator access");
    check(service.cancel(owner, ref).state == TaskState::succeeded, "terminal cancel immutable");
    error(ErrorCode::task_epoch_mismatch, [&] { restarted.get(owner, ref); });
    error(ErrorCode::task_epoch_mismatch, [&] { restarted.cancel(owner, ref); });
    error(ErrorCode::task_not_found, [&] { service.get(owner, {service.epoch(), "missing"}); });
    error(ErrorCode::invalid_argument, [&] { service.submit(owner, {"", "", 256, true}, ok); });
    error(ErrorCode::invalid_argument, [&] { service.submit(owner, spec(), {}); });
    error(ErrorCode::invalid_argument, [&] { service.submit(owner, spec(3), ok); });
    check(std::string(error_code_name(ErrorCode::task_epoch_mismatch)) == "TASK_EPOCH_MISMATCH", "stable code");
}

void queue_and_cleanup() {
    TaskLimits limits;
    limits.workers = 1;
    limits.queued = 2;
    Gate started, release, cleaning, cleanup_done;
    std::atomic<int> side_effects{0};
    TaskService service(limits);
    auto running = service.submit(owner, spec(), [&](TaskControl& control) {
        control.progress({"copy", "bytes", 3, {}});
        started.release();
        release.wait();
        check(control.cancellation_requested(), "cancel requested");
        check(!control.enter_commit(), "cancellation must beat commit");
        cleaning.release();
        cleanup_done.wait();
        return TaskCompletion::cancelled();
    });
    started.wait();
    auto pending_spec = spec();
    pending_spec.cancellable = false; // Still cancellable before the work starts.
    auto pending = service.submit(owner, pending_spec, [&](TaskControl&) { ++side_effects; return TaskCompletion::success(); });
    auto second = service.submit(owner, spec(), ok);
    check(service.get(owner, pending).state == TaskState::queued && service.get(owner, pending).cancellable, "queued state");
    error(ErrorCode::resource_exhausted, [&] { service.submit(owner, spec(), [&](TaskControl&) { ++side_effects; return TaskCompletion::success(); }); });
    check(service.cancel(owner, pending).state == TaskState::cancelled, "cancel queued");
    auto replacement = service.submit(owner, spec(), ok); // Cancel releases the queue slot.
    const auto before = TaskService::Clock::now();
    check(service.get(owner, running).progress.completed == 3, "query while pool is busy");
    check(!service.get(owner, running).progress.total.has_value(), "unknown total remains unknown");
    check(service.cancel(owner, running).state == TaskState::cancelling, "request running cancellation");
    check(service.cancel(owner, running).state == TaskState::cancelling, "repeat running cancellation");
    check(TaskService::Clock::now() - before < 1s, "control operations blocked behind worker");
    release.release();
    cleaning.wait();
    check(service.get(owner, running).state == TaskState::cancelling, "must await cleanup");
    cleanup_done.release();
    check(finished(service, running).state == TaskState::cancelled, "cleanup completed");
    check(finished(service, second).state == TaskState::succeeded, "queued work executes");
    check(finished(service, replacement).state == TaskState::succeeded && side_effects == 0, "no rejected or cancelled side effects");
}

void retention_and_reservation() {
    std::atomic<int64_t> milliseconds{0};
    auto now = [&] { return TaskService::Clock::time_point(std::chrono::milliseconds(milliseconds.load())); };
    TaskLimits limits;
    limits.records = 1;
    TaskService service(limits, now);
    auto ref = service.submit(owner, spec(), ok);
    check(finished(service, ref).state == TaskState::succeeded, "retained result");
    milliseconds = 1799999;
    check(service.get(owner, ref).state == TaskState::succeeded, "retain full 30 minutes");
    error(ErrorCode::resource_exhausted, [&] { service.submit(owner, spec(), ok); });
    milliseconds = 1800000;
    error(ErrorCode::task_not_found, [&] { service.get(owner, ref); });
    auto next = service.submit(owner, spec(), ok);
    check(finished(service, next).state == TaskState::succeeded && next.id != ref.id, "reclaim expired slot");

    limits.records = 8;
    limits.retained_bytes = 4096 + 32;
    TaskService bytes(limits, now);
    Gate started, release;
    auto active = bytes.submit(owner, spec(32), [&](TaskControl&) { started.release(); release.wait(); return TaskCompletion::success(); });
    started.wait();
    milliseconds += 1800000;
    // An active record is never evicted, even when it outlives retention.
    error(ErrorCode::resource_exhausted, [&] { bytes.submit(owner, spec(32), ok); });
    release.release();
    check(finished(bytes, active).state == TaskState::succeeded, "active record retained");
    error(ErrorCode::resource_exhausted, [&] { bytes.submit(owner, spec(32), ok); });
    milliseconds += 1800000;
    check(finished(bytes, bytes.submit(owner, spec(32), ok)).state == TaskState::succeeded, "byte reservation released");
}

void failure_and_progress() {
    Json::Value exact = "\n\"";
    const auto encoded = wire::stringify(exact);
    check(wire::stringify_bounded(exact, encoded.size()) == encoded, "exact escaped JSON size");
    bool overflow = false;
    try { wire::stringify_bounded(exact, encoded.size() - 1); }
    catch (const std::length_error&) { overflow = true; }
    check(overflow, "escaped JSON byte limit");
    TaskService service;
    auto ref = service.submit(owner, spec(4), [](TaskControl&) { return TaskCompletion::success(std::string(10000, 'x')); });
    auto result = finished(service, ref);
    check(result.state == TaskState::failed && result.error == ErrorCode::resource_exhausted, "bounded retained result");
    check(result.result.isNull(), "oversized result not retained");
    auto exception = service.submit(owner, spec(), [](TaskControl&) -> TaskCompletion { throw std::runtime_error("SECRET /private/path"); });
    result = finished(service, exception);
    check(result.error == ErrorCode::internal && result.message == "Task failed", "sanitize unknown exceptions");
    auto invalid_cancel = service.submit(owner, spec(), [](TaskControl&) { return TaskCompletion::cancelled(); });
    check(finished(service, invalid_cancel).error == ErrorCode::internal, "no invented cancellation");
    auto progress = service.submit(owner, spec(), [](TaskControl& control) {
        control.progress({"scan", "items", 0, {}});
        control.progress({"scan", "items", 3, 5});
        error(ErrorCode::invalid_argument, [&] { control.progress({"scan", "items", 2, 5}); });
        error(ErrorCode::invalid_argument, [&] { control.progress({"scan", "items", 6, 5}); });
        error(ErrorCode::invalid_argument, [&] { control.progress({std::string(129, 'x'), "items", 0, {}}); });
        control.progress({"commit", "items", 0, 1});
        return TaskCompletion::success();
    });
    result = finished(service, progress);
    check(result.state == TaskState::succeeded && result.progress.phase == "commit", "progress phase change");
    Gate started, release;
    auto cleanup_failure = service.submit(owner, spec(), [&](TaskControl&) {
        started.release(); release.wait();
        return TaskCompletion::failure(ErrorCode::io_error, "Cleanup failed");
    });
    started.wait();
    service.cancel(owner, cleanup_failure);
    release.release();
    result = finished(service, cleanup_failure);
    check(result.state == TaskState::failed && result.error == ErrorCode::io_error, "cleanup failure must not claim cancelled");
    Gate started2, release2;
    auto ignored_cancel = service.submit(owner, spec(), [&](TaskControl&) { started2.release(); release2.wait(); return TaskCompletion::success(); });
    started2.wait();
    service.cancel(owner, ignored_cancel);
    release2.release();
    check(finished(service, ignored_cancel).error == ErrorCode::internal, "accepted cancel cannot become success");
    auto last = service.submit(owner, spec(), ok);
    check(finished(service, last).state == TaskState::succeeded, "worker survives callback errors");
}

void independent_call_context() {
    Gate started, release;
    TaskService service;
    TaskRef ref;
    {
        CallContext temporary = owner;
        auto uncancellable = spec();
        uncancellable.cancellable = false;
        ref = service.submit(temporary, uncancellable, [&](TaskControl&) {
            started.release(); release.wait();
            return TaskCompletion::success("retained after caller lifetime");
        });
        temporary.principal = "changed";
    }
    started.wait();
    check(service.get(owner, ref).owner == owner.principal, "task owns stable identity");
    error(ErrorCode::not_cancellable, [&] { service.cancel(owner, ref); });
    release.release();
    check(finished(service, ref).state == TaskState::succeeded, "call context lifetime cannot cancel work");
}

void commit_and_cancel_race() {
    TaskService service;
    for (int i = 0; i < 128; ++i) {
        Gate started, race;
        std::atomic<bool> committed{false}, accepted{false}, expected_cancel_reply{false};
        auto ref = service.submit(owner, spec(), [&](TaskControl& control) {
            started.release(); race.wait();
            if (!control.enter_commit()) return TaskCompletion::cancelled();
            committed = true;
            return TaskCompletion::success();
        });
        started.wait();
        std::thread cancellation([&] {
            race.wait();
            try {
                const auto value = service.cancel(owner, ref);
                accepted = value.state == TaskState::cancelling;
                expected_cancel_reply = accepted || value.state == TaskState::succeeded;
            } catch (const ServiceError& e) { expected_cancel_reply = e.code() == ErrorCode::not_cancellable; }
        });
        race.release();
        cancellation.join();
        const auto value = finished(service, ref);
        check(expected_cancel_reply, "race cancel response");
        check(committed != accepted, "exactly one of commit and cancellation wins");
        check(value.state == (committed ? TaskState::succeeded : TaskState::cancelled), "race terminal outcome");
        check(service.cancel(owner, ref).state == value.state, "terminal state is immutable");
    }
    // Deterministically test the commit-first branch as well.
    Gate committed, release;
    auto ref = service.submit(owner, spec(), [&](TaskControl& control) {
        check(control.enter_commit(), "commit accepted");
        committed.release(); release.wait();
        return TaskCompletion::success();
    });
    committed.wait();
    error(ErrorCode::not_cancellable, [&] { service.cancel(owner, ref); });
    release.release();
    check(finished(service, ref).state == TaskState::succeeded, "commit-first success");
}

void bounded_workers_and_shutdown() {
    TaskLimits limits;
    limits.workers = 2;
    Gate release;
    std::atomic<int> started{0}, active{0}, peak{0}, pending_effects{0};
    TaskService service(limits);
    auto work = [&](TaskControl& control) {
        int count = ++active;
        int old = peak.load();
        while (old < count && !peak.compare_exchange_weak(old, count)) {}
        ++started;
        release.wait();
        const auto deadline = TaskService::Clock::now() + 5s;
        while (!control.cancellation_requested() && TaskService::Clock::now() < deadline) std::this_thread::sleep_for(1ms);
        check(control.cancellation_requested(), "shutdown requests cancellation");
        --active;
        return TaskCompletion::cancelled();
    };
    auto one = service.submit(owner, spec(), work), two = service.submit(owner, spec(), work);
    const auto deadline = TaskService::Clock::now() + 5s;
    while (started != 2 && TaskService::Clock::now() < deadline) std::this_thread::sleep_for(1ms);
    check(started == 2, "two workers started");
    auto queued = service.submit(owner, spec(), [&](TaskControl&) { ++pending_effects; return TaskCompletion::success(); });
    check(service.get(owner, queued).state == TaskState::queued && peak == 2, "fixed worker limit");
    release.release();
    service.shutdown();
    service.shutdown();
    check(active == 0 && pending_effects == 0, "shutdown joins workers without running queue");
    for (const auto& ref : {one, two, queued}) check(service.get(owner, ref).state == TaskState::cancelled, "shutdown cancellation");
    error(ErrorCode::unavailable, [&] { service.submit(owner, spec(), ok); });

    TaskService committed_service;
    Gate committed, finish_commit;
    std::atomic<bool> shutdown_done{false};
    auto ref = committed_service.submit(owner, spec(), [&](TaskControl& control) {
        check(control.enter_commit(), "enter commit before shutdown");
        committed.release(); finish_commit.wait();
        check(!control.cancellation_requested(), "shutdown cannot cancel an irreversible commit");
        return TaskCompletion::success();
    });
    committed.wait();
    std::thread shutdown([&] { committed_service.shutdown(); shutdown_done = true; });
    // Queries remain available while shutdown waits for a committing worker.
    check(committed_service.get(owner, ref).state == TaskState::running && !shutdown_done, "shutdown must join commit");
    finish_commit.release();
    shutdown.join();
    check(committed_service.get(owner, ref).state == TaskState::succeeded && shutdown_done, "committed work finishes during shutdown");
}
}
int main() {
    return run({
            std::pair{"identity_access_epoch", &identity_and_access},
            std::pair{"bounded_queue_cancellation_cleanup", &queue_and_cleanup},
            std::pair{"retention_reserved_capacity", &retention_and_reservation},
            std::pair{"failure_progress", &failure_and_progress},
            std::pair{"independent_call_context", &independent_call_context},
            std::pair{"commit_cancel_128_races", &commit_and_cancel_race},
            std::pair{"bounded_workers_shutdown", &bounded_workers_and_shutdown}});
}
