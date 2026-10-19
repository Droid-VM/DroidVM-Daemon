// SPDX-License-Identifier: GPL-3.0-or-later
#include "agent/runner.h"
#include <algorithm>
#include <stdexcept>

namespace droidvm::agent {
namespace {
bool valid_slice(const vm::LogSlice& slice, const std::optional<vm::LogCursor>& cursor) {
    if (slice.reset || slice.generation.empty() || slice.generation.size() > 128
        || slice.bytes.size() > Protocol::input_limit || slice.floor > slice.start
        || slice.start > slice.next || slice.next > slice.end
        || slice.next - slice.start != slice.bytes.size()) return false;
    if (!cursor) return slice.floor == 0 && slice.start == 0;
    return slice.generation == cursor->generation && slice.start == cursor->offset;
}
void validate(const RunnerLimits& limits) {
    const auto maximum = std::chrono::hours(24);
    for (auto duration : {limits.startup_timeout, limits.preparation_timeout,
        limits.action_timeout, limits.finalization_timeout, limits.cleanup_timeout}) {
        if (duration <= std::chrono::milliseconds::zero() || duration > maximum)
            throw std::invalid_argument("Invalid agent runner timeout");
    }
    if (limits.poll_interval <= std::chrono::milliseconds::zero()
        || limits.poll_interval > std::chrono::seconds(1))
        throw std::invalid_argument("Invalid agent runner poll interval");
}
RunnerStatus status_for(const ProtocolSnapshot& protocol) {
    switch (protocol.outcome) {
        case Outcome::guest_succeeded:
        case Outcome::guest_skipped:
        case Outcome::guest_partial:
        case Outcome::guest_failed: return RunnerStatus::guest_reported;
        case Outcome::uncertain: return RunnerStatus::uncertain;
        case Outcome::aborted:
            return protocol.code == "CANCELLED" ? RunnerStatus::cancelled : RunnerStatus::failed;
        case Outcome::pending: return RunnerStatus::failed;
    }
    return RunnerStatus::failed;
}
}

RunnerResult run(Protocol& protocol, RunnerHost& host, RunnerControl& control, RunnerLimits limits) {
    validate(limits);
    if (protocol.phase() != Phase::boot)
        throw std::invalid_argument("Agent runner requires a fresh protocol");
    RunnerReason reason = RunnerReason::none;
    bool committed = false;
    bool running = false;
    bool finalizing = false;
    bool shell_input = false;
    std::optional<vm::LogCursor> cursor;
    auto deadline = host.now() + limits.startup_timeout;
    auto previous_time = host.now();
    const auto terminate = [&](RunnerReason failure, AbortReason abort_reason) {
        reason = failure;
        protocol.abort(abort_reason);
    };
    const auto expired = [&] {
        if (host.now() < deadline) return false;
        terminate(finalizing ? RunnerReason::finalization_timeout : !running ? RunnerReason::startup_timeout : committed
            ? RunnerReason::action_timeout : RunnerReason::preparation_timeout, AbortReason::timeout);
        return true;
    };
    try {
        if (control.cancellation_requested()) {
            terminate(RunnerReason::cancelled, AbortReason::cancelled);
        } else if (!host.start(deadline)) {
            terminate(RunnerReason::start_rejected, AbortReason::console_lost);
        }
        while (protocol.phase() != Phase::finished) {
            const auto current = host.now();
            if (current < previous_time) {
                terminate(RunnerReason::host_exception, AbortReason::console_lost);
                break;
            }
            previous_time = current;
            if (expired()) break;
            // Ordinary TaskControl cancellation cannot win after enter_commit.
            // A forced shutdown signal after commit still means uncertain, never
            // a cancelled operation with a promise of no disk changes.
            if (control.cancellation_requested()) {
                terminate(RunnerReason::cancelled, AbortReason::cancelled);
                break;
            }
            const auto state = host.poll(deadline);
            if (expired()) break;
            if (state == RunState::stopped || state == RunState::lost
                || (running && state == RunState::starting)) {
                terminate(state == RunState::stopped ? RunnerReason::vm_stopped
                    : RunnerReason::console_lost, AbortReason::console_lost);
                break;
            }
            if (state == RunState::starting) {
                host.wait_until(std::min(deadline, host.now() + limits.poll_interval));
                continue;
            }
            if (!running) {
                running = true;
                deadline = host.now() + limits.preparation_timeout;
            }
            if (protocol.phase() == Phase::await_approval) {
                if (!control.enter_commit()) {
                    terminate(RunnerReason::cancelled, AbortReason::cancelled);
                    break;
                }
                committed = true;
                if (!protocol.begin_actions()) {
                    terminate(RunnerReason::protocol_error, AbortReason::console_lost);
                    break;
                }
                deadline = host.now() + limits.action_timeout;
            }
            const auto pending = protocol.pending_write();
            if (!pending.empty()) {
                if (protocol.phase() == Phase::shell_handshake) shell_input = true;
                WriteResult write;
                try {
                    write = host.write(pending, deadline);
                } catch (...) {
                    // A thrown write does not prove zero bytes were accepted.
                    protocol.write_unknown();
                    reason = RunnerReason::write_unknown;
                    break;
                }
                if (!write.known) {
                    protocol.write_unknown();
                    reason = RunnerReason::write_unknown;
                    break;
                }
                protocol.write_ack(write.accepted);
                if (write.accepted == 0)
                    host.wait_until(std::min(deadline, host.now() + limits.poll_interval));
                continue;
            }
            auto received = host.read(cursor, deadline);
            if (expired()) break;
            if (!received) {
                host.wait_until(std::min(deadline, host.now() + limits.poll_interval));
                continue;
            }
            const auto& slice = *received;
            if (!valid_slice(slice, cursor)) {
                terminate(RunnerReason::console_lost, AbortReason::console_lost);
                break;
            }
            cursor = vm::LogCursor{slice.generation, slice.next};
            protocol.feed(slice.bytes);
            if ((protocol.phase() == Phase::finalizing || protocol.phase() == Phase::await_script_exit
                || protocol.phase() == Phase::shell_handshake) && !finalizing) {
                finalizing = true;
                deadline = host.now() + limits.finalization_timeout;
            }
            if (protocol.phase() != Phase::finished && slice.bytes.empty())
                host.wait_until(std::min(deadline, host.now() + limits.poll_interval));
        }
    } catch (...) {
        // Host exceptions never become public text; they may include paths or
        // credentials. A committed operation is conservatively uncertain.
        terminate(RunnerReason::host_exception, AbortReason::console_lost);
    }

    auto snapshot = protocol.snapshot();
    if (snapshot.shell_ready && reason == RunnerReason::none) {
        try {
            if (control.cancellation_requested()) reason = RunnerReason::cancelled;
            else if (host.now() >= deadline) reason = RunnerReason::finalization_timeout;
            else if (host.handoff(deadline)) {
                const bool guest_cleanup_failed = snapshot.guest_cleanup == GuestCleanup::failed;
                const auto handoff_status = guest_cleanup_failed ? RunnerStatus::cleanup_failed : status_for(snapshot);
                return {std::move(snapshot), {}, handoff_status,
                    guest_cleanup_failed ? RunnerReason::guest_cleanup_failed : RunnerReason::none, committed, false, true};
            }
        } catch (...) { reason = RunnerReason::host_exception; }
    }

    // A refused/failed handoff keeps ownership here. No shell command is retried
    // and no extra cleanup text is injected into a possibly unknown foreground.
    CleanupReport cleanup;
    try {
        cleanup = host.shutdown(host.now() + limits.cleanup_timeout);
    } catch (...) {
        cleanup = {};
    }
    if (!cleanup.stopped) { cleanup.removed = false; cleanup.disk_synced = false; }
    auto status = status_for(snapshot);
    if (snapshot.shell_ready && reason != RunnerReason::none) status = RunnerStatus::uncertain;
    if (reason == RunnerReason::none && (snapshot.outcome == Outcome::aborted
        || snapshot.outcome == Outcome::uncertain)) reason = RunnerReason::protocol_error;
    if (snapshot.guest_cleanup == GuestCleanup::failed) {
        status = RunnerStatus::cleanup_failed;
        reason = RunnerReason::guest_cleanup_failed;
    }
    if (!shell_input && snapshot.guest_cleanup == GuestCleanup::succeeded && cleanup.stopped && cleanup.removed && !cleanup.disk_synced) {
        status = RunnerStatus::cleanup_failed;
        reason = RunnerReason::disk_sync_failed;
    }
    if (!cleanup.stopped || !cleanup.removed) status = RunnerStatus::cleanup_failed;
    const bool durable = !shell_input && snapshot.guest_cleanup == GuestCleanup::succeeded
        && cleanup.stopped && cleanup.removed && cleanup.disk_synced;
    return {std::move(snapshot), cleanup, status, reason, committed, durable, false};
}
}
