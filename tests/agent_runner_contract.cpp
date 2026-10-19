// SPDX-License-Identifier: GPL-3.0-or-later
#include "agent/runner.h"
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace droidvm;
using namespace droidvm::agent;
namespace {
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
struct Control final : RunnerControl {
    bool cancelled = false;
    bool permit_commit = true;
    bool cancel_after_commit = false;
    const bool* cancel_gate = nullptr;
    int commits = 0;
    bool cancellation_requested() const override { return cancelled || (commits && cancel_after_commit) || (cancel_gate && *cancel_gate); }
    bool enter_commit() override { ++commits; return permit_commit; }
};

struct Host final : RunnerHost {
    RunnerDeadline clock{};
    std::string output;
    std::string command;
    std::string writes;
    std::string secret = "Safe:123!";
    std::size_t write_size = 19;
    std::size_t read_size = 13;
    int starts = 0, shutdowns = 0, polls = 0, reads = 0, write_calls = 0, executions = 0, passwords = 0;
    int busy_reads = 0, busy_writes = 0;
    bool reject_start = false, throw_start = false, always_starting = false;
    bool idle_preparation = false, idle_action = false, password_action = false;
    bool deny_cleanup = false, throw_cleanup = false, inconsistent_cleanup = false;
    bool initial_loss = false, cursor_reset = false, generation_change = false, offset_gap = false;
    bool lost_runtime = false, unknown_write = false, throw_write = false, late_result = false;
    bool malformed_slice = false;
    bool finalized_script = false, guest_cleanup_error = false, omit_finalizer = false, disk_synced = false;
    bool script_exit_expected = false, omit_script_exit = false, omit_shell_ready = false;
    bool accept_handoff = false, throw_handoff = false, unknown_shell_write = false;
    int shell_commands = 0, handoffs = 0;
    bool shell_reply_read = false;

    void marker(std::string_view text) {
        output += "\n__DROIDVM_AGENT__:" + std::string(text) + "\n";
        if (text == "RESULT:OK" && finalized_script && !omit_finalizer)
            output += guest_cleanup_error ? "\n__DROIDVM_AGENT__:CLEANUP:ERROR\n" : "\n__DROIDVM_AGENT__:CLEANUP:OK\n";
    }
    RunnerDeadline now() const noexcept override { return clock; }
    void wait_until(RunnerDeadline until) override {
        require(until >= clock, "Runner requested a backwards wait");
        require(until - clock <= std::chrono::seconds(1), "Runner requested an unbounded wait");
        clock = until;
    }
    bool start(RunnerDeadline deadline) override {
        ++starts;
        require(deadline > clock, "Missing startup budget");
        if (throw_start) throw std::runtime_error("private host detail");
        if (!idle_preparation) output = "Linux boot\n~ #\n";
        return !reject_start;
    }
    RunState poll(RunnerDeadline deadline) override {
        ++polls;
        require(deadline > clock, "Poll used an expired deadline");
        clock += std::chrono::milliseconds(1);
        if (lost_runtime && executions) return RunState::lost;
        return always_starting ? RunState::starting : RunState::running;
    }
    std::optional<vm::LogSlice> read(const std::optional<vm::LogCursor>& cursor, RunnerDeadline deadline) override {
        ++reads;
        require(deadline > clock, "Read used an expired deadline");
        if (busy_reads > 0) { --busy_reads; return {}; }
        vm::LogSlice slice;
        slice.generation = generation_change && executions ? "new-run" : "run-one";
        slice.start = cursor ? cursor->offset : 0;
        slice.floor = 0;
        if (initial_loss && !cursor) slice.start = slice.floor = 4;
        if (offset_gap && cursor) ++slice.start;
        slice.end = output.size();
        if (slice.start <= slice.end) slice.bytes = output.substr(static_cast<std::size_t>(slice.start), read_size);
        slice.next = slice.start + slice.bytes.size();
        const std::string shell_marker = "__DROIDVM_AGENT__:SHELL:READY\n";
        const auto shell_at = output.find(shell_marker);
        if (shell_at != std::string::npos && slice.next >= shell_at + shell_marker.size()) shell_reply_read = true;
        slice.reset = cursor_reset && cursor.has_value();
        if (malformed_slice) ++slice.next;
        if (late_result && executions) clock = deadline;
        return slice;
    }
    void consume_command() {
        if (command.find("busybox setsid") == 0) marker("TTY:READY");
        else if (command.find("stty -echo") == 0) marker("READY");
        else if (command.find("rm -f /run/droidvm-rescue.b64") == 0) marker("STAGE:READY");
        else if (command.find("if printf '%s'") == 0) {
            const std::string begin = ":STAGE:CHUNK:";
            const auto at = command.find(begin);
            require(at != std::string::npos, "Chunk command omitted acknowledgement marker");
            const auto number = at + begin.size();
            marker("STAGE:CHUNK:" + command.substr(number, command.find(':', number) - number) + ":OK");
        } else if (command.find("if busybox base64") == 0) marker("SCRIPT:READY");
        else if (command.find("busybox sh /run/droidvm-rescue.sh;") == 0) {
            ++executions;
            script_exit_expected = command.find("SCRIPT:EXITED") != std::string::npos;
            if (idle_action) return;
            if (password_action) {
                marker("ACTION:START:0:chpasswd");
                output += "New password:";
            } else {
                marker("ACTION:START:0:autogrow");
                marker("AUTOGROW:PARTITION:/dev/vda1:ext4:8192");
                marker("ACTION:OK:0:autogrow");
                marker("RESULT:OK");
                if (script_exit_expected && !omit_script_exit && !omit_finalizer) marker("SCRIPT:EXITED");
            }
        } else if (password_action && command == secret + '\n') {
            if (++passwords == 1) output += "\nRetype password:";
            else {
                marker("ACTION:OK:0:chpasswd");
                marker("RESULT:OK");
                if (script_exit_expected && !omit_script_exit && !omit_finalizer) marker("SCRIPT:EXITED");
            }
        } else if (command.find("ROOT_DEVICE=$(cat /run/droidvm-root-device") == 0) {
            ++shell_commands;
            if (!omit_shell_ready) marker("SHELL:READY");
        } else throw std::runtime_error("Unexpected command sent by runner");
    }
    WriteResult write(std::string_view bytes, RunnerDeadline deadline) override {
        ++write_calls;
        require(deadline > clock, "Write used an expired deadline");
        require(!bytes.empty() && bytes.size() <= Protocol::write_limit, "Unbounded console write");
        if (busy_writes > 0) { --busy_writes; return {true, 0}; }
        const auto count = std::min(write_size, bytes.size());
        writes.append(bytes.substr(0, count));
        for (char byte : bytes.substr(0, count)) {
            command += byte;
            if (byte == '\n') { consume_command(); command.clear(); }
        }
        // Simulate accepting bytes and losing the response: runner must not retry.
        if (executions && throw_write) throw std::runtime_error("private write detail");
        if (executions && unknown_write) return {false, 0};
        if (shell_commands && unknown_shell_write) return {false, 0};
        return {true, count};
    }
    bool handoff(RunnerDeadline deadline) override {
        ++handoffs;
        require(deadline > clock && shell_commands == 1, "Ownership handoff preceded shell readiness or exceeded its deadline");
        if (throw_handoff) throw std::runtime_error("private handoff detail");
        return accept_handoff;
    }
    CleanupReport shutdown(RunnerDeadline deadline) override {
        ++shutdowns;
        require(deadline > clock, "Cleanup inherited an expired operation budget");
        if (throw_cleanup) throw std::runtime_error("private cleanup detail");
        if (inconsistent_cleanup) return {false, true, disk_synced};
        return deny_cleanup ? CleanupReport{true, false, disk_synced} : CleanupReport{true, true, disk_synced};
    }
};

RunnerLimits limits() {
    RunnerLimits value;
    value.startup_timeout = std::chrono::milliseconds(50);
    value.preparation_timeout = std::chrono::seconds(5);
    value.action_timeout = std::chrono::seconds(2);
    value.finalization_timeout = std::chrono::milliseconds(100);
    value.cleanup_timeout = std::chrono::milliseconds(100);
    value.poll_interval = std::chrono::milliseconds(5);
    return value;
}

void successful_protocol_is_only_guest_report() {
    Protocol protocol("#!/bin/sh\n", {{ActionKind::autogrow}});
    Host host;
    host.busy_reads = 2;
    host.busy_writes = 2;
    Control control;
    const auto result = run(protocol, host, control, limits());
    require(result.status == RunnerStatus::guest_reported && result.protocol.outcome == Outcome::guest_succeeded,
        "Successful transcript did not preserve guest report");
    require(result.committed && control.commits == 1 && host.executions == 1, "Commit boundary was not exactly once");
    require(result.cleanup.stopped && result.cleanup.removed && host.shutdowns == 1, "Owned VM was not cleaned up");
    require(!result.durability_confirmed, "Forced lifecycle cleanup claimed disk durability");
    require(host.command.empty(), "Partial writes duplicated/lost command bytes");
    require(host.writes.find("poweroff") == std::string::npos, "Runner injected shell input after guest result");
}

void passwords_and_unknown_write() {
    Protocol protocol("#!/bin/sh\n", {{ActionKind::password}}, "Safe:123!");
    Host host;
    host.password_action = true;
    host.write_size = 3;
    Control control;
    const auto result = run(protocol, host, control, limits());
    require(result.protocol.outcome == Outcome::guest_succeeded && host.passwords == 2,
        "Fragmented password input did not finish exactly once per prompt");
    require(result.protocol.code.empty(), "Secret escaped through public result");

    for (bool thrown : {false, true}) {
        Protocol uncertain("#!/bin/sh\n", {{ActionKind::autogrow}});
        Host lost;
        lost.unknown_write = !thrown;
        lost.throw_write = thrown;
        Control normal;
        const auto unknown = run(uncertain, lost, normal, limits());
        require(unknown.status == RunnerStatus::uncertain && unknown.reason == RunnerReason::write_unknown,
            "Unknown accepted write was not uncertain");
        require(lost.executions == 1 && lost.shutdowns == 1 && uncertain.pending_write().empty(),
            "Unknown write was replayed or not cleaned up");
    }
}

void cancellation_and_commit() {
    Protocol before("#x", {{ActionKind::autogrow}});
    Host first;
    Control cancel;
    cancel.cancelled = true;
    auto result = run(before, first, cancel, limits());
    require(result.status == RunnerStatus::cancelled && first.starts == 0 && first.shutdowns == 1,
        "Pre-start cancellation started VM or skipped cleanup");

    Protocol refused("#x", {{ActionKind::autogrow}});
    Host second;
    Control losing;
    losing.permit_commit = false;
    result = run(refused, second, losing, limits());
    require(result.status == RunnerStatus::cancelled && second.executions == 0 && !result.committed,
        "Cancelled commit still executed guest actions");

    Protocol after("#x", {{ActionKind::autogrow}});
    Host third;
    Control shutdown;
    shutdown.cancel_after_commit = true;
    result = run(after, third, shutdown, limits());
    require(result.status == RunnerStatus::uncertain && result.committed && third.shutdowns == 1,
        "Post-commit cancellation claimed safe rollback");
}

void timeout_and_lifecycle() {
    for (int scenario = 0; scenario < 5; ++scenario) {
        Protocol protocol("#x", {{ActionKind::autogrow}});
        Host host;
        Control control;
        if (scenario == 0) host.always_starting = true;
        if (scenario == 1) host.idle_preparation = true;
        if (scenario == 2) host.idle_action = true;
        if (scenario == 3) host.lost_runtime = true;
        if (scenario == 4) host.late_result = true;
        const auto result = run(protocol, host, control, limits());
        require(host.shutdowns == 1 && result.cleanup.removed, "Timeout/loss failed to clean up");
        if (scenario < 2) require(result.status == RunnerStatus::failed && !result.committed,
            "Setup timeout was misclassified");
        else require(result.status == RunnerStatus::uncertain && result.committed,
            "Action timeout/loss claimed unchanged disk");
        const auto expected = scenario == 0 ? RunnerReason::startup_timeout : scenario == 1
            ? RunnerReason::preparation_timeout : scenario == 3 ? RunnerReason::console_lost : RunnerReason::action_timeout;
        require(result.reason == expected, "Wrong timeout/lifecycle reason");
    }
}

void cursor_and_cleanup_failures() {
    for (int scenario = 0; scenario < 5; ++scenario) {
        Protocol protocol("#x", {{ActionKind::autogrow}});
        Host host;
        Control control;
        if (scenario == 0) host.initial_loss = true;
        if (scenario == 1) host.cursor_reset = true;
        if (scenario == 2) host.generation_change = true;
        if (scenario == 3) host.offset_gap = true;
        if (scenario == 4) host.malformed_slice = true;
        const auto result = run(protocol, host, control, limits());
        require(result.reason == RunnerReason::console_lost && host.shutdowns == 1,
            "Cursor discontinuity was allowed or cleanup skipped");
        require(result.status == (scenario == 2 ? RunnerStatus::uncertain : RunnerStatus::failed),
            "Cursor loss phase was misclassified");
    }
    for (int scenario = 0; scenario < 3; ++scenario) {
        Protocol protocol("#x", {{ActionKind::autogrow}});
        Host host;
        Control control;
        if (scenario == 0) host.deny_cleanup = true;
        if (scenario == 1) host.throw_cleanup = true;
        if (scenario == 2) host.inconsistent_cleanup = true;
        const auto result = run(protocol, host, control, limits());
        require(result.status == RunnerStatus::cleanup_failed && result.protocol.outcome == Outcome::guest_succeeded,
            "Cleanup failure erased guest report or claimed overall success");
        require(!result.cleanup.removed && !result.durability_confirmed && host.shutdowns == 1,
            "Incomplete cleanup released ownership or claimed durability");
    }
    for (bool thrown : {false, true}) {
        Protocol protocol("#x", {{ActionKind::autogrow}});
        Host host;
        Control control;
        host.throw_start = thrown;
        host.reject_start = !thrown;
        const auto result = run(protocol, host, control, limits());
        require(result.status == RunnerStatus::failed && host.shutdowns == 1 && host.executions == 0,
            "Partial/failed startup bypassed cleanup");
    }
}

void finalization_and_durability() {
    for (int scenario = 0; scenario < 6; ++scenario) {
        Protocol protocol("#x", {{ActionKind::autogrow}}, {}, true);
        Host host;
        Control control;
        host.finalized_script = true;
        host.disk_synced = true;
        if (scenario == 1) host.disk_synced = false;
        if (scenario == 2) host.guest_cleanup_error = true;
        if (scenario == 3) host.omit_finalizer = true;
        if (scenario == 4) host.deny_cleanup = true;
        if (scenario == 5) host.inconsistent_cleanup = true;
        const auto result = run(protocol, host, control, limits());
        require(result.protocol.guest_result == Outcome::guest_succeeded,
            "Cleanup outcome erased original guest RESULT");
        require(result.durability_confirmed == (scenario == 0),
            "Durability did not require guest finalization, worker stop, removal and inode fsync");
        require(host.shutdowns == 1 && host.executions == 1, "Finalization retried an action or cleanup");
        if (scenario == 0)
            require(result.status == RunnerStatus::guest_reported && result.protocol.guest_cleanup == GuestCleanup::succeeded,
                "Confirmed finalization did not retain guest result");
        if (scenario == 1)
            require(result.status == RunnerStatus::cleanup_failed && result.reason == RunnerReason::disk_sync_failed,
                "Host fsync failure was mistaken for guest success");
        if (scenario == 2)
            require(result.status == RunnerStatus::cleanup_failed && result.reason == RunnerReason::guest_cleanup_failed,
                "Guest cleanup failure was mistaken for host cleanup failure");
        if (scenario == 3)
            require(result.status == RunnerStatus::uncertain && result.reason == RunnerReason::finalization_timeout
                && result.protocol.guest_cleanup == GuestCleanup::uncertain,
                "Missing finalizer confirmation did not use its separate deadline");
        if (scenario >= 4)
            require(result.status == RunnerStatus::cleanup_failed, "Incomplete worker cleanup claimed success");
        if (scenario == 5)
            require(!result.cleanup.disk_synced && !result.cleanup.removed, "Host claimed fsync before worker stop");
    }

    // Backward-compatible protocol mode must never infer guest cleanup from a
    // successful host fsync alone.
    Protocol legacy("#x", {{ActionKind::autogrow}});
    Host host;
    host.disk_synced = true;
    Control control;
    const auto result = run(legacy, host, control, limits());
    require(!result.durability_confirmed && result.protocol.guest_cleanup == GuestCleanup::not_required,
        "Legacy RESULT alone was promoted to durable completion");
}

void shell_ownership_handoff() {
    for (int scenario = 0; scenario < 8; ++scenario) {
        Protocol protocol("#x", {{ActionKind::autogrow}}, {}, true, true);
        Host host;
        Control control;
        host.finalized_script = true;
        host.disk_synced = true;
        host.accept_handoff = true;
        if (scenario == 1) host.accept_handoff = false;
        if (scenario == 2) host.throw_handoff = true;
        if (scenario == 3) host.omit_script_exit = true;
        if (scenario == 4) host.omit_shell_ready = true;
        if (scenario == 5) host.unknown_shell_write = true;
        if (scenario == 6) host.guest_cleanup_error = true;
        if (scenario == 7) control.cancel_gate = &host.shell_reply_read;
        // The same finalization budget covers wrapper return AND shell handshake.
        auto budget = limits(); budget.finalization_timeout = std::chrono::milliseconds(200);
        const auto result = run(protocol, host, control, budget);
        const bool transferred = scenario == 0 || scenario == 6;
        require(result.handed_off == transferred, "Ownership was transferred without complete handoff confirmation");
        require(host.shutdowns == (transferred ? 0 : 1), "Handoff lost ownership or destroyed the transferred VM");
        require(host.executions == 1 && host.shell_commands <= 1, "Handoff replayed an action or shell command");
        if (transferred) {
            require(result.protocol.shell_ready && host.handoffs == 1 && !result.cleanup.stopped
                && !result.cleanup.removed && !result.cleanup.disk_synced && !result.durability_confirmed,
                "Live handoff falsely claimed VM cleanup or durability");
            require(result.protocol.guest_result == Outcome::guest_succeeded,
                "Handoff discarded the original guest result");
        }
        if (scenario == 1 || scenario == 2) {
            require(host.handoffs == 1 && result.cleanup.removed && !result.durability_confirmed,
                "Rejected handoff treated a re-mounted root as durably unmounted");
        }
        if (scenario == 3 || scenario == 4) {
            require(host.handoffs == 0 && result.reason == RunnerReason::finalization_timeout
                && result.status == RunnerStatus::uncertain, "Missing wrapper return or shell ACK did not time out safely");
        }
        if (scenario == 5) {
            require(host.handoffs == 0 && result.reason == RunnerReason::write_unknown && !result.durability_confirmed,
                "Unknown shell write was retried or promoted to a durable result");
        }
        if (scenario == 6) require(result.protocol.guest_cleanup == GuestCleanup::failed,
            "Rescue handoff erased the guest cleanup failure");
        if (scenario == 7) require(host.handoffs == 0 && result.status == RunnerStatus::uncertain
            && result.reason == RunnerReason::cancelled && !result.durability_confirmed,
            "Cancellation arriving with shell readiness still transferred ownership");
    }
}
}

int main() {
    try {
        successful_protocol_is_only_guest_report();
        passwords_and_unknown_write();
        cancellation_and_commit();
        timeout_and_lifecycle();
        cursor_and_cleanup_failures();
        finalization_and_durability();
        shell_ownership_handoff();
        std::cout << "Agent runner contract passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
