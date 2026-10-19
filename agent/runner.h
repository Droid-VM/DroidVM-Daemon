// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "agent/protocol.h"
#include "vm/console_history.h"
#include <chrono>
#include <optional>

namespace droidvm::agent {
using RunnerClock = std::chrono::steady_clock;
using RunnerDeadline = RunnerClock::time_point;

enum class RunState { starting, running, stopped, lost };
struct WriteResult {
    bool known = false;
    std::size_t accepted = 0;
};
struct CleanupReport {
    // Must prove the worker has stopped (native try_edit guard), not just a
    // STOPPED state observation or an accepted asynchronous stop request.
    bool stopped = false;
    bool removed = false;
    // fsync completed on retained writable disk inode leases AFTER worker stop.
    // Keep file/registry ownership until this attempt finishes. False does not
    // mean the disk is unchanged or that cleanup can roll back guest writes.
    bool disk_synced = false;
};

// Trusted host adapter, bound to one exclusively owned temporary VM. It must
// enforce the same runtime incarnation on poll/read/write and never reconnect to
// a new run. Methods must return/throw by their deadline, including shutdown.
// shutdown must be idempotent and safe after start rejection/partial failure or
// before start; removed=true requires stopped=true. Keep disk reservations when
// cleanup is incomplete. Never persist raw UART output or write payloads.
class RunnerHost {
public:
    virtual ~RunnerHost() = default;
    virtual bool start(RunnerDeadline deadline) = 0;
    virtual RunState poll(RunnerDeadline deadline) = 0;
    // nullopt is transient lock contention; it must not advance the cursor.
    virtual std::optional<vm::LogSlice> read(const std::optional<vm::LogCursor>& cursor, RunnerDeadline deadline) = 0;
    virtual WriteResult write(std::string_view bytes, RunnerDeadline deadline) = 0;
    // Explicit ownership transfer after the controlling shell acknowledges its
    // readiness. true transfers the live VM plus disk/registry reservations;
    // false/throw MUST leave ownership here for shutdown. Never return true
    // after the deadline. No new session is created by the runner itself.
    virtual bool handoff(RunnerDeadline) { return false; }
    virtual CleanupReport shutdown(RunnerDeadline deadline) = 0;
    virtual RunnerDeadline now() const noexcept = 0;
    // Cancellation-aware bounded wait where available; never create a new
    // worker/thread here. The injected monotonic clock must advance during waits.
    virtual void wait_until(RunnerDeadline deadline) = 0;
};

// Thin adapter over the EXISTING TaskControl, without another task registry.
class RunnerControl {
public:
    virtual ~RunnerControl() = default;
    virtual bool cancellation_requested() const = 0;
    virtual bool enter_commit() = 0;
};

struct RunnerLimits {
    std::chrono::milliseconds startup_timeout = std::chrono::seconds(30);
    std::chrono::milliseconds preparation_timeout = std::chrono::minutes(2);
    std::chrono::milliseconds action_timeout = std::chrono::minutes(10);
    std::chrono::milliseconds finalization_timeout = std::chrono::seconds(60);
    std::chrono::milliseconds cleanup_timeout = std::chrono::seconds(45);
    std::chrono::milliseconds poll_interval = std::chrono::milliseconds(20);
};

enum class RunnerStatus { guest_reported, cancelled, failed, uncertain, cleanup_failed };
enum class RunnerReason {
    none, cancelled, start_rejected, startup_timeout, preparation_timeout, action_timeout,
    finalization_timeout, vm_stopped, console_lost, write_unknown, host_exception, protocol_error,
    guest_cleanup_failed, disk_sync_failed
};
struct RunnerResult {
    ProtocolSnapshot protocol;
    CleanupReport cleanup;
    RunnerStatus status = RunnerStatus::failed;
    RunnerReason reason = RunnerReason::none;
    bool committed = false;
    bool durability_confirmed = false;
    bool handed_off = false;
};

// Executes synchronously in the caller's TaskService worker. Requires a fresh
// Protocol and valid positive limits (invalid arguments throw before host work).
// Unless a confirmed shell handoff transfers ownership, every valid invocation
// attempts shutdown exactly once, including cancellation and host exceptions.
// No terminal result is named "success": a
// guest report plus forced stop/remove does not establish safe unmount/durability.
// Durability additionally requires the fixed guest finalizer's CLEANUP:OK and
// fsync on retained writable disk leases after the worker has stopped.
// Handoff requires opt-in Protocol configuration, SCRIPT:EXITED, SHELL:READY and
// an explicit host ownership transfer. Its result never claims VM cleanup or
// durability. A rejected handoff is cleaned up without retrying guest commands.
RunnerResult run(Protocol& protocol, RunnerHost& host, RunnerControl& control, RunnerLimits limits = {});
}
