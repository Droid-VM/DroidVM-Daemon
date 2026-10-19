// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "agent/scripts.h"
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace droidvm::agent {

enum class Phase { boot, tty, bootstrap, stage, upload, decode, await_approval, actions,
    finalizing, await_script_exit, shell_handshake, finished };
enum class ActionState { pending, running, succeeded, skipped, failed };
// These are guest reports, never proof of disk durability or successful VM cleanup.
enum class Outcome { pending, guest_succeeded, guest_skipped, guest_partial, guest_failed, aborted, uncertain };
enum class AbortReason { cancelled, timeout, console_lost, input_overflow };
enum class GuestCleanup { not_required, pending, succeeded, failed, uncertain };

struct ActionProgress {
    ActionKind kind;
    bool optional;
    ActionState state = ActionState::pending;
    std::string code{}; // Fixed allowlist only; never guest-controlled free text.
};
struct ProtocolSnapshot {
    Phase phase;
    Outcome outcome;
    std::string code;
    std::vector<ActionProgress> actions;
    // Preserve the original RESULT even if finalization later fails or times out.
    Outcome guest_result = Outcome::pending;
    std::string guest_code;
    GuestCleanup guest_cleanup = GuestCleanup::not_required;
    std::string cleanup_code;
    bool shell_ready = false;
};

// Single-threaded, transport-independent rescue UART protocol. The caller must own
// the VM/console exclusively, feed only fresh bytes from the SAME VM incarnation,
// and abort on cursor loss/reset. Do not log feed(), pending_write(), or passwords.
// The caller owns deadlines, cancellation, file leases, shutdown and cleanup.
class Protocol final {
public:
    static constexpr std::size_t write_limit = 512;
    static constexpr std::size_t input_limit = 64 * 1024;
    static constexpr std::size_t script_limit = 64 * 1024;
    static constexpr std::size_t line_limit = 2048;

    // Handoff is opt-in and requires the trusted finalized script. The finalizer
    // report, controlling-shell return and shell handshake are separate gates.
    Protocol(std::string_view trusted_script, std::vector<Action> actions, std::string password = {},
        bool require_cleanup = false, bool handoff = false);
    ~Protocol();
    Protocol(const Protocol&) = delete;
    Protocol& operator=(const Protocol&) = delete;
    Protocol(Protocol&&) = delete;
    Protocol& operator=(Protocol&&) = delete;

    void feed(std::string_view bytes);
    // The view remains valid only until the next non-const operation. Repeated
    // calls before acknowledgement expose the same slice, NOT a new command.
    std::string_view pending_write();
    // Acknowledge the exact returned slice, including accepted==0 backpressure.
    // After any unknown write result call write_unknown(); NEVER resend it.
    void write_ack(std::size_t accepted);
    void write_unknown();
    // Must follow the runner's successful TaskControl::enter_commit(). No script
    // execution bytes are exposed before this explicit approval boundary.
    bool begin_actions();
    void abort(AbortReason reason);
    ProtocolSnapshot snapshot() const;
    Phase phase() const noexcept { return phase_; }
    Outcome outcome() const noexcept { return outcome_; }

private:
    void queue(std::string command);
    void consume_line(std::string_view line);
    void consume_marker(std::string_view marker);
    void upload_next();
    void inspect_prompt();
    void fail_protocol(std::string_view code);
    void finish(Outcome outcome, std::string_view code = {});
    void report_guest(Outcome outcome, std::string_view code = {});
    void clear_buffers();

    Phase phase_ = Phase::boot;
    Outcome outcome_ = Outcome::pending;
    std::string code_;
    std::vector<ActionProgress> actions_;
    std::string password_;
    std::string payload_;
    std::string line_;
    std::string command_;
    std::size_t write_offset_ = 0;
    std::size_t offered_ = 0;
    std::size_t payload_offset_ = 0;
    std::size_t chunk_index_ = 0;
    std::size_t next_action_ = 0;
    std::size_t password_prompts_ = 0;
    bool committed_ = false;
    bool require_cleanup_ = false;
    bool handoff_ = false;
    bool shell_ready_ = false;
    Outcome guest_result_ = Outcome::pending;
    std::string guest_code_;
    GuestCleanup guest_cleanup_ = GuestCleanup::not_required;
    std::string cleanup_code_;
};
}
