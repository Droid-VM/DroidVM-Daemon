// SPDX-License-Identifier: GPL-3.0-or-later
#include "agent/protocol.h"
#include "agent/plan.h"
#include "common/wire.h"
#include <algorithm>
#include <array>
#include <stdexcept>

namespace droidvm::agent {
namespace {
constexpr std::string_view prefix = "__DROIDVM_AGENT__:";
constexpr std::size_t payload_chunk = 1024;

// Best-effort erasure of owned buffers; the console/runner must also suppress
// persistent UART logs. This cannot erase copies held by the transport or caller.
void erase(std::string& value) noexcept {
    volatile char* bytes = value.empty() ? nullptr : &value[0];
    for (std::size_t i = 0; i < value.size(); ++i) bytes[i] = 0;
    value.clear();
}
bool starts_with(std::string_view value, std::string_view start) {
    return value.size() >= start.size() && value.substr(0, start.size()) == start;
}
bool ends_with(std::string_view value, std::string_view end) {
    return value.size() >= end.size() && value.substr(value.size() - end.size()) == end;
}
std::string safe_error(std::string_view code) {
    constexpr std::array codes{
        "ROOT_NOT_FOUND", "PASSWD_FAILED", "PASSWD_NOT_FOUND", "UNMOUNT_FAILED", "SCRIPT_FAILED",
        "AUTOGROW_DISK_NOT_FOUND", "AUTOGROW_PROBE_FAILED", "AUTOGROW_PARTITION_IN_USE",
        "PARTITION_GROW_FAILED", "PARTITION_REREAD_FAILED", "FILESYSTEM_CHECK_FAILED",
        "FILESYSTEM_MOUNT_FAILED", "FILESYSTEM_GROW_FAILED", "FILESYSTEM_UNMOUNT_FAILED"};
    for (auto known : codes) if (code == known) return known;
    return "UNKNOWN_AGENT_ERROR";
}
std::string safe_skip(std::string_view code) {
    constexpr std::array codes{"NO_PARTITION", "UNKNOWN_FILESYSTEM", "NO_TRAILING_SPACE"};
    for (auto known : codes) if (code == known) return known;
    if (starts_with(code, "UNSUPPORTED_FILESYSTEM:")) return "UNSUPPORTED_FILESYSTEM";
    return "UNKNOWN_AGENT_SKIP";
}
std::string error_marker() {
    return "printf '\\n__DROIDVM_%s:RESULT:ERROR:SCRIPT_FAILED\\n' AGENT__";
}
}

Protocol::Protocol(std::string_view trusted_script, std::vector<Action> actions, std::string password,
        bool require_cleanup, bool handoff) : require_cleanup_(require_cleanup), handoff_(handoff) {
    // Validate before retaining credentials. No command/script supplied by a
    // remote client may reach this constructor; scripts come from scripts.h.
    std::size_t password_actions = 0;
    for (const auto& action : actions) {
        if (action.kind == ActionKind::password) ++password_actions;
        else if (action.kind != ActionKind::autogrow || action.normal_users) {
            erase(password);
            throw std::invalid_argument("Invalid agent action");
        }
    }
    if (trusted_script.empty() || trusted_script.size() > script_limit || actions.empty()
        || actions.size() > 16 || password_actions > 1
        || (handoff && !require_cleanup)
        || (password_actions == 1 ? !valid_password(password) : !password.empty())) {
        erase(password);
        throw std::invalid_argument("Invalid agent protocol input");
    }
    try {
        payload_ = wire::encode_base64(trusted_script);
        for (const auto& action : actions) actions_.push_back({action.kind, action.optional});
        password_ = password;
        erase(password);
        line_.reserve(line_limit);
        command_.reserve(line_limit);
    } catch (...) {
        erase(password);
        clear_buffers();
        throw;
    }
}

Protocol::~Protocol() { clear_buffers(); }

void Protocol::clear_buffers() {
    erase(password_);
    erase(line_);
    erase(command_);
    erase(payload_);
    write_offset_ = offered_ = 0;
}

ProtocolSnapshot Protocol::snapshot() const {
    return {phase_, outcome_, code_, actions_, guest_result_, guest_code_, guest_cleanup_, cleanup_code_, shell_ready_};
}

void Protocol::finish(Outcome outcome, std::string_view code) {
    if (phase_ == Phase::finished) return;
    code_ = code;
    outcome_ = outcome;
    phase_ = Phase::finished;
    clear_buffers();
}

void Protocol::fail_protocol(std::string_view code) {
    if (guest_cleanup_ == GuestCleanup::pending) guest_cleanup_ = GuestCleanup::uncertain;
    finish(committed_ ? Outcome::uncertain : Outcome::aborted, code);
}

void Protocol::report_guest(Outcome outcome, std::string_view code) {
    guest_result_ = outcome;
    guest_code_ = code;
    erase(password_);
    if (require_cleanup_ && committed_) {
        // The fixed wrapper owns finalization. Never send additional shell or
        // password input after RESULT; the original action may have failed.
        phase_ = Phase::finalizing;
        return;
    }
    finish(outcome, code);
}

void Protocol::abort(AbortReason reason) {
    switch (reason) {
        case AbortReason::cancelled: fail_protocol("CANCELLED"); break;
        case AbortReason::timeout: fail_protocol("TIMEOUT"); break;
        case AbortReason::console_lost: fail_protocol("CONSOLE_LOST"); break;
        case AbortReason::input_overflow: fail_protocol("INPUT_OVERFLOW"); break;
    }
}

void Protocol::queue(std::string command) {
    if (phase_ == Phase::finished) { erase(command); return; }
    if (!command_.empty() || command.empty() || command.size() > line_limit) {
        erase(command);
        fail_protocol("PROTOCOL_ORDER");
        return;
    }
    command_ = command;
    erase(command);
    write_offset_ = offered_ = 0;
}

std::string_view Protocol::pending_write() {
    if (command_.empty()) return {};
    offered_ = std::min(write_limit, command_.size() - write_offset_);
    return std::string_view(command_).substr(write_offset_, offered_);
}

void Protocol::write_ack(std::size_t accepted) {
    if (phase_ == Phase::finished) return;
    if (!offered_ || accepted > offered_) { fail_protocol("INVALID_WRITE_ACK"); return; }
    write_offset_ += accepted;
    offered_ = 0;
    if (write_offset_ == command_.size()) {
        erase(command_);
        write_offset_ = 0;
    }
}

void Protocol::write_unknown() {
    // Even a bootstrap write with an unknown acceptance count must not replay.
    fail_protocol("WRITE_UNCERTAIN");
}

bool Protocol::begin_actions() {
    if (phase_ != Phase::await_approval || !command_.empty()) return false;
    committed_ = true;
    if (require_cleanup_) guest_cleanup_ = GuestCleanup::pending;
    phase_ = Phase::actions;
    auto command = "busybox sh /run/droidvm-rescue.sh; rc=$?; rm -f /run/droidvm-rescue.sh; "
        "[ $rc -eq 0 ] || " + error_marker();
    // This marker belongs to the controlling shell, outside the action script
    // and its finalizer. RESULT/CLEANUP alone do not prove stdin is safe to use.
    if (handoff_) command += "; printf '\\n__DROIDVM_%s:SCRIPT:EXITED\\n' AGENT__";
    queue(command + '\n');
    return phase_ == Phase::actions;
}

void Protocol::feed(std::string_view bytes) {
    if (phase_ == Phase::finished) return;
    if (bytes.size() > input_limit) { abort(AbortReason::input_overflow); return; }
    for (char byte : bytes) {
        if (phase_ == Phase::finished) return;
        if (byte == '\n') {
            if (!line_.empty() && line_.back() == '\r') line_.pop_back();
            // consume_line may finish and erase line_; it never uses its view
            // after that transition.
            consume_line(line_);
            erase(line_);
            continue;
        }
        if (line_.size() == line_limit) { abort(AbortReason::input_overflow); return; }
        line_.push_back(byte);
        if (phase_ == Phase::boot && (ends_with(line_, "~ #")
            || ends_with(line_, "Run /bin/sh as init process"))) {
            phase_ = Phase::tty;
            queue("busybox setsid -c sh -c 'printf \"\\n__DROIDVM_%s:TTY:READY\\n\" AGENT__; exec sh'\n");
        } else if (phase_ == Phase::actions) {
            inspect_prompt();
        }
    }
}

void Protocol::consume_line(std::string_view line) {
    if (starts_with(line, prefix)) consume_marker(line.substr(prefix.size()));
}

void Protocol::upload_next() {
    if (payload_offset_ == payload_.size()) {
        erase(payload_);
        phase_ = Phase::decode;
        queue("if busybox base64 -d < /run/droidvm-rescue.b64 > /run/droidvm-rescue.sh "
              "&& busybox sh -n /run/droidvm-rescue.sh; then rm -f /run/droidvm-rescue.b64; "
              "printf '\\n__DROIDVM_%s:SCRIPT:READY\\n' AGENT__; "
              "else rm -f /run/droidvm-rescue.b64 /run/droidvm-rescue.sh; " + error_marker() + "; fi\n");
        return;
    }
    phase_ = Phase::upload;
    const auto chunk = payload_.substr(payload_offset_, payload_chunk);
    payload_offset_ += chunk.size();
    queue("if printf '%s' '" + chunk + "' >> /run/droidvm-rescue.b64; then "
          "printf '\\n__DROIDVM_%s:STAGE:CHUNK:" + std::to_string(chunk_index_)
          + ":OK\\n' AGENT__; else " + error_marker() + "; fi\n");
}

void Protocol::consume_marker(std::string_view marker) {
    if (!command_.empty()) { fail_protocol("PROTOCOL_ORDER"); return; }
    if (phase_ == Phase::finalizing) {
        if (marker == "CLEANUP:OK") {
            guest_cleanup_ = GuestCleanup::succeeded;
            if (handoff_) phase_ = Phase::await_script_exit;
            else finish(guest_result_, guest_code_);
            return;
        }
        if (marker == "CLEANUP:ERROR") {
            cleanup_code_ = "GUEST_CLEANUP_FAILED";
            guest_cleanup_ = GuestCleanup::failed;
            if (handoff_) phase_ = Phase::await_script_exit;
            else finish(Outcome::uncertain, cleanup_code_);
            return;
        }
        fail_protocol("PROTOCOL_ORDER");
        return;
    }
    if (phase_ == Phase::await_script_exit) {
        if (marker != "SCRIPT:EXITED") { fail_protocol("PROTOCOL_ORDER"); return; }
        phase_ = Phase::shell_handshake;
        // Fixed App-equivalent handoff. This may re-mount the target read/write,
        // so the earlier guest cleanup report is not a new durability guarantee.
        queue("ROOT_DEVICE=$(cat /run/droidvm-root-device 2>/dev/null); "
              "if [ -n \"$ROOT_DEVICE\" ] && ! mountpoint -q /mnt; then "
              "mount -o rw \"$ROOT_DEVICE\" /mnt >/dev/null 2>&1 || true; fi; "
              "if mountpoint -q /mnt; then printf '\\nDroidVM rescue shell; target root: /mnt\\n'; "
              "else printf '\\nDroidVM rescue shell\\n'; fi; "
              "PS1='droidvm-rescue # '; stty echo; "
              "printf '\\n__DROIDVM_%s:SHELL:READY\\n' AGENT__\n");
        return;
    }
    if (phase_ == Phase::shell_handshake) {
        if (marker != "SHELL:READY") { fail_protocol("PROTOCOL_ORDER"); return; }
        shell_ready_ = true;
        if (guest_cleanup_ == GuestCleanup::failed) finish(Outcome::uncertain, cleanup_code_);
        else finish(guest_result_, guest_code_);
        return;
    }
    constexpr std::string_view result_error = "RESULT:ERROR:";
    if (starts_with(marker, result_error)) {
        const auto code = safe_error(marker.substr(result_error.size()));
        const bool setup_failed = (phase_ == Phase::stage || phase_ == Phase::upload
            || phase_ == Phase::decode) && code == "SCRIPT_FAILED";
        const bool required_failed = next_action_ && actions_[next_action_ - 1].state == ActionState::failed
            && !actions_[next_action_ - 1].optional && actions_[next_action_ - 1].code == code;
        if (!setup_failed && !(phase_ == Phase::actions && (code == "SCRIPT_FAILED" || required_failed))) {
            fail_protocol("PROTOCOL_ORDER"); return;
        }
        report_guest(Outcome::guest_failed, code);
        return;
    }
    switch (phase_) {
        case Phase::tty:
            if (marker != "TTY:READY") break;
            phase_ = Phase::bootstrap;
            queue("stty -echo 2>/dev/null; mount -t proc proc /proc 2>/dev/null || true; "
                  "mount -t sysfs sysfs /sys 2>/dev/null || true; "
                  "mount -t devtmpfs devtmpfs /dev 2>/dev/null || true; busybox mdev -s; "
                  "printf '\\n__DROIDVM_%s:READY\\n' AGENT__\n");
            return;
        case Phase::bootstrap:
            if (marker != "READY") break;
            phase_ = Phase::stage;
            queue("rm -f /run/droidvm-rescue.b64 /run/droidvm-rescue.sh; "
                  "if : > /run/droidvm-rescue.b64; then "
                  "printf '\\n__DROIDVM_%s:STAGE:READY\\n' AGENT__; else " + error_marker() + "; fi\n");
            return;
        case Phase::stage:
            if (marker != "STAGE:READY") break;
            upload_next();
            return;
        case Phase::upload:
            if (marker != "STAGE:CHUNK:" + std::to_string(chunk_index_) + ":OK") break;
            ++chunk_index_;
            upload_next();
            return;
        case Phase::decode:
            if (marker != "SCRIPT:READY") break;
            phase_ = Phase::await_approval;
            return;
        case Phase::actions: {
            if (marker == "RESULT:OK" || starts_with(marker, "RESULT:PARTIAL:")) {
                if (next_action_ != actions_.size()) break;
                bool skipped = false;
                std::string failed;
                for (const auto& action : actions_) {
                    skipped |= action.state == ActionState::skipped;
                    if (action.state == ActionState::failed) {
                        if (!action.optional) { fail_protocol("PROTOCOL_ORDER"); return; }
                        if (!failed.empty()) failed += ',';
                        failed += std::string(action_name(action.kind)) + '=' + action.code;
                    }
                }
                if (marker == "RESULT:OK" && failed.empty())
                    report_guest(skipped ? Outcome::guest_skipped : Outcome::guest_succeeded);
                else if (!failed.empty() && marker == "RESULT:PARTIAL:" + failed)
                    report_guest(Outcome::guest_partial);
                else fail_protocol("PROTOCOL_ORDER");
                return;
            }
            if (next_action_ >= actions_.size()) break;
            auto& action = actions_[next_action_];
            const auto suffix = std::to_string(next_action_) + ':' + std::string(action_name(action.kind));
            if (marker == "ACTION:START:" + suffix && action.state == ActionState::pending) {
                if (next_action_ && actions_[next_action_ - 1].state == ActionState::failed
                    && !actions_[next_action_ - 1].optional) break;
                action.state = ActionState::running;
                return;
            }
            if (action.state != ActionState::running) break;
            // The shared App scripts emit diagnostic markers between control
            // markers. Accept only their known families and discard all payload
            // text: device paths/user names/command output are not public state.
            if (starts_with(marker, "COMMAND:RC:")) return;
            if (action.kind == ActionKind::password && (starts_with(marker, "PROBE:")
                || starts_with(marker, "ROOT:") || starts_with(marker, "PASSWD:"))) return;
            if (action.kind == ActionKind::autogrow && (starts_with(marker, "AUTOGROW:PARTITION:")
                || starts_with(marker, "AUTOGROW:GROWN:"))) return;
            const auto error_prefix = "ACTION:ERROR:" + suffix + ':';
            const auto skipped_prefix = "ACTION:SKIPPED:" + suffix + ':';
            if (marker == "ACTION:OK:" + suffix) action.state = ActionState::succeeded;
            else if (starts_with(marker, error_prefix)) {
                action.state = ActionState::failed;
                action.code = safe_error(marker.substr(error_prefix.size()));
            } else if (starts_with(marker, skipped_prefix)) {
                action.state = ActionState::skipped;
                action.code = safe_skip(marker.substr(skipped_prefix.size()));
            } else break;
            if (action.kind == ActionKind::password) erase(password_);
            ++next_action_;
            return;
        }
        default: break;
    }
    fail_protocol("PROTOCOL_ORDER");
}

void Protocol::inspect_prompt() {
    // A diagnostic marker can contain arbitrary guest text. It is never a
    // password prompt, even if its payload happens to end in a prompt string.
    if (starts_with(line_, prefix)) return;
    if (next_action_ >= actions_.size()) return;
    const auto& action = actions_[next_action_];
    if (action.kind != ActionKind::password || action.state != ActionState::running) return;
    constexpr std::array prompts{"New password:", "Re-enter new password:", "Retype new password:",
        "Retype password:", "Enter new UNIX password:", "Retype new UNIX password:"};
    for (auto prompt : prompts) {
        if (!ends_with(line_, prompt)) continue;
        if (password_.empty() || ++password_prompts_ > 2048) { fail_protocol("PASSWORD_PROMPT_LIMIT"); return; }
        queue(password_ + '\n');
        erase(line_);
        return;
    }
}
}
