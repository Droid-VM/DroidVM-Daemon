// SPDX-License-Identifier: GPL-3.0-or-later
#include "agent/protocol.h"
#include "common/wire.h"
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace droidvm::agent;
namespace {
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
template<class Work> void invalid(Work work) {
    try { work(); } catch (const std::invalid_argument&) { return; }
    throw std::runtime_error("Expected invalid protocol configuration");
}
void fragmented(Protocol& protocol, std::string_view bytes) {
    for (char byte : bytes) protocol.feed(std::string_view(&byte, 1));
}
void marker(Protocol& protocol, std::string_view value) {
    fragmented(protocol, "\r\n__DROIDVM_AGENT__:" + std::string(value) + "\r\n");
}
std::string drain(Protocol& protocol, std::size_t accepted_limit = 73) {
    std::string bytes;
    std::size_t iterations = 0;
    while (true) {
        auto offered = protocol.pending_write();
        if (offered.empty()) break;
        require(offered.size() <= Protocol::write_limit, "Write exceeded runtime console limit");
        require(protocol.pending_write() == offered, "Inspection advanced the write cursor");
        const auto count = std::min(offered.size(), accepted_limit);
        bytes.append(offered.substr(0, count));
        protocol.write_ack(count);
        require(++iterations < 3000, "Write did not converge");
    }
    return bytes;
}
std::string prepare(Protocol& protocol) {
    require(!protocol.begin_actions(), "Approval was accepted before script staging");
    fragmented(protocol, "Booting Linux\r\nRun /bin/sh as init process\r\n~ # ");
    require(protocol.phase() == Phase::tty, "Boot prompt was not recognized");
    const auto first = std::string(protocol.pending_write());
    protocol.write_ack(0);
    require(protocol.pending_write() == first, "Zero acceptance consumed command bytes");
    require(drain(protocol).find("busybox setsid -c") == 0, "Missing TTY bootstrap");
    marker(protocol, "TTY:READY");
    require(drain(protocol).find("stty -echo") == 0, "Console echo was not disabled");
    marker(protocol, "READY");
    require(drain(protocol).find(": > /run/droidvm-rescue.b64") != std::string::npos, "Missing payload initialization");
    marker(protocol, "STAGE:READY");
    std::size_t index = 0;
    std::string payload;
    while (protocol.phase() == Phase::upload) {
        const auto command = drain(protocol, 17);
        const std::string start = "if printf '%s' '";
        require(command.find(start) == 0, "Missing payload chunk command");
        const auto end = command.find('\'', start.size());
        require(end != std::string::npos && end - start.size() <= 1024, "Invalid canonical payload chunk");
        payload += command.substr(start.size(), end - start.size());
        marker(protocol, "STAGE:CHUNK:" + std::to_string(index++) + ":OK");
    }
    require(protocol.phase() == Phase::decode, "Upload did not finish at decode");
    const auto decode = drain(protocol);
    require(decode.find("busybox base64 -d") != std::string::npos
        && decode.find("busybox sh -n") != std::string::npos, "Script was not decoded and syntax checked");
    require(decode.find("stty echo") == std::string::npos, "Protocol re-enabled password echo");
    marker(protocol, "SCRIPT:READY");
    require(protocol.phase() == Phase::await_approval && protocol.pending_write().empty(), "Script ran without commit approval");
    return payload;
}
void start(Protocol& protocol) {
    prepare(protocol);
    require(protocol.begin_actions(), "Execution approval failed");
    require(!protocol.begin_actions(), "Duplicate approval was accepted");
    require(drain(protocol).find("busybox sh /run/droidvm-rescue.sh;") == 0, "No approved script execution");
}

void upload_and_result() {
    const std::string script = "#!/bin/sh\n# " + std::string(2400, 'x') + "\n";
    Protocol protocol(script, {{ActionKind::autogrow}});
    require(prepare(protocol) == droidvm::wire::encode_base64(script), "Partial writes corrupted or duplicated uploaded script");
    require(protocol.begin_actions(), "Execution approval failed");
    drain(protocol);
    marker(protocol, "ACTION:START:0:autogrow");
    require(protocol.snapshot().actions[0].state == ActionState::running, "Action did not start");
    marker(protocol, "AUTOGROW:PARTITION:/dev/vda1:ext4:8192");
    marker(protocol, "COMMAND:RC:PARTED:0");
    marker(protocol, "AUTOGROW:GROWN:/dev/vda1:ext4:4096:8192");
    fragmented(protocol, "\n__DROIDVM_AGENT__:ACTION:OK:0:autogrow");
    require(protocol.snapshot().actions[0].state == ActionState::running, "Incomplete marker was consumed");
    protocol.feed("\n");
    marker(protocol, "RESULT:OK");
    require(protocol.outcome() == Outcome::guest_succeeded && protocol.phase() == Phase::finished, "Guest success was lost");
    marker(protocol, "RESULT:ERROR:SCRIPT_FAILED");
    require(protocol.outcome() == Outcome::guest_succeeded, "Terminal result changed");
    require(protocol.pending_write().empty(), "Terminal protocol retained writes");
}

void password_prompts() {
    const std::string password = "Secret:123!";
    Protocol protocol("#!/bin/sh\n", {{ActionKind::autogrow}, {ActionKind::password}}, password);
    start(protocol);
    fragmented(protocol, "New password:");
    require(protocol.pending_write().empty(), "Password sent before action start");
    marker(protocol, "ACTION:START:0:autogrow");
    fragmented(protocol, "New password:");
    require(protocol.pending_write().empty(), "Password sent to a non-password action");
    marker(protocol, "ACTION:OK:0:autogrow");
    marker(protocol, "ACTION:START:1:chpasswd");
    marker(protocol, "PROBE:/dev/vda1");
    marker(protocol, "ROOT:/dev/vda1");
    marker(protocol, "PASSWD:BINARY:/usr/bin/passwd");
    marker(protocol, "PASSWD:root");
    marker(protocol, "PASSWD:BINARY:New password:");
    require(protocol.pending_write().empty(), "Diagnostic marker was mistaken for a password prompt");
    fragmented(protocol, "Changing password for root\nNew pass");
    require(protocol.pending_write().empty(), "Partial password prompt was accepted");
    fragmented(protocol, "word:");
    require(drain(protocol, 2) == password + '\n', "Password was not delivered exactly once");
    fragmented(protocol, "\r\nRetype password:");
    require(drain(protocol, 1) == password + '\n', "Busybox confirmation prompt was not supported");
    fragmented(protocol, "\r\nEnter new UNIX password:");
    require(drain(protocol) == password + '\n', "UNIX password prompt was not supported");
    fragmented(protocol, "\r\nRetype new UNIX password:");
    require(drain(protocol) == password + '\n', "UNIX confirmation prompt was not supported");
    marker(protocol, "COMMAND:RC:PASSWD:root:0");
    marker(protocol, "ACTION:OK:1:chpasswd");
    fragmented(protocol, "New password:");
    require(protocol.pending_write().empty(), "Completed action still sent its password");
    marker(protocol, "RESULT:OK");
    const auto snapshot = protocol.snapshot();
    require(snapshot.outcome == Outcome::guest_succeeded && snapshot.code.empty(), "Password action failed");
    for (const auto& action : snapshot.actions)
        require(action.code.find(password) == std::string::npos, "Password leaked through public action code");
}

void outcomes_and_sanitization() {
    Protocol skipped("#!/bin/sh\n", {{ActionKind::autogrow}});
    start(skipped);
    marker(skipped, "ACTION:START:0:autogrow");
    marker(skipped, "ACTION:SKIPPED:0:autogrow:UNSUPPORTED_FILESYSTEM:private-guest-text");
    marker(skipped, "RESULT:OK");
    require(skipped.outcome() == Outcome::guest_skipped, "Skipped operation reported ordinary success");
    require(skipped.snapshot().actions[0].code == "UNSUPPORTED_FILESYSTEM", "Guest filesystem text escaped allowlist");

    Protocol no_space("#!/bin/sh\n", {{ActionKind::autogrow}});
    start(no_space);
    marker(no_space, "ACTION:START:0:autogrow");
    marker(no_space, "ACTION:SKIPPED:0:autogrow:NO_TRAILING_SPACE");
    marker(no_space, "RESULT:OK");
    require(no_space.snapshot().actions[0].code == "NO_TRAILING_SPACE", "Known skip code was not parsed exactly");

    Protocol partial("#!/bin/sh\n", {{ActionKind::autogrow, true}, {ActionKind::password}}, "Safe123!");
    start(partial);
    marker(partial, "ACTION:START:0:autogrow");
    marker(partial, "ACTION:ERROR:0:autogrow:PARTITION_GROW_FAILED");
    marker(partial, "ACTION:START:1:chpasswd");
    marker(partial, "ACTION:OK:1:chpasswd");
    marker(partial, "RESULT:PARTIAL:autogrow=PARTITION_GROW_FAILED");
    require(partial.outcome() == Outcome::guest_partial, "Optional action error lost partial outcome");

    Protocol failed("#!/bin/sh\n", {{ActionKind::autogrow}});
    start(failed);
    marker(failed, "ACTION:START:0:autogrow");
    marker(failed, "ACTION:ERROR:0:autogrow:guest-private-password");
    marker(failed, "RESULT:ERROR:guest-private-password");
    require(failed.outcome() == Outcome::guest_failed, "Required action failure not retained");
    require(failed.snapshot().code == "UNKNOWN_AGENT_ERROR"
        && failed.snapshot().actions[0].code == "UNKNOWN_AGENT_ERROR", "Guest text escaped public error allowlist");
}

void uncertain_writes_and_abort() {
    Protocol protocol("#!/bin/sh\n", {{ActionKind::password}}, "Safe123!");
    start(protocol);
    marker(protocol, "ACTION:START:0:chpasswd");
    fragmented(protocol, "New password:");
    require(!protocol.pending_write().empty(), "Missing password pending write");
    protocol.write_ack(2);
    protocol.write_unknown();
    require(protocol.outcome() == Outcome::uncertain && protocol.pending_write().empty(), "Unknown password write could be replayed");
    fragmented(protocol, "Retype password:");
    require(protocol.pending_write().empty(), "Secret retained after uncertain write");

    Protocol cancelled("#!/bin/sh\n", {{ActionKind::autogrow}});
    prepare(cancelled);
    cancelled.abort(AbortReason::cancelled);
    require(cancelled.outcome() == Outcome::aborted && !cancelled.begin_actions(), "Cancelled setup could execute");

    Protocol timeout("#!/bin/sh\n", {{ActionKind::autogrow}});
    start(timeout);
    timeout.abort(AbortReason::timeout);
    require(timeout.outcome() == Outcome::uncertain && timeout.snapshot().code == "TIMEOUT", "Post-commit timeout claimed no side effect");

    Protocol ack("#!/bin/sh\n", {{ActionKind::autogrow}});
    ack.feed("~ #");
    const auto offered = ack.pending_write().size();
    ack.write_ack(offered + 1);
    require(ack.outcome() == Outcome::aborted && ack.snapshot().code == "INVALID_WRITE_ACK", "Invalid transport acceptance was allowed");
}

void ordering_and_limits() {
    invalid([] { Protocol p("", {{ActionKind::autogrow}}); });
    invalid([] { Protocol p(std::string(Protocol::script_limit + 1, 'x'), {{ActionKind::autogrow}}); });
    invalid([] { Protocol p("#x", {}); });
    invalid([] { Protocol p("#x", std::vector<Action>(17, {ActionKind::autogrow})); });
    invalid([] { Protocol p("#x", {{ActionKind::password}}, "bad\npassword"); });
    invalid([] { Protocol p("#x", {{ActionKind::password}}, std::string(129, 'a')); });
    invalid([] { Protocol p("#x", {{ActionKind::password}, {ActionKind::password}}, "Safe123"); });
    invalid([] { Protocol p("#x", {{ActionKind::autogrow}}, "unexpected"); });
    invalid([] { Protocol p("#x", {{ActionKind::autogrow, false, true}}); });

    Protocol overflow("#x", {{ActionKind::autogrow}});
    overflow.feed(std::string(Protocol::line_limit + 1, 'x'));
    require(overflow.snapshot().code == "INPUT_OVERFLOW", "Unbounded guest line accepted");
    Protocol input("#x", {{ActionKind::autogrow}});
    input.feed(std::string(Protocol::input_limit + 1, '\n'));
    require(input.snapshot().code == "INPUT_OVERFLOW", "Unbounded feed accepted");

    Protocol early("#x", {{ActionKind::autogrow}});
    marker(early, "SCRIPT:READY");
    require(early.outcome() == Outcome::aborted, "Out-of-order script marker accepted");

    Protocol duplicate("#x", {{ActionKind::autogrow}});
    duplicate.feed("~ #");
    drain(duplicate);
    marker(duplicate, "TTY:READY");
    drain(duplicate);
    marker(duplicate, "TTY:READY");
    require(duplicate.outcome() == Outcome::aborted && duplicate.pending_write().empty(), "Duplicate stage marker replayed a command");

    Protocol premature("#x", {{ActionKind::autogrow}});
    start(premature);
    marker(premature, "RESULT:OK");
    require(premature.outcome() == Outcome::uncertain, "Guest success accepted before actions completed");
}

void required_guest_finalization() {
    Protocol protocol("#!/bin/sh\n", {{ActionKind::password}}, "Safe123!", true);
    start(protocol);
    marker(protocol, "ACTION:START:0:chpasswd");
    marker(protocol, "ACTION:OK:0:chpasswd");
    marker(protocol, "RESULT:OK");
    auto snapshot = protocol.snapshot();
    require(snapshot.phase == Phase::finalizing && snapshot.outcome == Outcome::pending
        && snapshot.guest_result == Outcome::guest_succeeded && snapshot.guest_cleanup == GuestCleanup::pending,
        "Guest RESULT bypassed required finalization");
    fragmented(protocol, "New password:");
    require(protocol.pending_write().empty(), "Finalization accepted a password prompt");
    fragmented(protocol, "\n__DROIDVM_AGENT__:CLEANUP:OK");
    require(protocol.phase() == Phase::finalizing, "Incomplete cleanup marker was accepted");
    protocol.feed("\n");
    require(protocol.outcome() == Outcome::guest_succeeded
        && protocol.snapshot().guest_cleanup == GuestCleanup::succeeded, "Guest cleanup was not confirmed");

    Protocol failed_action("#x", {{ActionKind::autogrow}}, {}, true);
    start(failed_action);
    marker(failed_action, "ACTION:START:0:autogrow");
    marker(failed_action, "ACTION:ERROR:0:autogrow:PARTITION_GROW_FAILED");
    marker(failed_action, "RESULT:ERROR:PARTITION_GROW_FAILED");
    require(failed_action.phase() == Phase::finalizing, "Required action error bypassed finalizer");
    marker(failed_action, "CLEANUP:OK");
    snapshot = failed_action.snapshot();
    require(snapshot.outcome == Outcome::guest_failed && snapshot.guest_result == Outcome::guest_failed
        && snapshot.guest_code == "PARTITION_GROW_FAILED" && snapshot.guest_cleanup == GuestCleanup::succeeded,
        "Cleanup success erased the required action error");

    for (int failure = 0; failure < 3; ++failure) {
        Protocol failed_cleanup("#x", {{ActionKind::autogrow}}, {}, true);
        start(failed_cleanup);
        marker(failed_cleanup, "ACTION:START:0:autogrow");
        marker(failed_cleanup, "ACTION:OK:0:autogrow");
        marker(failed_cleanup, "RESULT:OK");
        if (failure == 0) marker(failed_cleanup, "CLEANUP:ERROR");
        if (failure == 1) failed_cleanup.abort(AbortReason::timeout);
        if (failure == 2) marker(failed_cleanup, "CLEANUP:ERROR:private-guest-text");
        snapshot = failed_cleanup.snapshot();
        require(snapshot.outcome == Outcome::uncertain && snapshot.guest_result == Outcome::guest_succeeded,
            "Finalization failure lost original guest RESULT or claimed success");
        require(snapshot.guest_cleanup == (failure == 0 ? GuestCleanup::failed : GuestCleanup::uncertain),
            "Finalization error was confused with missing acknowledgement");
        require(snapshot.cleanup_code == (failure == 0 ? "GUEST_CLEANUP_FAILED" : ""),
            "Guest cleanup text escaped public error allowlist");
    }

    Protocol premature("#x", {{ActionKind::autogrow}}, {}, true);
    start(premature);
    marker(premature, "CLEANUP:OK");
    require(premature.outcome() == Outcome::uncertain
        && premature.snapshot().guest_cleanup != GuestCleanup::succeeded,
        "Cleanup confirmation was accepted before the action result");
}

void shell_handoff_requires_script_return() {
    invalid([] { Protocol p("#x", {{ActionKind::autogrow}}, {}, false, true); });
    for (bool cleanup_failed : {false, true}) {
        Protocol protocol("#x", {{ActionKind::password}}, "Safe123!", true, true);
        prepare(protocol);
        require(protocol.begin_actions(), "Handoff operation did not enter commit");
        const auto execute = drain(protocol);
        require(execute.find("rm -f /run/droidvm-rescue.sh;") < execute.find("SCRIPT:EXITED"),
            "Script return marker is not outside the foreground action");
        marker(protocol, "ACTION:START:0:chpasswd");
        marker(protocol, "ACTION:OK:0:chpasswd");
        marker(protocol, "RESULT:OK");
        require(protocol.phase() == Phase::finalizing && protocol.pending_write().empty(),
            "Action result admitted shell input");
        marker(protocol, cleanup_failed ? "CLEANUP:ERROR" : "CLEANUP:OK");
        require(protocol.phase() == Phase::await_script_exit && protocol.pending_write().empty(),
            "Guest cleanup report admitted shell input before script exit");
        fragmented(protocol, "New password:\n__DROIDVM_AGENT__:SCRIPT:EXITED");
        require(protocol.pending_write().empty(), "Incomplete script exit marker admitted shell input");
        protocol.feed("\n");
        require(protocol.phase() == Phase::shell_handshake && !protocol.snapshot().shell_ready,
            "Script exit alone claimed an interactive shell");
        const auto command = drain(protocol, 5);
        require(command.find("ROOT_DEVICE=$(cat /run/droidvm-root-device") == 0
            && command.find("mount -o rw \"$ROOT_DEVICE\" /mnt") != std::string::npos
            && command.find("PS1='droidvm-rescue # '") != std::string::npos
            && command.find("Safe123!") == std::string::npos, "Handoff did not use the fixed secret-free App command");
        fragmented(protocol, "New password:");
        require(protocol.pending_write().empty(), "Password input remained enabled during shell handoff");
        marker(protocol, "SHELL:READY");
        const auto result = protocol.snapshot();
        require(result.shell_ready && result.phase == Phase::finished
            && result.guest_result == Outcome::guest_succeeded
            && result.outcome == (cleanup_failed ? Outcome::uncertain : Outcome::guest_succeeded),
            "Shell readiness erased the action or cleanup result");
    }
    for (bool early_exit : {false, true}) {
        Protocol protocol("#x", {{ActionKind::autogrow}}, {}, true, true);
        start(protocol);
        marker(protocol, "ACTION:START:0:autogrow");
        marker(protocol, "ACTION:OK:0:autogrow");
        marker(protocol, "RESULT:OK");
        if (!early_exit) marker(protocol, "CLEANUP:OK");
        marker(protocol, early_exit ? "SCRIPT:EXITED" : "SHELL:READY");
        require(protocol.outcome() == Outcome::uncertain && !protocol.snapshot().shell_ready
            && protocol.pending_write().empty(), "Out-of-order shell marker bypassed the handoff gates");
    }
    Protocol unknown("#x", {{ActionKind::autogrow}}, {}, true, true);
    start(unknown);
    marker(unknown, "ACTION:START:0:autogrow");
    marker(unknown, "ACTION:OK:0:autogrow");
    marker(unknown, "RESULT:OK");
    marker(unknown, "CLEANUP:OK");
    marker(unknown, "SCRIPT:EXITED");
    require(!unknown.pending_write().empty(), "Missing fixed handoff command");
    unknown.write_ack(3);
    unknown.write_unknown();
    require(unknown.outcome() == Outcome::uncertain && !unknown.snapshot().shell_ready
        && unknown.pending_write().empty(), "Unknown handoff write could replay or grant shell control");
}
}

int main() {
    try {
        upload_and_result();
        password_prompts();
        outcomes_and_sanitization();
        uncertain_writes_and_abort();
        ordering_and_limits();
        required_guest_finalization();
        shell_handoff_requires_script_return();
        std::cout << "Agent protocol contract passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
