// SPDX-License-Identifier: GPL-3.0-or-later
#include "agent/scripts.h"
#include <iostream>
#include <source_location>
#include <stdexcept>

namespace {
void require(bool value, const std::source_location& at = std::source_location::current()) {
    if (!value) throw std::runtime_error("Agent scripts contract failed at line " + std::to_string(at.line()));
}
template<class Function> void rejects(Function work) {
    bool rejected = false;
    try { work(); } catch (const std::exception&) { rejected = true; }
    require(rejected);
}
}
int main(int argc, char** argv) {
    try {
        using namespace droidvm::agent;
        if (argc == 2 && std::string_view(argv[1]) == "--emit-finalized") {
            std::cout << rescue_script({{ActionKind::password, false, true}, {ActionKind::autogrow, true, false}}, true);
            return 0;
        }
        const auto script = rescue_script({{ActionKind::password, false, true}, {ActionKind::autogrow, true, false}});
        require(script.starts_with("#!/bin/sh\n"));
        require(script.find("ACTION_TYPE=chpasswd") < script.find("ACTION_TYPE=autogrow"));
        require(script.find("CHANGE_NORMAL_USERS='true'") != std::string::npos);
        require(script.find("DISK='/dev/vda'") != std::string::npos);
        require(script.find("ACTION_OPTIONAL=true") != std::string::npos);
        const auto result = script.find("marker RESULT:OK");
        require(result != std::string::npos && script.find("marker RESULT:OK", result + 1) == std::string::npos);
        // Passwords are supplied interactively, never expanded into the script.
        require(script.find("PASSWORD=") == std::string::npos);
        require(script.find("LC_ALL=C busybox chroot /mnt $PASSWD_BIN") != std::string::npos);
        require(script.find("RESULT:PARTIAL:$FAILED_ACTIONS") != std::string::npos);
        require(script.find("skip_action NO_TRAILING_SPACE") != std::string::npos);
        require(script.find("COMMAND:RC:RESIZE2FS") != std::string::npos);
        require(script.size() <= (64u << 10));
        require(script == rescue_script({{ActionKind::password, false, true}, {ActionKind::autogrow, true, false}}, false));
        require(script.find("droidvm_run") == std::string::npos);
        const auto finalized = rescue_script({{ActionKind::password}}, true);
        require(finalized.starts_with("#!/bin/sh\n") && finalized.ends_with("\n}\ndroidvm_run\n"));
        require(finalized.find("( droidvm_actions )") != std::string::npos);
        require(finalized.find("marker() { droidvm_marker \"$1\"; }") != std::string::npos);
        require(finalized.find("__DROIDVM_AGENT__:CLEANUP:OK") != std::string::npos);
        require(finalized.find("__DROIDVM_AGENT__:CLEANUP:ERROR") != std::string::npos);
        require(finalized.find("cat /proc/mounts") != std::string::npos);
        require(finalized.size() <= (64u << 10));
        rejects([] { (void)rescue_script({}); });
        rejects([] { (void)rescue_script(std::vector<Action>(17, {ActionKind::autogrow})); });
        rejects([] { (void)rescue_script({{static_cast<ActionKind>(99)}}); });
        rejects([] { (void)rescue_script({{ActionKind::autogrow, false, true}}); });
        std::cout << "Shared Agent script ordering, optional outcomes, fixed target and bounds passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
