// SPDX-License-Identifier: GPL-3.0-or-later
#include "scripts.h"
#include "agent_scripts_data.h"
#include <stdexcept>

namespace droidvm::agent {
std::string_view action_name(ActionKind kind) {
    switch (kind) {
    case ActionKind::password: return "chpasswd";
    case ActionKind::autogrow: return "autogrow";
    }
    throw std::invalid_argument("Unknown rescue action");
}

std::string rescue_script(const std::vector<Action>& actions, bool finalize) {
    if (actions.empty() || actions.size() > 16)
        throw std::invalid_argument("Rescue scripts require one to sixteen actions");
    std::string script(embedded::preamble);
    if (finalize) script += "\nmarker() { droidvm_marker \"$1\"; }\n";
    for (size_t i = 0; i < actions.size(); ++i) {
        const auto& action = actions[i];
        if (action.kind == ActionKind::autogrow && action.normal_users)
            throw std::invalid_argument("Normal users only apply to password actions");
        const auto index = std::to_string(i);
        script += "ACTION_INDEX=" + index + "\n";
        script += "ACTION_TYPE=";
        script += action_name(action.kind);
        script += "\nACTION_OPTIONAL=";
        script += action.optional ? "true\n" : "false\n";
        script += "begin_action\nagent_action_" + index + "() {\n";
        switch (action.kind) {
        case ActionKind::password:
            script += action.normal_users ? "CHANGE_NORMAL_USERS='true'\n"
                                          : "CHANGE_NORMAL_USERS='false'\n";
            script += embedded::chpasswd;
            break;
        case ActionKind::autogrow:
            script += "DISK='/dev/vda'\n";
            script += embedded::autogrow;
            break;
        }
        if (script.back() != '\n') script += '\n';
        // Keep fail() confined to its action; end_action controls queue continuation.
        script += "}\n( agent_action_" + index + " )\nend_action $?\n\n";
        if (script.size() + embedded::epilogue.size() > 64 * 1024)
            throw std::invalid_argument("Rescue script exceeds the payload limit");
    }
    script += embedded::epilogue;
    if (finalize) {
        script = "#!/bin/sh\n" + std::string(embedded::finalize) +
            "\ndroidvm_actions() {\n" + script + "\n}\ndroidvm_run\n";
        if (script.size() > 64 * 1024)
            throw std::invalid_argument("Rescue script exceeds the payload limit");
    }
    return script;
}
}
