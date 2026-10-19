// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <string>
#include <string_view>
#include <vector>

namespace droidvm::agent {
enum class ActionKind { password, autogrow };

// Credentials intentionally have no representation in a rescue script action.
struct Action {
    ActionKind kind;
    bool optional = false;
    bool normal_users = false;
};

std::string_view action_name(ActionKind kind);
// One to sixteen actions, at most 64 KiB. Native operations attach exactly one
// disk, always addressed as /dev/vda; normal_users only applies to password.
// Native managed operations request finalization: wait for the action process,
// sync, unmount and verify the guest mount table, then emit CLEANUP:OK/ERROR.
// The default preserves the App-compatible script and rescue-shell behavior.
std::string rescue_script(const std::vector<Action>& actions, bool finalize = false);
}
