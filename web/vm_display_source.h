// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "services/context.h"
#include "vm/observation.h"
#include <functional>
#include <memory>
#include <string_view>
#include <vector>

namespace droidvm::web {
struct VmDisplayScreen {
    std::string id;
    bool available = false;
    std::string reason;
    bool input_enabled = false;
};
struct VmDisplayTarget {
    std::string vm_id;
    vm::Observation observed;
    std::vector<VmDisplayScreen> screens;
};
// Every I/O callback validates the same running runtime observation before
// touching the nonblocking native socket. Empty read means EAGAIN; EOF throws.
// These callbacks capture native socket ownership, never browser-selected URLs.
struct VmDisplayStream {
    std::function<bool()> connected;
    std::function<std::string(size_t)> read;
    std::function<size_t(std::string_view)> write;
    std::function<void()> close;
    std::string password;
};
struct VmDisplaySource {
    std::function<VmDisplayTarget(const CallContext&, const std::string&)> list;
    std::function<VmDisplayStream(const CallContext&, const std::string&, const std::string&, const vm::Observation&)> open;
};
}
