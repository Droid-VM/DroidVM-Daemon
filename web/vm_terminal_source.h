// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "services/context.h"
#include "vm/console_history.h"
#include "vm/observation.h"
#include <functional>

namespace droidvm::web {
struct VmTerminalTarget {
    std::string vm_id;
    vm::Observation observed;
    std::vector<std::string> streams;
};
struct VmTerminalRead {
    std::string vm_id, stream;
    vm::Observation observed;
    std::optional<vm::LogCursor> cursor;
    bool tail = true;
};
struct VmTerminalWrite {
    std::string vm_id, stream;
    vm::Observation observed;
    std::string bytes;
};
// These callbacks bind the existing runtime's console_target/read/write, not a
// new console/history store. Native read/write must check RUNNING, !retired,
// expected incarnation/revision and the bidirectional non-agent stream while
// holding the same runtime state lock as the actual read/write. A partial write
// returns its actual accepted byte count; neither layer retries input bytes.
struct VmTerminalSource {
    std::function<VmTerminalTarget(const CallContext&, const std::string&)> list;
    std::function<vm::LogSlice(const CallContext&, const VmTerminalRead&)> read;
    std::function<size_t(const CallContext&, const VmTerminalWrite&)> write;
};
}
