// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include "vm/console_history.h"

namespace droidvm::web {
struct VmLogTarget { std::string vm_id, instance_id; std::vector<std::string> streams; };
struct VmLogRead {
    std::string vm_id, instance_id, stream;
    std::optional<vm::LogCursor> cursor;
    bool tail = true;
};
struct VmLogSource {
    std::function<VmLogTarget(const CallContext&, const std::string&)> list;
    std::function<vm::LogSlice(const CallContext&, const VmLogRead&)> read;
};
VmLogs vm_logs(VmLogSource source);
}
