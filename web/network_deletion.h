// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "staged_configuration.h"

namespace droidvm::web {
// Same ConfigUploads participant used by the App: begin's revision is the VM
// configuration revision; the uploaded body carries the exact network object.
ConfigOperations network_deletion(TaskService& tasks, JsonConfigurationStaging staging);

// Global ConfigurationService journal recovery, exposed independently of any
// deletion. Reconciliation must never repeat the original destructive request.
BackgroundOperations configuration_recovery(TaskService& tasks,
    std::function<void(const CallContext&)> recover);
}
