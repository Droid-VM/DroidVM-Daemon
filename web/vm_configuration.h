// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include "services/tasks.h"
#include "services/config_snapshot.h"
#include "staged_configuration.h"

namespace droidvm::web {
// Bound to the SAME ConfigUploads used by the App. No web staging registry.
using ConfigStaging = ConfigurationStaging<std::shared_ptr<const VmConfigSnapshot>>;
ConfigOperations vm_configuration(TaskService& tasks, ConfigStaging staging,
    std::function<Json::Value(const CallContext&)> defaults = {});
}
