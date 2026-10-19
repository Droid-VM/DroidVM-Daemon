// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "staged_configuration.h"

namespace droidvm::web {
ConfigOperations usb_rules_configuration(TaskService& tasks, JsonConfigurationStaging staging,
    std::function<Json::Value(const CallContext&)> read,
    std::function<Json::Value(const CallContext&)> targets,
    std::function<Json::Value(const CallContext&, const std::string&)> preview = {});
}
