// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "staged_configuration.h"

namespace droidvm::web {
// Uses the App's ConfigUploads network participant. Expected configurations live
// in the uploaded operations envelope; no invented global network revision.
ConfigOperations network_configuration(TaskService& tasks, JsonConfigurationStaging staging);
}
