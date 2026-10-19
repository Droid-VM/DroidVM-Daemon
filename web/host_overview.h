// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "services/host_overview.h"
#include <json/json.h>

namespace droidvm::web {
// Observation only: no host paths, process launching or guessed missing values.
Json::Value host_overview_catalog(const HostOverview& snapshot);
}
