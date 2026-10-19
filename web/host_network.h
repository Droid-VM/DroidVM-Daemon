// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>

namespace droidvm::web {
// Projects the existing administrator-only NetworkHostService observations.
// Discovery failures propagate; an empty successful view is never a fallback.
Json::Value host_network_catalog(const Json::Value& interfaces,
    const Json::Value& uplinks, const Json::Value& addresses);
}
