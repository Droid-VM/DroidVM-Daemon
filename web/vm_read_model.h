// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <functional>
#include "services/config_snapshot.h"

namespace droidvm::web {
// Input is VmService::list(caller), after its authentication/configuration gate.
// Explicit allowlist: never expose the complete VM config (passwords, paths,
// environment, agent settings, console credentials, etc.) to a list request.
using VmLeaseLookup = std::function<Json::Value(const std::string& network)>;
using VmCurrentObservation = std::function<bool(const std::string& id, const std::string& instance, const std::string& revision)>;
Json::Value vm_snapshot(const Json::Value& inventory, const VmConfigSnapshot* configuration = nullptr,
    VmLeaseLookup leases = {}, VmCurrentObservation current = {});
}
