// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "control_http.h"
#include "runtime/managed_process.h"
#include <json/json.h>

namespace droidvm::network {
// Shared 5s whole-readiness budget. Validate the actual API payload on a worker.
void await_helper(ManagedProcess& process, const ControlHttp& client, const std::string& endpoint,
    const std::function<bool(const Json::Value&)>& ready);
}
