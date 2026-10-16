// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <string>
#include <vector>

namespace droidvm::config {
// Port of the VMConfig(JSONObject) load-time folds: EDK2 kernel, flat boot
// keys, VM-level port forwards, legacy display/geometry/GPU, serial defaults
// and the xHCI controller. Deterministic and in memory only: the app owns
// vms.json and the daemon never writes the result back.
Json::Value migrate_vm(Json::Value original);
// Enums.optEnum: strict string, Java toUpperCase, unknown names fall back.
std::string java_enum(const Json::Value& object, const char* key, const char* fallback, const std::vector<const char*>& names);
// Console stream names a backend instance registers for this config.
Json::Value vm_streams(const Json::Value& config);
}
