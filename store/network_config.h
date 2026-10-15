// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <optional>
#include <string>

namespace droidvm::config {
// DataItem accessors are type-strict; JSONObject's schema optInt is not.
const Json::Value& member(const Json::Value& object, const char* key);
std::string string(const Json::Value& object, const char* key, std::string fallback = {});
bool boolean(const Json::Value& object, const char* key, bool fallback = false);
int64_t integer(const Json::Value& object, const char* key, int64_t fallback = 0);
int schema(const Json::Value& object);
std::string uuid(const Json::Value& object);
Json::Value default_vlan(int id);
// Unsupported future schemas are not interpreted. The store must retain their
// original JSON even though they cannot be activated by this daemon version.
std::optional<Json::Value> migrate_network(const Json::Value& original);
// Matches NetworkConfigValidator, including its normalization of l2/l3 and
// ipv4/ipv6 sections. Throws invalid_argument with the legacy validation text.
void validate_network(Json::Value& config);
// Effective values consumed by backends; raw JSON remains the persistence form.
Json::Value network_view(Json::Value& config);
}
