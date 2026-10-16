// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <array>
#include <optional>
#include <string>

namespace droidvm::config {
// DataItem accessors are type-strict; JSONObject's schema optInt is not.
const Json::Value& member(const Json::Value& object, const char* key);
std::string string(const Json::Value& object, const char* key, std::string fallback = {});
bool boolean(const Json::Value& object, const char* key, bool fallback = false);
int64_t integer(const Json::Value& object, const char* key, int64_t fallback = 0);
int schema(const Json::Value& object);
// Long.parseLong(text, 10), including Character.digit's Unicode digits.
int64_t java_long(std::string_view text);
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
// Shares exactly the parser used by validation (including Java-compatible
// numeric input). Values are immutable; offsets are relative to network base.
class NetworkPrefix {
public:
    static NetworkPrefix parse(const std::string& cidr, bool ipv6);
    int prefix() const { return prefix_; }
    std::string address() const;
    std::string network() const;
    std::string address_at(int64_t offset) const;
private:
    std::array<uint8_t, 16> bytes_{};
    int prefix_ = 0;
    bool ipv6_ = false;
    std::array<uint8_t, 16> base() const;
    std::string format(const std::array<uint8_t, 16>& bytes) const;
};
}
