// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

// org.json / java.lang behaviour the legacy USB code leans on.
namespace droidvm::usb {
// RequestException: the only text a legacy client sees as "message". Every
// other exception thrown by the USB service is the legacy "internal error".
class RequestError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};
// String.trim: strips everything <= U+0020 from both ends.
std::string trim(std::string_view text);
// toLowerCase(Locale.ROOT) for the ASCII text sysfs and the rules carry.
std::string lower(std::string text);
// new String(bytes, UTF_8): malformed sequences become U+FFFD.
std::string utf8_lossy(std::string_view bytes);
// Integer.parseInt; nullopt where it throws NumberFormatException.
std::optional<int> parse_int(std::string_view text);
// Double.toString.
std::string java_double(double value);
// String.valueOf of a value org.json parsed (JSON.toString, JSONObject.toString).
// jsoncpp does not keep member order: objects print in sorted key order.
std::string java_string(const Json::Value& value);
// JSONObject.optString(key, fallback): absent -> fallback, null -> "null".
std::string opt_string(const Json::Value& object, const char* key, const std::string& fallback = {});
// JSONObject.optInt(key, fallback) (JSON.toInteger).
int opt_int(const Json::Value& object, const char* key, int fallback);
// Number.intValue of a numeric JSON value as org.json boxes it.
int int_value(const Json::Value& number);
// JSONObject.has(key) && !isNull(key).
bool present(const Json::Value& object, const char* key);
}
