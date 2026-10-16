// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>

namespace droidvm::wire {
inline constexpr uint32_t max_payload = 8u << 20;
uint32_t payload_size(const void* header);
std::string frame(std::string_view json, bool trailing_nul = false);
Json::Value parse(std::string_view json);
std::string stringify(const Json::Value& value, bool pretty = false);
// Stop writing as soon as the encoded result would exceed the reservation.
std::string stringify_bounded(const Json::Value& value, size_t max_bytes);
// Canonical RFC 4648 base64, no whitespace, partial quartets or nonzero pad bits.
std::string decode_base64(std::string_view text, size_t max_bytes);
}
