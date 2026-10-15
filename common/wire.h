// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <cstdint>
#include <string>
#include <string_view>

namespace droidvm::wire {
inline constexpr uint32_t max_payload = 8u << 20;
uint32_t payload_size(const void* header);
std::string frame(std::string_view json, bool trailing_nul = false);
Json::Value parse(std::string_view json);
std::string stringify(const Json::Value& value, bool pretty = false);
}
