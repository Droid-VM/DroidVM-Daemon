// SPDX-License-Identifier: GPL-3.0-or-later
// Extracted from the existing console/ipc_proto.cpp JSON and frame contract.
#include "wire.h"
#include <memory>
#include <stdexcept>

namespace droidvm::wire {
uint32_t payload_size(const void* header) {
    const auto* p = static_cast<const uint8_t*>(header);
    const uint32_t size = uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
    if (!size || size > max_payload) throw std::runtime_error("invalid payload length");
    return size;
}
std::string frame(std::string_view json, bool trailing_nul) {
    if (json.empty() || json.size() > max_payload - unsigned(trailing_nul))
        throw std::runtime_error("invalid payload length");
    const auto size = static_cast<uint32_t>(json.size() + unsigned(trailing_nul));
    std::string result(4, '\0');
    for (unsigned i = 0; i < 4; ++i) result[i] = static_cast<char>(size >> (8 * i));
    result.append(json);
    if (trailing_nul) result.push_back('\0');
    return result;
}
Json::Value parse(std::string_view json) {
    if (!json.empty() && json.back() == '\0') json.remove_suffix(1);
    Json::CharReaderBuilder builder;
    Json::Value value;
    std::string errors;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    if (!reader->parse(json.data(), json.data() + json.size(), &value, &errors))
        throw std::runtime_error("JSON parse error: " + errors);
    return value;
}
std::string stringify(const Json::Value& value, bool pretty) {
    Json::StreamWriterBuilder builder;
    builder["indentation"] = pretty ? "  " : "";
    return Json::writeString(builder, value);
}
}
