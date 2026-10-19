// SPDX-License-Identifier: GPL-3.0-or-later
#include "vm_display.h"
#include <algorithm>
#include <charconv>
#include <set>

namespace droidvm::web {
namespace {
[[noreturn]] void invalid() { throw ServiceError(ErrorCode::invalid_argument, "Invalid display frame"); }
void access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || caller.principal.empty()) throw ServiceError(ErrorCode::permission_denied, "Display permission required");
}
std::string field(const Json::Value& value, size_t maximum = 128) {
    if (!value.isString()) invalid();
    auto result = value.asString();
    if (result.empty() || result.size() > maximum || result.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::string::npos) invalid();
    return result;
}
vm::Observation observation(const Json::Value& value) {
    if (!value.isObject() || value.size() != 2) invalid();
    auto instance = field(value["instanceId"], 32);
    if (instance.size() != 32 || instance.find_first_not_of("0123456789abcdef") != std::string::npos || !value["revision"].isString()) invalid();
    const auto text = value["revision"].asString(); uint64_t revision = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), revision);
    if (text.empty() || text.size() > 20 || error != std::errc() || end != text.data() + text.size() || std::to_string(revision) != text) invalid();
    return {std::move(instance), revision};
}
Json::Value observed(const vm::Observation& value) {
    Json::Value result; result["instanceId"] = value.instance; result["revision"] = std::to_string(value.revision);
    (void)observation(result); return result;
}
}
Json::Value vm_display_list(const VmDisplaySource& source, const CallContext& caller, const std::string& id) {
    access(caller); field(id);
    if (!source.list || !source.open) throw ServiceError(ErrorCode::unavailable, "Display source unavailable");
    const auto target = source.list(caller, id);
    if (target.vm_id != id || target.screens.size() > 2) throw ServiceError(ErrorCode::unavailable, "Invalid display metadata");
    Json::Value result; result["vmId"] = id; result["expected"] = observed(target.observed);
    result["screens"] = Json::Value(Json::arrayValue); std::set<std::string> ids;
    const std::set<std::string> reasons{"", "disabled", "not-vnc", "not-running", "input-disabled", "unsupported", "invalid-endpoint"};
    for (const auto& screen : target.screens) {
        if ((screen.id != "gpu-0" && screen.id != "simplefb") || !ids.insert(screen.id).second
            || !reasons.contains(screen.reason) || (screen.available != screen.reason.empty()))
            throw ServiceError(ErrorCode::unavailable, "Invalid display screen");
        Json::Value row; row["id"] = screen.id; row["available"] = screen.available; row["reason"] = screen.reason;
        row["inputEnabled"] = screen.input_enabled; result["screens"].append(std::move(row));
    }
    return result;
}
}
