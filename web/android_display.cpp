// SPDX-License-Identifier: GPL-3.0-or-later
#include "android_display.h"
#include "task_adapter.h"
#include <charconv>

namespace droidvm::web {
namespace {
[[noreturn]] void invalid() { throw ServiceError(ErrorCode::invalid_argument, "Invalid Android display request"); }
bool token(const Json::Value& value, size_t limit = 128) {
    if (!value.isString()) return false;
    const auto text = value.asString();
    return !text.empty() && text.size() <= limit && text.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-") == std::string::npos;
}
bool quantity(const Json::Value& value) {
    if (!value.isString()) return false;
    const auto text = value.asString(); uint64_t number = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), number);
    return !text.empty() && error == std::errc() && end == text.data() + text.size() && std::to_string(number) == text;
}
Json::Value nullable_quantity(const Json::Value& value) {
    if (value.isNull()) return value;
    if (!quantity(value)) invalid();
    return value;
}
Json::Value expected(const Json::Value& value) {
    if (!value.isObject() || value.size() != 1 || !token(value["revision"])) invalid();
    return value;
}
Json::Value state(const Json::Value& value) {
    if (value != "android" && value != "stopping" && value != "stopped" && value != "restoring") invalid();
    return value;
}
Json::Value network(const Json::Value& value) {
    if (value.isNull()) return value;
    if (!value.isObject() || value.size() != 2 || !token(value["interface"], 32) ||
        !(value["operstate"].isNull() || token(value["operstate"], 32))) invalid();
    Json::Value out; out["interface"] = value["interface"]; out["operstate"] = value["operstate"];
    return out;
}
Json::Value owner(const Json::Value& value) {
    if (value.isNull()) return value;
    if (!value.isObject() || (value["kind"] != "manual" && value["kind"] != "vm") ||
        !(value["vmId"].isNull() || token(value["vmId"])) || !(value["vmName"].isNull() || (value["vmName"].isString() && value["vmName"].asString().size() <= 256))) invalid();
    Json::Value out; out["kind"] = value["kind"]; out["vmId"] = value["vmId"]; out["vmName"] = value["vmName"];
    return out;
}
Json::Value last_restore(const Json::Value& value) {
    if (value.isNull()) return value;
    if (!value.isObject() || !value["ok"].isBool() || !value["uncertain"].isBool() ||
        !(value["message"].isNull() || value["message"].isString()) || !quantity(value["atMs"])) invalid();
    Json::Value out;
    out["ok"] = value["ok"]; out["uncertain"] = value["uncertain"]; out["atMs"] = value["atMs"];
    out["message"] = value["message"].isString() ? Json::Value(value["message"].asString().substr(0, 512)) : Json::Value();
    return out;
}
void access(const CallContext& caller, bool write) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || (write && !caller.manage_tasks))
        throw ServiceError(ErrorCode::permission_denied, "Android display permission required");
}
void identity(const TaskView& task, const std::string& id) {
    if (task.kind != "android_display" || task.resource != "android-display" || task.request_id != id)
        throw ServiceError(ErrorCode::conflict, "Android display task identity mismatch");
}
void validate(const Json::Value& input) {
    if (!input.isObject() || input.size() != 3 || !token(input["requestId"])) invalid();
    (void)expected(input["expected"]);
    const auto& operation = input["operation"];
    if (!operation.isObject() || !operation["kind"].isString()) invalid();
    if (operation["kind"] == "stop") {
        if (operation.size() > 3) invalid();
        for (const auto& key : operation.getMemberNames())
            if (key != "kind" && key != "autoRestoreSeconds" && key != "restoreOnNetworkLoss") invalid();
        if (operation.isMember("autoRestoreSeconds") &&
            (!operation["autoRestoreSeconds"].isInt() || operation["autoRestoreSeconds"].asInt() < 60 || operation["autoRestoreSeconds"].asInt() > 86400)) invalid();
        if (operation.isMember("restoreOnNetworkLoss") && !operation["restoreOnNetworkLoss"].isBool()) invalid();
    } else if (operation["kind"] != "restore" || operation.size() != 1) invalid();
}
}
Json::Value android_display_catalog(const Json::Value& native) {
    try {
        if (!native.isObject() || native["capability"] != "android-display-v1" || !native["supported"].isBool() ||
            !native["restoreOnNetworkLoss"].isBool() || !native["progress"].isString() || native["progress"].asString().size() > 128 ||
            !native["watchdog"].isObject() || !native["watchdog"]["verified"].isBool() ||
            !(native["watchdog"]["reason"].isNull() || native["watchdog"]["reason"].isString()) ||
            !native["services"].isObject() || !native["services"]["surfaceflinger"].isString() || !native["services"]["composer"].isString() ||
            !(native["panelLit"].isNull() || native["panelLit"].isBool())) invalid();
        Json::Value result;
        result["capability"] = native["capability"]; result["supported"] = native["supported"];
        result["expected"] = expected(native["expected"]);
        result["state"] = state(native["state"]);
        result["owner"] = owner(native["owner"]);
        result["sinceMs"] = nullable_quantity(native["sinceMs"]);
        result["autoRestoreAtMs"] = nullable_quantity(native["autoRestoreAtMs"]);
        result["restoreOnNetworkLoss"] = native["restoreOnNetworkLoss"];
        result["progress"] = native["progress"];
        result["network"] = network(native["network"]);
        result["panelLit"] = native["panelLit"];
        result["watchdog"]["verified"] = native["watchdog"]["verified"];
        result["watchdog"]["reason"] = native["watchdog"]["reason"].isString() ? Json::Value(native["watchdog"]["reason"].asString().substr(0, 256)) : Json::Value();
        result["services"]["surfaceflinger"] = native["services"]["surfaceflinger"].asString().substr(0, 32);
        result["services"]["composer"] = native["services"]["composer"].asString().substr(0, 32);
        result["lastRestore"] = last_restore(native["lastRestore"]);
        return result;
    } catch (const ServiceError&) { throw ServiceError(ErrorCode::unavailable, "Android display observation unavailable"); }
}
Json::Value project_android_display_result(const Json::Value& native, bool cancelled) {
    if (!native.isObject() || !native["stopped"].isBool() || !native["restored"].isBool() || !native["uncertain"].isBool()) return {};
    for (const auto* key : {"expected", "kind", "state", "revision", "network", "message"}) if (!native.isMember(key)) return {};
    Json::Value result;
    if (cancelled && native["expected"].isNull() && native["kind"].isNull() && native["state"].isNull() && native["revision"].isNull() &&
        native["network"].isNull() && native["message"].isNull() && native["stopped"] == false && native["restored"] == false && native["uncertain"] == false) {
        for (const auto* key : {"expected", "kind", "state", "revision", "network", "message", "stopped", "restored", "uncertain"}) result[key] = native[key];
        return result;
    }
    try {
        result["expected"] = expected(native["expected"]);
        if (native["kind"] != "stop" && native["kind"] != "restore") return {};
        result["kind"] = native["kind"];
        result["state"] = state(native["state"]);
        if (!native["revision"].isNull() && !token(native["revision"])) return {};
        result["revision"] = native["revision"];
        result["network"] = network(native["network"]);
        result["message"] = native["message"].isString() ? Json::Value(native["message"].asString().substr(0, 512)) : Json::Value();
        for (const auto* key : {"stopped", "restored", "uncertain"}) result[key] = native[key];
        if ((result["stopped"] == true || result["restored"] == true) && result["revision"].isNull()) return {};
        return result;
    } catch (const ServiceError&) { return {}; }
}
WebServiceOperations android_display_operations(AndroidDisplayBindings source) {
    if (!source.read || !source.start || !source.status) throw std::invalid_argument("Missing Android display binding");
    return {
        [source](const CallContext& caller) { access(caller, false); return android_display_catalog(source.read(caller)); },
        {
            [source](const CallContext& caller, const Json::Value& input) {
                access(caller, true); validate(input);
                const auto task = source.start(caller, input); identity(task, input["requestId"].asString());
                return task_view(task);
            },
            [source](const CallContext& caller, const std::string& id) {
                access(caller, true); if (!token(id)) invalid();
                try { const auto task = source.status(caller, id); identity(task, id); return task_view(task); }
                catch (const ServiceError& error) { if (error.code() != ErrorCode::task_not_found) throw; return Json::Value(); }
            }
        }
    };
}
}
