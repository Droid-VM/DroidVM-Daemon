// SPDX-License-Identifier: GPL-3.0-or-later
#include "usb_acm.h"
#include "task_adapter.h"
#include <set>

namespace droidvm::web {
namespace {
[[noreturn]] void invalid() { throw ServiceError(ErrorCode::invalid_argument, "Invalid USB ACM request"); }
bool token(const Json::Value& value, size_t limit = 128) {
    if (!value.isString()) return false;
    const auto text = value.asString();
    return !text.empty() && text.size() <= limit && text.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-") == std::string::npos;
}
Json::Value expected(const Json::Value& value) {
    if (!value.isObject() || value.size() != 1 || !token(value["revision"])) invalid();
    return value;
}
Json::Value settings(const Json::Value& value) {
    if (!value.isObject() || value.size() != 2 || !value["enabled"].isBool() ||
        !value["ports"].isInt() || value["ports"].asInt() < 1 || value["ports"].asInt() > 6) invalid();
    return value;
}
Json::Value live(const Json::Value& value) {
    if (!value.isObject() || !value["available"].isBool() || !value["applied"].isBool() ||
        !value.isMember("udcBound") || (!value["udcBound"].isNull() && !value["udcBound"].isBool()) ||
        !value.isMember("ports") || (!value["ports"].isNull() && (!value["ports"].isInt() || value["ports"].asInt() < 0 || value["ports"].asInt() > 6)) ||
        !value["owners"].isArray() || value["owners"].size() > 6) invalid();
    Json::Value result;
    for (const auto* key : {"available", "applied", "udcBound", "ports"}) result[key] = value[key];
    result["reason"] = token(value["reason"], 64) ? value["reason"] : Json::Value();
    result["owners"] = Json::Value(Json::arrayValue);
    std::set<int> slots;
    for (const auto& owner : value["owners"]) {
        if (!owner.isObject() || !owner["slot"].isInt() || owner["slot"].asInt() < 0 || owner["slot"].asInt() > 5 ||
            !slots.insert(owner["slot"].asInt()).second || !token(owner["vmId"])) invalid();
        Json::Value row; row["slot"] = owner["slot"]; row["vmId"] = owner["vmId"];
        result["owners"].append(std::move(row));
    }
    if (result["applied"] == true && (result["available"] != true || result["ports"].isNull())) invalid();
    return result;
}
void access(const CallContext& caller, bool write) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || (write && !caller.manage_tasks))
        throw ServiceError(ErrorCode::permission_denied, "USB ACM permission required");
}
void identity(const TaskView& task, const std::string& id) {
    if (task.kind != "usb_acm" || task.resource != "usb-acm" || task.request_id != id)
        throw ServiceError(ErrorCode::conflict, "USB ACM task identity mismatch");
}
}
Json::Value usb_acm_catalog(const Json::Value& native) {
    try {
        if (!native.isObject() || native["capability"] != "usb-acm-v1" ||
            !native["initialized"].isBool() || !native["persistenceUncertain"].isBool()) invalid();
        Json::Value result;
        for (const auto* key : {"capability", "initialized", "persistenceUncertain"}) result[key] = native[key];
        result["expected"] = expected(native["expected"]); result["desired"] = settings(native["desired"]);
        result["live"] = live(native["live"]); return result;
    } catch (const ServiceError&) { throw ServiceError(ErrorCode::unavailable, "USB ACM observation unavailable"); }
}
Json::Value project_usb_acm_result(const Json::Value& native, bool cancelled) {
    if (!native.isObject() || !native["saved"].isBool() || !native["applied"].isBool() || !native["uncertain"].isBool()) return {};
    for (const auto* key : {"expected", "desired", "revision", "live"}) if (!native.isMember(key)) return {};
    Json::Value result;
    if (cancelled && native["expected"].isNull() && native["desired"].isNull() && native["revision"].isNull() &&
        native["live"].isNull() && native["saved"] == false && native["applied"] == false && native["uncertain"] == false) {
        for (const auto* key : {"expected", "desired", "revision", "live", "saved", "applied", "uncertain"}) result[key] = native[key];
        return result;
    }
    try {
        result["expected"] = expected(native["expected"]);
        result["desired"] = native["desired"].isNull() ? Json::Value() : settings(native["desired"]);
        result["live"] = native["live"].isNull() ? Json::Value() : live(native["live"]);
        if (!native["revision"].isNull() && !token(native["revision"])) return {};
        for (const auto* key : {"revision", "saved", "applied", "uncertain"}) result[key] = native[key];
        if ((result["saved"] == true || result["applied"] == true) && (result["desired"].isNull() || result["revision"].isNull())) return {};
        if (result["applied"] == true && (result["live"].isNull() || result["live"]["applied"] != true)) return {};
        return result;
    } catch (const ServiceError&) { return {}; }
}
WebServiceOperations usb_acm_operations(UsbAcmBindings bindings) {
    if (!bindings.read || !bindings.start || !bindings.status) throw std::invalid_argument("Missing USB ACM binding");
    return {
        [bindings](const CallContext& caller) { access(caller, false); return usb_acm_catalog(bindings.read(caller)); },
        {
            [bindings](const CallContext& caller, const Json::Value& input) {
                access(caller, true);
                if (!input.isObject() || input.size() != 3 || !token(input["requestId"])) invalid();
                (void)expected(input["expected"]);
                const auto& operation = input["operation"];
                if (!operation.isObject()) invalid();
                if (operation["kind"] == "configure") {
                    if (operation.size() != 3) invalid();
                    auto value = operation; value.removeMember("kind"); (void)settings(value);
                } else if (operation["kind"] != "apply" || operation.size() != 1) invalid();
                const auto task = bindings.start(caller, input); identity(task, input["requestId"].asString());
                return task_view(task);
            },
            [bindings](const CallContext& caller, const std::string& id) {
                access(caller, true); if (!token(id)) invalid();
                try { const auto task = bindings.status(caller, id); identity(task, id); return task_view(task); }
                catch (const ServiceError& error) { if (error.code() != ErrorCode::task_not_found) throw; return Json::Value(); }
            }
        }
    };
}
}
