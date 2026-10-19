// SPDX-License-Identifier: GPL-3.0-or-later
#include "usb_operations.h"
#include "task_adapter.h"
#include "common/wire.h"
#include <charconv>

namespace droidvm::web {
namespace {
[[noreturn]] void invalid() { throw ServiceError(ErrorCode::invalid_argument, "Invalid USB operation"); }
void access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || !caller.manage_tasks || caller.principal.empty())
        throw ServiceError(ErrorCode::permission_denied, "USB operation permission required");
}
std::string text(const Json::Value& value, size_t maximum, bool empty = false) {
    if (!value.isString()) invalid();
    const auto result = value.asString();
    if ((!empty && result.empty()) || result.size() > maximum || result.find('\0') != std::string::npos) invalid();
    return result;
}
std::string request_id(const Json::Value& value) {
    auto result = text(value, 128);
    if (result.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::string::npos) invalid();
    return result;
}
UsbOperation parse(const Json::Value& input) {
    if (!input.isObject() || input.size() != 4 || !input["expected"].isObject() ||
        input["expected"].size() != 7 || !input["target"].isObject()) invalid();
    UsbOperation result;
    result.request_id = request_id(input["requestId"]);
    result.device_id = text(input["deviceId"], 128);
    const auto separator = result.device_id.find('#');
    if (separator == std::string::npos || separator == 0 || result.device_id.find('#', separator + 1) != std::string::npos ||
        result.device_id.find_first_not_of("0123456789.-#") != std::string::npos) invalid();
    result.sysfs = result.device_id.substr(0, separator);
    result.expected = input["expected"]; result.target = input["target"];
    const auto& expected = result.expected;
    if (!expected["busNumber"].isInt() || expected["busNumber"].asInt() < 1 || expected["busNumber"].asInt() > 65535 ||
        !expected["locked"].isBool()) invalid();
    (void)text(expected["vendorId"], 16, true); (void)text(expected["productId"], 16, true);
    const auto state = text(expected["state"], 16);
    if (state != "host" && state != "claimed" && state != "idle" && state != "unknown") invalid();
    const auto& owner = expected["owner"];
    if (!expected.isMember("owner")) invalid();
    if (!owner.isNull()) {
        if (!owner.isObject() || owner.size() != 3 || !owner.isMember("controllerId") || !owner.isMember("port")) invalid();
        (void)request_id(owner["vmId"]);
        if (!owner["controllerId"].isNull()) (void)text(owner["controllerId"], 128, true);
        if (!owner["port"].isNull() && (!owner["port"].isInt() || owner["port"].asInt() < 1 || owner["port"].asInt() > 65535)) invalid();
    }
    if (!result.expected["deviceNumber"].isInt() || result.expected["deviceNumber"].asInt() < 1 ||
        result.expected["deviceNumber"].asInt() > 65535 ||
        result.device_id.substr(separator + 1) != std::to_string(result.expected["deviceNumber"].asInt())) invalid();
    const auto kind = text(result.target["kind"], 16);
    if (kind == "vm") {
        if (result.target.size() != 5) invalid();
        (void)request_id(result.target["vmId"]);
        (void)text(result.target["controllerId"], 128, true);
        vm::Observation observed;
        observed.instance = text(result.target["instanceId"], 32);
        if (observed.instance.size() != 32 || observed.instance.find_first_not_of("0123456789abcdef") != std::string::npos) invalid();
        const auto revision = text(result.target["revision"], 20);
        const auto [end, error] = std::from_chars(revision.data(), revision.data() + revision.size(), observed.revision);
        if (error != std::errc() || end != revision.data() + revision.size() || std::to_string(observed.revision) != revision) invalid();
        result.vm_observation = observed;
    } else if ((kind != "host" && kind != "idle") || result.target.size() != 1) invalid();
    return result;
}
}
void require_usb_observation(const UsbOperation& operation, const Json::Value& catalogue) {
    if (!catalogue["available"].isBool() || !catalogue["available"].asBool())
        throw ServiceError(ErrorCode::unavailable, "USB catalogue unavailable");
    bool found = false;
    for (const auto& row : catalogue["items"]) if (row["id"] == operation.device_id && usb_observation(row) == operation.expected) found = true;
    if (!found) throw ServiceError(ErrorCode::conflict, "USB device or ownership changed");
    if (operation.target["kind"] != "vm") return;
    for (const auto& row : catalogue["targets"]) {
        if (row["vmId"] == operation.target["vmId"] && row["instanceId"] == operation.target["instanceId"] &&
            row["revision"] == operation.target["revision"] && row["controllerId"] == operation.target["controllerId"]) return;
    }
    throw ServiceError(ErrorCode::conflict, "USB target VM changed");
}
Json::Value usb_observation(const Json::Value& device) {
    Json::Value result;
    for (const auto* key : {"busNumber", "deviceNumber", "vendorId", "productId", "state", "locked"}) result[key] = device[key];
    result["owner"] = device["owner"];
    if (result["owner"].isObject()) result["owner"].removeMember("vmName");
    return result;
}
UsbOperations usb_operations(TaskService& tasks, ApplyUsbOperation apply) {
    if (!apply) throw std::invalid_argument("Missing USB operation binding");
    return {
        [&tasks, apply](const CallContext& caller, const Json::Value& input) {
            access(caller);
            auto request = parse(input);
            TaskSpec spec{"usb_target", "usb:" + request.device_id, 4, true, true};
            auto signature = input; signature.removeMember("requestId");
            spec.request_id = request.request_id; spec.request_signature = wire::stringify(signature);
            const auto ref = tasks.submit(caller, std::move(spec), [apply, caller, request](TaskControl& control) {
                if (!control.enter_commit()) return TaskCompletion::cancelled();
                apply(caller, request);
                return TaskCompletion::success();
            });
            return task_view(tasks.get(caller, ref));
        },
        [&tasks](const CallContext& caller, const std::string& id) {
            access(caller); request_id(Json::Value(id));
            const auto task = tasks.find_request(caller, id);
            if (task && task->kind != "usb_target") throw ServiceError(ErrorCode::conflict, "Request belongs to another operation");
            return task ? task_view(*task) : Json::Value();
        }
    };
}
}
