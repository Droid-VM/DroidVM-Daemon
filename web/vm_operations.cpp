// SPDX-License-Identifier: GPL-3.0-or-later
#include "vm_operations.h"
#include "task_adapter.h"
#include "common/wire.h"
#include <charconv>

namespace droidvm::web {
namespace {
[[noreturn]] void invalid() { throw ServiceError(ErrorCode::invalid_argument, "Invalid VM operation"); }
void access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || !caller.manage_tasks || caller.principal.empty())
        throw ServiceError(ErrorCode::permission_denied, "VM operation permission required");
}
std::string field(const Json::Value& value, size_t maximum) {
    if (!value.isString()) invalid();
    auto text = value.asString();
    if (text.empty() || text.size() > maximum || text.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::string::npos) invalid();
    return text;
}
VmOperation parse(const Json::Value& input) {
    if (!input.isObject() || input.size() != 4 || !input["expected"].isObject() || input["expected"].size() != 3) invalid();
    VmOperation result;
    result.request_id = field(input["requestId"], 128);
    result.vm_id = field(input["vmId"], 128);
    result.action = field(input["action"], 16);
    if (result.action != "start" && result.action != "stop" && result.action != "reboot" && result.action != "suspend" && result.action != "resume") invalid();
    const auto& expected = input["expected"];
    result.observed.instance = field(expected["instanceId"], 32);
    if (result.observed.instance.size() != 32 || result.observed.instance.find_first_not_of("0123456789abcdef") != std::string::npos) invalid();
    const auto revision = field(expected["revision"], 20);
    const auto [end, error] = std::from_chars(revision.data(), revision.data() + revision.size(), result.observed.revision);
    if (error != std::errc() || end != revision.data() + revision.size() || std::to_string(result.observed.revision) != revision) invalid();
    if (!expected.isMember("configRevision")) invalid();
    if (!expected["configRevision"].isNull()) result.config_revision = field(expected["configRevision"], 128);
    if (result.action == "start" && result.config_revision.empty()) invalid();
    return result;
}
}
VmOperations vm_operations(TaskService& tasks, ApplyVmOperation apply) {
    if (!apply) throw std::invalid_argument("Missing VM operation binding");
    return {
        [&tasks, apply](const CallContext& caller, const Json::Value& input) {
            access(caller);
            auto request = parse(input);
            TaskSpec spec{"vm_" + request.action, "vm:" + request.vm_id, 4, true, true};
            spec.request_id = request.request_id;
            spec.request_signature = wire::stringify(input);
            auto ref = tasks.submit(caller, std::move(spec), [apply, caller, request](TaskControl& control) {
                if (!control.enter_commit()) return TaskCompletion::cancelled();
                apply(caller, request);
                control.progress({"admitted", "", 0, {}});
                return TaskCompletion::success();
            });
            return task_view(tasks.get(caller, ref));
        },
        [&tasks](const CallContext& caller, const std::string& id) {
            access(caller);
            field(Json::Value(id), 128);
            const auto task = tasks.find_request(caller, id);
            return task ? task_view(*task) : Json::Value();
        }
    };
}
}
