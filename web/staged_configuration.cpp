// SPDX-License-Identifier: GPL-3.0-or-later
#include "staged_configuration.h"
#include "task_adapter.h"
#include "common/wire.h"

namespace droidvm::web {
namespace configuration_input {
[[noreturn]] void invalid() { throw ServiceError(ErrorCode::invalid_argument, "Invalid configuration request"); }
void access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || !caller.manage_tasks || caller.principal.empty())
        throw ServiceError(ErrorCode::permission_denied, "Configuration permission required");
}
std::string id(const Json::Value& value) {
    if (!value.isString()) invalid();
    const auto text = value.asString();
    if (text.empty() || text.size() > 128 || text.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::string::npos) invalid();
    return text;
}
size_t count(const Json::Value& value, size_t maximum) {
    if (!value.isUInt64() || value.asUInt64() > maximum) invalid();
    return static_cast<size_t>(value.asUInt64());
}
}
ConfigOperations staged_configuration(TaskService& tasks, JsonConfigurationStaging staging,
        std::string kind, std::string resource, size_t document_limit) {
    if (!staging.begin || !staging.append || !staging.commit || !staging.abort || kind.empty() || resource.empty() || !document_limit)
        throw std::invalid_argument("Missing configuration staging binding");
    return { [&tasks, staging = std::move(staging), kind = std::move(kind), resource = std::move(resource), document_limit]
        (const CallContext& caller, const std::string& operation, const Json::Value& input) {
        using namespace configuration_input;
        access(caller);
        if (!input.isObject()) invalid();
        Json::Value result(Json::objectValue);
        if (operation == "begin") {
            if (input.size() != 2) invalid();
            const auto bytes = count(input["bytes"], document_limit);
            if (!bytes) invalid();
            result["uploadId"] = staging.begin(caller, id(input["revision"]), bytes);
        } else if (operation == "append") {
            if (input.size() != 3 || !input["data"].isString()) invalid();
            std::string bytes;
            try { bytes = wire::decode_base64(input["data"].asString(), 48u << 10); }
            catch (const std::exception&) { invalid(); }
            if (bytes.empty()) invalid();
            result["received"] = Json::UInt64(staging.append(caller, id(input["uploadId"]), count(input["offset"], document_limit), bytes));
        } else if (operation == "abort") {
            if (input.size() != 1) invalid();
            staging.abort(caller, id(input["uploadId"]));
        } else if (operation == "commit") {
            if (input.size() != 2) invalid();
            const auto upload = id(input["uploadId"]);
            TaskSpec spec{kind, resource, 1024, true, true};
            spec.request_id = id(input["requestId"]);
            spec.request_signature = kind + ":" + upload;
            const auto ref = tasks.submit(caller, std::move(spec), [staging, caller, upload](TaskControl& control) {
                if (!control.enter_commit()) {
                    try { staging.abort(caller, upload); } catch (...) {}
                    return TaskCompletion::cancelled();
                }
                return TaskCompletion::success(staging.commit(caller, upload));
            }, [staging, caller, upload](const TaskRef&) { try { staging.abort(caller, upload); } catch (...) {} });
            result["task"] = task_view(tasks.get(caller, ref));
        } else if (operation == "status") {
            if (input.size() != 1) invalid();
            const auto task = tasks.find_request(caller, id(input["requestId"]));
            if (task && task->kind != kind) throw ServiceError(ErrorCode::not_found, "Configuration request not found");
            result["task"] = task ? task_view(*task) : Json::Value();
            result["version"] = task && task->state == TaskState::succeeded ? task->result : Json::Value();
        } else throw ServiceError(ErrorCode::not_found, "Unknown configuration operation");
        return result;
    }, {} };
}
}
