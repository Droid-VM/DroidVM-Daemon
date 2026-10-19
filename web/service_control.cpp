// SPDX-License-Identifier: GPL-3.0-or-later
#include "service_control.h"
#include "service.h"
#include "staged_configuration.h"
#include "task_adapter.h"
#include "common/wire.h"

namespace droidvm::web {
namespace {
using namespace configuration_input;
Json::Value settings(const Json::Value& value) {
    return WebSettings::parse(value).json();
}
std::string action(const Json::Value& value) {
    if (value != "configure" && value != "restart") invalid();
    return value.asString();
}
Json::Value status(const Json::Value& value) {
    if (!value.isObject() || !value["running"].isBool() || !value["applyPending"].isBool()
        || (value["state"] != "disabled" && value["state"] != "running" && value["state"] != "local_only" && value["state"] != "error")
        || (!value.isMember("error") || (!value["error"].isNull() && value["error"] != "discovery_failed"
            && value["error"] != "listen_failed" && value["error"] != "configuration_write_failed"))
        || !value["addresses"].isArray() || value["addresses"].size() > 64) invalid();
    Json::Value result; result["settings"] = settings(value["settings"]);
    for (const auto* field : {"running", "state", "error", "applyPending"}) result[field] = value[field];
    result["addresses"] = Json::Value(Json::arrayValue);
    for (const auto& address : value["addresses"]) {
        if (!address.isString() || !address.asString().starts_with("http://")) invalid();
        const auto text = address.asString();
        try { HttpApi::validate_origins({{text.substr(7), text}}); } catch (const std::exception&) { invalid(); }
        result["addresses"].append(address);
    }
    return result;
}
}
Json::Value project_web_service_result(const Json::Value& value) {
    try {
        if (!value.isObject() || !value["applyPending"].isBool()) return {};
        Json::Value result; result["action"] = action(value["action"]);
        result["settings"] = settings(value["settings"]); result["applyPending"] = value["applyPending"];
        return result;
    } catch (...) { return {}; }
}
WebServiceOperations web_service_operations(TaskService& tasks, WebServiceBindings bindings) {
    if (!bindings.read || !bindings.change) throw std::invalid_argument("Missing Web service control binding");
    return {
        [read = bindings.read](const CallContext& caller) {
            access(caller); return status(read(caller));
        }, {
            [&tasks, change = bindings.change](const CallContext& caller, const Json::Value& input) {
                access(caller);
                if (!input.isObject() || input.size() != 4) invalid();
                const auto request_id = id(input["requestId"]);
                Json::Value command; command["action"] = action(input["action"]);
                command["expected"] = settings(input["expected"]); command["settings"] = settings(input["settings"]);
                if (command["action"] == "restart" && command["settings"] != command["expected"]) invalid();
                TaskSpec spec{"web_service", "webui", 8192, true, true};
                spec.request_id = request_id; spec.request_signature = "web_service:" + wire::stringify(command);
                const auto ref = tasks.submit(caller, std::move(spec), [change, caller, command](TaskControl& control) {
                    if (!control.enter_commit()) return TaskCompletion::cancelled();
                    auto result = project_web_service_result(change(caller, command));
                    if (result.isNull() || result["action"] != command["action"] || result["settings"] != command["settings"] || result["applyPending"] != true)
                        throw ServiceError(ErrorCode::internal, "Invalid Web service configuration receipt");
                    // This receipt confirms saving/queueing only. The active
                    // listener is observed separately after applyPending clears.
                    return TaskCompletion::success(std::move(result));
                });
                return task_view(tasks.get(caller, ref));
            },
            [&tasks](const CallContext& caller, const std::string& request_id) {
                access(caller); (void)id(request_id);
                const auto task = tasks.find_request(caller, request_id);
                if (task && (task->kind != "web_service" || task->resource != "webui"))
                    throw ServiceError(ErrorCode::not_found, "Web service request not found");
                return task ? task_view(*task) : Json::Value();
            }
        }
    };
}
}
