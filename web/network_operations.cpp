// SPDX-License-Identifier: GPL-3.0-or-later
#include "network_operations.h"
#include "task_adapter.h"
#include "common/wire.h"
#include <charconv>

namespace droidvm::web {
namespace {
[[noreturn]] void invalid() { throw ServiceError(ErrorCode::invalid_argument, "Invalid network operation"); }
void access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || !caller.manage_tasks || caller.principal.empty())
        throw ServiceError(ErrorCode::permission_denied, "Network operation permission required");
}
std::string id(const Json::Value& value) {
    if (!value.isString()) invalid();
    auto result = value.asString();
    if (result.empty() || result.size() > 128 ||
        result.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::string::npos) invalid();
    return result;
}
uint64_t generation(const Json::Value& value) {
    if (!value.isString()) invalid();
    const auto input = value.asString();
    if (input.empty() || input.size() > 20) invalid();
    uint64_t result = 0;
    const auto [end, error] = std::from_chars(input.data(), input.data() + input.size(), result);
    if (error != std::errc() || end != input.data() + input.size() || std::to_string(result) != input) invalid();
    return result;
}
NetworkState state(const Json::Value& value) {
    if (!value.isString()) invalid();
    const auto input = value.asString();
    if (input == "STOPPED") return NetworkState::stopped;
    if (input == "STARTING") return NetworkState::starting;
    if (input == "RUNNING") return NetworkState::running;
    if (input == "RECOVERING") return NetworkState::recovering;
    if (input == "STOPPING") return NetworkState::stopping;
    if (input == "FAILED") return NetworkState::failed;
    invalid();
}
NetworkOperation request(const Json::Value& input) {
    if (!input.isObject() || input.size() != 4) invalid();
    (void)id(input["requestId"]);
    if (!input["action"].isString()) invalid();
    const auto action = input["action"].asString();
    if (action != "start" && action != "stop") invalid();
    const auto& expected = input["expected"];
    if (!expected.isObject() || expected.size() != 3) invalid();
    return {id(input["networkId"]), action == "start", generation(expected["generation"]),
        state(expected["state"]), id(expected["configurationRevision"])};
}
}
BackgroundOperations network_operations(TaskService& tasks, ExecuteNetworkOperation execute) {
    if (!execute) throw std::invalid_argument("Missing native network operation binding");
    return {
        [&tasks, execute](const CallContext& caller, const Json::Value& input) {
            access(caller);
            const auto operation = request(input);
            TaskSpec spec{"network_lifecycle", "networks", 1024, true, true};
            spec.request_id = id(input["requestId"]);
            auto signature = input; signature.removeMember("requestId");
            spec.request_signature = wire::stringify_bounded(signature, TaskSpec::max_signature_bytes);
            const auto ref = tasks.submit(caller, std::move(spec), [execute, caller, operation](TaskControl& control) {
                // Cancellation may discard queued work, but never claim a
                // running backend start/stop has been undone.
                if (!control.enter_commit()) return TaskCompletion::cancelled();
                execute(caller, operation);
                return TaskCompletion::success();
            });
            return task_view(tasks.get(caller, ref));
        },
        [&tasks](const CallContext& caller, const std::string& request_id) {
            access(caller); (void)id(Json::Value(request_id));
            const auto task = tasks.find_request(caller, request_id);
            if (task && task->kind != "network_lifecycle")
                throw ServiceError(ErrorCode::conflict, "Request belongs to another operation");
            return task ? task_view(*task) : Json::Value();
        }
    };
}
}
