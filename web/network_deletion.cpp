// SPDX-License-Identifier: GPL-3.0-or-later
#include "network_deletion.h"
#include "task_adapter.h"

namespace droidvm::web {
namespace {
Json::Value deletion_version(const Json::Value& saved) {
    // Native commit may already have changed both durable stores. A malformed
    // receipt is therefore uncertain, not proof that the operation did nothing.
    auto uncertain = []() -> void {
        throw ServiceError(ErrorCode::commit_uncertain, "Network deletion persistence was not confirmed");
    };
    if (!saved.isObject() || saved["persistence"] != "persisted") uncertain();
    Json::Value result;
    for (const char* key : {"networkId", "vmRevision"}) {
        try { result[key] = configuration_input::id(saved[key]); }
        catch (const ServiceError&) { uncertain(); }
    }
    result["persistence"] = "persisted";
    return result;
}
}
ConfigOperations network_deletion(TaskService& tasks, JsonConfigurationStaging staging) {
    if (!staging.commit) throw std::invalid_argument("Missing network deletion commit");
    const auto commit = std::move(staging.commit);
    staging.commit = [commit](const CallContext& caller, const std::string& upload) {
        return deletion_version(commit(caller, upload));
    };
    return staged_configuration(tasks, std::move(staging), "network_deletion", "networks", 9u << 20);
}
BackgroundOperations configuration_recovery(TaskService& tasks, std::function<void(const CallContext&)> recover) {
    if (!recover) throw std::invalid_argument("Missing configuration recovery binding");
    return {
        [&tasks, recover](const CallContext& caller, const Json::Value& input) {
            using namespace configuration_input;
            access(caller);
            if (!input.isObject() || input.size() != 1) invalid();
            TaskSpec spec{"configuration_recovery", "networks", 1024, true, true};
            spec.request_id = id(input["requestId"]);
            spec.request_signature = "configuration-recovery-v1";
            const auto ref = tasks.submit(caller, std::move(spec), [recover, caller](TaskControl& control) {
                if (!control.enter_commit()) return TaskCompletion::cancelled();
                recover(caller);
                return TaskCompletion::success();
            });
            return task_view(tasks.get(caller, ref));
        },
        [&tasks](const CallContext& caller, const std::string& request_id) {
            using namespace configuration_input;
            access(caller); (void)id(Json::Value(request_id));
            const auto task = tasks.find_request(caller, request_id);
            if (task && task->kind != "configuration_recovery")
                throw ServiceError(ErrorCode::conflict, "Request belongs to another operation");
            return task ? task_view(*task) : Json::Value();
        }
    };
}
}
