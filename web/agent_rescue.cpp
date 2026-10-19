// SPDX-License-Identifier: GPL-3.0-or-later
#include "agent_rescue.h"
#include "staged_configuration.h"
#include "task_adapter.h"
#include "vm_terminal_source.h"
#include "common/identity.h"
#include <algorithm>

namespace droidvm::web {
bool valid_rescue_session_id(std::string_view id) noexcept {
    return id.size() == 64 && id.find_first_not_of("0123456789abcdef") == std::string_view::npos;
}
Json::Value project_agent_rescue_cleanup(const Json::Value& value) {
    if (!value.isObject() || !value["sessionId"].isString()
        || !valid_rescue_session_id(value["sessionId"].asString()) || !value["cleanup"].isObject()) return {};
    const auto& cleanup = value["cleanup"];
    for (const char* key : {"stopped", "removed", "diskSynced"}) if (!cleanup[key].isBool()) return {};
    if (!cleanup["stopped"].asBool() && (cleanup["removed"].asBool() || cleanup["diskSynced"].asBool())) return {};
    Json::Value result; result["sessionId"] = value["sessionId"];
    for (const char* key : {"stopped", "removed", "diskSynced"}) result["cleanup"][key] = cleanup[key];
    return result;
}
AgentRescueOperations agent_rescue(TaskService& tasks, agent::RescueSessions& sessions, agent::RescueSessions::Now now) {
    if (!now) throw std::invalid_argument("Missing rescue clock");
    auto source = std::make_shared<VmTerminalSource>(VmTerminalSource{
        [&sessions](const CallContext& caller, const std::string& id) {
            if (!valid_rescue_session_id(id)) configuration_input::invalid();
            return VmTerminalTarget{id, sessions.observe(caller, id), {"uart"}};
        },
        [&sessions](const CallContext& caller, const VmTerminalRead& read) {
            if (!valid_rescue_session_id(read.vm_id) || read.stream != "uart") configuration_input::invalid();
            return sessions.read(caller, read.vm_id, read.observed, read.cursor, read.tail);
        },
        [&sessions](const CallContext& caller, const VmTerminalWrite& write) {
            if (!valid_rescue_session_id(write.vm_id) || write.stream != "uart") configuration_input::invalid();
            return sessions.write(caller, write.vm_id, write.observed, write.bytes);
        }
    });
    return {
        [&sessions, now](const CallContext& caller) {
            configuration_input::access(caller);
            Json::Value result; auto& items = result["items"] = Json::Value(Json::arrayValue);
            const auto current = now();
            for (const auto& session : sessions.list(caller)) {
                Json::Value row;
                row["id"] = session.id; row["diskId"] = session.disk_id;
                row["expected"]["instanceId"] = session.expected.instance;
                row["expected"]["revision"] = std::to_string(session.expected.revision);
                const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(session.expires - current).count();
                row["remainingMs"] = Json::UInt64(session.expired ? 0 : std::clamp<int64_t>(remaining, 0, 900000));
                row["closing"] = session.closing; row["expired"] = session.expired;
                items.append(std::move(row));
            }
            return result;
        }, {
            [&tasks, &sessions](const CallContext& caller, const Json::Value& input) {
                using namespace configuration_input;
                access(caller);
                if (!input.isObject() || input.size() != 2 || !input["sessionId"].isString()) invalid();
                const auto session_id = input["sessionId"].asString();
                if (!valid_rescue_session_id(session_id)) invalid();
                TaskSpec spec{"agent_rescue_close", "agent-rescue:" + session_id, 1024, true, true};
                spec.request_id = id(input["requestId"]);
                spec.request_signature = "agent-rescue-close-once:" + random_id(true);
                // Ownership is checked again by the registry at execution time.
                (void)sessions.view(caller, session_id);
                const auto ref = tasks.submit(caller, std::move(spec), [&sessions, caller, session_id](TaskControl& control) {
                    if (!control.enter_commit()) return TaskCompletion::cancelled();
                    try {
                        const auto cleanup = sessions.close(caller, session_id);
                        Json::Value result; result["sessionId"] = session_id;
                        result["cleanup"]["stopped"] = cleanup.stopped;
                        result["cleanup"]["removed"] = cleanup.removed;
                        result["cleanup"]["diskSynced"] = cleanup.disk_synced;
                        if (cleanup.stopped && cleanup.removed && cleanup.disk_synced)
                            return TaskCompletion::success(std::move(result));
                        return TaskCompletion::failure(ErrorCode::io_error, "Rescue cleanup was not fully confirmed", std::move(result));
                    } catch (const ServiceError& error) {
                        return TaskCompletion::failure(error.code(), "Rescue cleanup failed");
                    } catch (...) { return TaskCompletion::failure(ErrorCode::internal, "Rescue cleanup failed"); }
                });
                return task_view(tasks.get(caller, ref));
            },
            [&tasks](const CallContext& caller, const std::string& request_id) {
                using namespace configuration_input;
                access(caller); (void)id(Json::Value(request_id));
                const auto task = tasks.find_request(caller, request_id);
                if (task && task->kind != "agent_rescue_close") throw ServiceError(ErrorCode::conflict, "Request belongs to another operation");
                return task ? task_view(*task) : Json::Value();
            }
        }, std::move(source)
    };
}
}
