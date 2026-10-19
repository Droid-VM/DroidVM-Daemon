// SPDX-License-Identifier: GPL-3.0-or-later
#include "agent_operations.h"
#include "agent_rescue.h"
#include "staged_configuration.h"
#include "task_adapter.h"
#include "common/identity.h"
#include <algorithm>
#include <initializer_list>
#include <memory>
#include <string_view>

namespace droidvm::web {
namespace {
using namespace configuration_input;
using namespace agent;

bool one_of(const Json::Value& value, std::initializer_list<std::string_view> choices) {
    if (!value.isString()) return false;
    const auto text = value.asString();
    for (auto choice : choices) if (text == choice) return true;
    return false;
}
bool public_code(const Json::Value& value) {
    return value.isNull() || one_of(value, {
        "ROOT_NOT_FOUND", "PASSWD_FAILED", "PASSWD_NOT_FOUND", "UNMOUNT_FAILED", "SCRIPT_FAILED",
        "AUTOGROW_DISK_NOT_FOUND", "AUTOGROW_PROBE_FAILED", "AUTOGROW_PARTITION_IN_USE",
        "PARTITION_GROW_FAILED", "PARTITION_REREAD_FAILED", "FILESYSTEM_CHECK_FAILED",
        "FILESYSTEM_MOUNT_FAILED", "FILESYSTEM_GROW_FAILED", "FILESYSTEM_UNMOUNT_FAILED",
        "NO_PARTITION", "UNKNOWN_FILESYSTEM", "NO_TRAILING_SPACE", "UNSUPPORTED_FILESYSTEM",
        "UNKNOWN_AGENT_ERROR", "UNKNOWN_AGENT_SKIP"});
}
Json::Value safe_code(const std::string& code) {
    if (code.empty()) return {};
    const Json::Value value(code);
    return public_code(value) ? value : Json::Value("UNKNOWN_AGENT_ERROR");
}
const char* guest_outcome(Outcome outcome) {
    switch (outcome) {
        case Outcome::pending: return "pending";
        case Outcome::guest_succeeded: return "succeeded";
        case Outcome::guest_skipped: return "skipped";
        case Outcome::guest_partial: return "partial";
        case Outcome::guest_failed: return "failed";
        case Outcome::aborted: return "cancelled";
        case Outcome::uncertain: return "uncertain";
    }
    return "uncertain";
}
const char* guest_cleanup(GuestCleanup cleanup) {
    switch (cleanup) {
        case GuestCleanup::not_required: return "not_required";
        case GuestCleanup::pending: return "pending";
        case GuestCleanup::succeeded: return "succeeded";
        case GuestCleanup::failed: return "failed";
        case GuestCleanup::uncertain: return "uncertain";
    }
    return "uncertain";
}
const char* action_state(ActionState state) {
    switch (state) {
        case ActionState::pending: return "pending";
        case ActionState::running: return "running";
        case ActionState::succeeded: return "succeeded";
        case ActionState::skipped: return "skipped";
        case ActionState::failed: return "failed";
    }
    return "failed";
}
const char* runner_reason(RunnerReason reason) {
    switch (reason) {
        case RunnerReason::none: return "none";
        case RunnerReason::cancelled: return "cancelled";
        case RunnerReason::start_rejected: return "start_rejected";
        case RunnerReason::startup_timeout: return "startup_timeout";
        case RunnerReason::preparation_timeout: return "preparation_timeout";
        case RunnerReason::action_timeout: return "action_timeout";
        case RunnerReason::finalization_timeout: return "finalization_timeout";
        case RunnerReason::vm_stopped: return "vm_stopped";
        case RunnerReason::console_lost: return "console_lost";
        case RunnerReason::write_unknown: return "write_unknown";
        case RunnerReason::host_exception: return "host_exception";
        case RunnerReason::protocol_error: return "protocol_error";
        case RunnerReason::guest_cleanup_failed: return "guest_cleanup_failed";
        case RunnerReason::disk_sync_failed: return "disk_sync_failed";
    }
    return "host_exception";
}
Json::Value receipt(const std::string& disk, ActionKind action, const RunnerResult& run) {
    Json::Value value;
    value["diskId"] = disk;
    value["action"] = std::string(action_name(action));
    value["guestOutcome"] = guest_outcome(run.protocol.guest_result);
    value["guestCode"] = safe_code(run.protocol.guest_code);
    value["guestCleanup"] = guest_cleanup(run.protocol.guest_cleanup);
    value["cleanup"]["stopped"] = run.cleanup.stopped;
    value["cleanup"]["removed"] = run.cleanup.stopped && run.cleanup.removed;
    value["cleanup"]["diskSynced"] = run.cleanup.stopped && run.cleanup.disk_synced;
    const bool durable = run.durability_confirmed && run.committed && run.cleanup.stopped
        && run.cleanup.removed && run.cleanup.disk_synced && run.protocol.guest_cleanup == GuestCleanup::succeeded;
    value["durabilityConfirmed"] = durable;
    value["committed"] = run.committed;
    value["reason"] = runner_reason(run.reason);
    value["recoveryRequired"] = !value["cleanup"]["removed"].asBool();
    auto& actions = value["actions"] = Json::Value(Json::arrayValue);
    if (run.protocol.actions.size() > 16) throw std::runtime_error("Invalid Agent action count");
    for (const auto& progress : run.protocol.actions) {
        Json::Value row;
        row["action"] = std::string(action_name(progress.kind));
        row["state"] = action_state(progress.state);
        row["code"] = safe_code(progress.code);
        actions.append(std::move(row));
    }
    const bool cleaned = run.cleanup.stopped && run.cleanup.removed;
    if (run.status == RunnerStatus::cancelled && !run.committed && cleaned) value["outcome"] = "cancelled";
    else if (run.status == RunnerStatus::uncertain || run.status == RunnerStatus::cleanup_failed
        || run.protocol.outcome == Outcome::uncertain) value["outcome"] = "uncertain";
    else if (run.protocol.outcome == Outcome::guest_succeeded) {
        const bool complete_success = durable && run.status == RunnerStatus::guest_reported
            && run.protocol.guest_result == Outcome::guest_succeeded && !run.protocol.actions.empty()
            && std::all_of(run.protocol.actions.begin(), run.protocol.actions.end(),
                [](const auto& progress) { return progress.state == ActionState::succeeded; });
        value["outcome"] = complete_success ? "succeeded" : "uncertain";
    }
    else if (run.protocol.outcome == Outcome::guest_skipped) value["outcome"] = "skipped";
    else if (run.protocol.outcome == Outcome::guest_partial) value["outcome"] = "partial";
    else value["outcome"] = "failed";
    return value;
}
TaskCompletion complete(const std::string& disk, ActionKind action, const NativeResult& native, TaskControl& control, bool rescue) {
    const auto& run = native.execution;
    auto result = receipt(disk, action, run);
    if (run.handed_off || !native.rescue_session_id.empty()) {
        if (!rescue || !run.handed_off || !run.protocol.shell_ready || !run.committed
            || !valid_rescue_session_id(native.rescue_session_id) || run.cleanup.stopped || run.cleanup.removed
            || run.cleanup.disk_synced || run.durability_confirmed)
            return TaskCompletion::failure(ErrorCode::commit_uncertain, "Rescue custody was not confirmed");
        result["outcome"] = "rescue_ready";
        result["rescueSessionId"] = native.rescue_session_id;
        result["recoveryRequired"] = false;
        return TaskCompletion::success(std::move(result));
    }
    if (result["outcome"] == "succeeded") return TaskCompletion::success(std::move(result));
    if (result["outcome"] == "cancelled" && control.cancellation_requested())
        return TaskCompletion::cancelled(std::move(result));
    const auto error = result["outcome"] == "uncertain" ? ErrorCode::commit_uncertain : ErrorCode::io_error;
    return TaskCompletion::failure(error,
        "Agent operation did not complete successfully", std::move(result));
}
Json::Value recovery_view(const Json::Value& result) {
    if (!result.isObject() || !result["pending"].isUInt64() || result["pending"].asUInt64() > 64)
        throw ServiceError(ErrorCode::internal, "Invalid Agent recovery result");
    Json::Value view; view["pendingRecords"] = result["pending"];
    return view;
}
}

Json::Value project_agent_result(const Json::Value& value) {
    if (!value.isObject()) return {};
    try {
        Json::Value identity;
        identity["action"] = "autogrow";
        identity["diskId"] = value["diskId"];
        (void)agent::parse_request(identity); // Reuse the canonical UUID boundary.
    } catch (...) { return {}; }
    if (!one_of(value["action"], {"chpasswd", "autogrow"})
        || !one_of(value["outcome"], {"succeeded", "skipped", "partial", "failed", "uncertain", "cancelled", "rescue_ready"})
        || !one_of(value["guestOutcome"], {"pending", "succeeded", "skipped", "partial", "failed", "uncertain", "cancelled"})
        || !value.isMember("guestCode") || !public_code(value["guestCode"])
        || !one_of(value["guestCleanup"], {"not_required", "pending", "succeeded", "failed", "uncertain"})
        || !one_of(value["reason"], {"none", "cancelled", "start_rejected", "startup_timeout", "preparation_timeout",
            "action_timeout", "finalization_timeout", "vm_stopped", "console_lost", "write_unknown", "host_exception",
            "protocol_error", "guest_cleanup_failed", "disk_sync_failed"})
        || !value["durabilityConfirmed"].isBool() || !value["committed"].isBool()
        || !value["recoveryRequired"].isBool() || !value["cleanup"].isObject()
        || !value["actions"].isArray() || value["actions"].size() > 16) return {};
    const auto& cleanup = value["cleanup"];
    for (const char* key : {"stopped", "removed", "diskSynced"}) if (!cleanup[key].isBool()) return {};
    const bool rescue = value["outcome"] == "rescue_ready";
    if (rescue) {
        if (!value["rescueSessionId"].isString() || !valid_rescue_session_id(value["rescueSessionId"].asString())
            || !value["committed"].asBool() || value["durabilityConfirmed"].asBool() || value["recoveryRequired"].asBool()
            || cleanup["stopped"].asBool() || cleanup["removed"].asBool() || cleanup["diskSynced"].asBool()) return {};
    } else if (value.isMember("rescueSessionId") || value["recoveryRequired"].asBool() == cleanup["removed"].asBool()) return {};
    if (!cleanup["stopped"].asBool() && (cleanup["removed"].asBool() || cleanup["diskSynced"].asBool())) return {};
    if (value["durabilityConfirmed"].asBool() && (!value["committed"].asBool() || value["guestCleanup"] != "succeeded"
        || !cleanup["stopped"].asBool() || !cleanup["removed"].asBool() || !cleanup["diskSynced"].asBool())) return {};
    if (value["outcome"] == "succeeded" && (!value["durabilityConfirmed"].asBool() || value["guestOutcome"] != "succeeded")) return {};
    if (value["outcome"] == "cancelled" && (value["committed"].asBool() || !cleanup["removed"].asBool())) return {};
    Json::Value result;
    for (const char* key : {"diskId", "action", "outcome", "guestOutcome", "guestCode", "guestCleanup",
        "durabilityConfirmed", "committed", "reason", "recoveryRequired"}) result[key] = value[key];
    if (rescue) result["rescueSessionId"] = value["rescueSessionId"];
    for (const char* key : {"stopped", "removed", "diskSynced"}) result["cleanup"][key] = cleanup[key];
    result["actions"] = Json::Value(Json::arrayValue);
    for (const auto& action : value["actions"]) {
        if (!action.isObject() || !one_of(action["action"], {"chpasswd", "autogrow"})
            || !one_of(action["state"], {"pending", "running", "succeeded", "skipped", "failed"})
            || !action.isMember("code") || !public_code(action["code"])) return {};
        Json::Value row;
        for (const char* key : {"action", "state", "code"}) row[key] = action[key];
        result["actions"].append(std::move(row));
    }
    return result;
}

BackgroundOperations agent_operations(TaskService& tasks, ExecuteAgentOperation execute, TaskService::Now now) {
    if (!execute || !now) throw std::invalid_argument("Missing native Agent operation binding");
    return {
        [&tasks, execute, now](const CallContext& caller, const Json::Value& input) {
            access(caller);
            if (!input.isObject() || input.size() != 4u + (input.isMember("rescue") ? 1u : 0u)
                || (input.isMember("rescue") && !input["rescue"].isBool())) invalid();
            const bool rescue = input.get("rescue", false).asBool();
            const auto request_id = id(input["requestId"]);
            const Confirmation confirmed{id(input["revision"]), id(input["vmRevision"])};
            auto request = parse_request(input["operation"]);
            const auto disk = request.disk_id();
            const auto action = request.action();
            auto secret = std::make_shared<Request>(std::move(request));
            const auto expires = now() + std::chrono::seconds(60);
            TaskSpec spec{"agent_operation", "disk:" + disk, 16u << 10, true, true};
            spec.request_id = request_id;
            // Intentionally unrelated to the password: no retained secret,
            // password-derived hash, or equality oracle in task metadata.
            spec.request_signature = "agent-once-v1:" + random_id(true);
            const auto ref = tasks.submit(caller, std::move(spec),
                [execute, now, caller, confirmed, disk, action, expires, rescue, secret = std::move(secret)](TaskControl& control) mutable {
                    try {
                        auto request = std::move(*secret);
                        secret.reset(); // No credential remains in the retained work capture.
                        if (control.cancellation_requested()) return TaskCompletion::cancelled();
                        if (now() >= expires) return TaskCompletion::failure(ErrorCode::unavailable, "Agent request expired before execution");
                        auto result = execute(caller, std::move(request), confirmed, control, rescue);
                        return complete(disk, action, result, control, rescue);
                    } catch (const ServiceError& error) {
                        return TaskCompletion::failure(error.code(), "Agent operation failed");
                    } catch (...) {
                        return TaskCompletion::failure(ErrorCode::internal, "Agent operation failed");
                    }
                });
            return task_view(tasks.get(caller, ref));
        },
        [&tasks](const CallContext& caller, const std::string& request_id) {
            access(caller); (void)id(Json::Value(request_id));
            const auto task = tasks.find_request(caller, request_id);
            if (task && task->kind != "agent_operation") throw ServiceError(ErrorCode::conflict, "Request belongs to another operation");
            return task ? task_view(*task) : Json::Value();
        }
    };
}

DiskRecoveryOperations agent_recovery(TaskService& tasks, std::function<size_t(const CallContext&)> pending,
        std::function<Json::Value(const CallContext&)> recover) {
    if (!pending || !recover) throw std::invalid_argument("Missing native Agent recovery binding");
    return {
        [pending](const CallContext& caller) {
            access(caller);
            try {
                const auto count = pending(caller);
                if (count > 64) throw ServiceError(ErrorCode::internal, "Invalid Agent recovery count");
                Json::Value result; result["pendingRecords"] = Json::UInt64(count); return result;
            } catch (...) { throw ServiceError(ErrorCode::internal, "Agent recovery status unavailable"); }
        }, {
            [&tasks, recover](const CallContext& caller, const Json::Value& input) {
                access(caller);
                if (!input.isObject() || input.size() != 1) invalid();
                TaskSpec spec{"agent_recovery", "agent", 1024, true, true};
                spec.request_id = id(input["requestId"]);
                spec.request_signature = "agent-recovery-v1";
                const auto ref = tasks.submit(caller, std::move(spec), [recover, caller](TaskControl& control) {
                    if (!control.enter_commit()) return TaskCompletion::cancelled();
                    try { return TaskCompletion::success(recovery_view(recover(caller))); }
                    catch (const ServiceError& error) { return TaskCompletion::failure(error.code(), "Agent recovery failed"); }
                    catch (...) { return TaskCompletion::failure(ErrorCode::internal, "Agent recovery failed"); }
                });
                return task_view(tasks.get(caller, ref));
            },
            [&tasks](const CallContext& caller, const std::string& request_id) {
                access(caller); (void)id(Json::Value(request_id));
                const auto task = tasks.find_request(caller, request_id);
                if (task && task->kind != "agent_recovery") throw ServiceError(ErrorCode::conflict, "Request belongs to another operation");
                return task ? task_view(*task) : Json::Value();
            }
        }
    };
}
}
