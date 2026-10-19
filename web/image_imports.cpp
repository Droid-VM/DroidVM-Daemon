// SPDX-License-Identifier: GPL-3.0-or-later
#include "image_imports.h"
#include "staged_configuration.h"
#include "task_adapter.h"
#include "common/wire.h"
#include <charconv>
#include <set>

namespace droidvm::web {
namespace {
using namespace configuration_input;
std::string text(const Json::Value& value, size_t maximum) {
    if (!value.isString()) invalid();
    auto result = value.asString();
    if (result.empty() || result.size() > maximum || result.find('\0') != std::string::npos) invalid();
    return result;
}
std::string path(const Json::Value& value) {
    auto result = text(value, 4096); if (result.front() != '/') invalid(); return result;
}
bool flag(const Json::Value& value) { if (!value.isBool()) invalid(); return value.asBool(); }
Json::UInt number(const Json::Value& value, Json::UInt maximum) {
    if ((value.type() != Json::intValue && value.type() != Json::uintValue) || !value.isUInt() || value.asUInt() > maximum) invalid();
    return value.asUInt();
}
std::string size_bytes(const Json::Value& value) {
    auto result = text(value, 20); uint64_t bytes = 0;
    const auto [end, error] = std::from_chars(result.data(), result.data() + result.size(), bytes);
    if (error != std::errc() || end != result.data() + result.size() || std::to_string(bytes) != result) invalid();
    return result;
}
void require_task(const TaskView& task, const CallContext& caller, const std::string& request_id, const std::string& kind) {
    if (task.kind != kind || task.resource != "image" || task.owner != caller.principal || task.request_id != request_id)
        throw ServiceError(ErrorCode::conflict, "Request belongs to another operation");
}
}
Json::Value project_image_import_plan(const Json::Value& value) {
    try {
        if (!value.isObject() || !value["members"].isArray() || value["members"].empty() || value["members"].size() > 64
            || !value["attachments"].isArray() || value["attachments"].size() > 512) return {};
        Json::Value result; result["source"] = path(value["source"]); result["vmRevision"] = id(value["vmRevision"]);
        result["diskRevision"] = id(value["diskRevision"]); result["diskId"] = id(value["diskId"]);
        result["members"] = Json::Value(Json::arrayValue); result["attachments"] = Json::Value(Json::arrayValue);
        std::set<std::string> ids, paths;
        for (const auto& member : value["members"]) {
            if (!member.isObject()) invalid();
            Json::Value row; const auto member_id = id(member["id"]), member_path = path(member["path"]);
            if (!ids.insert(member_id).second || !paths.insert(member_path).second) invalid();
            row["id"] = member_id; row["path"] = member_path; row["name"] = text(member["name"], 255);
            if (!member.isMember("parentId")) invalid();
            row["parentId"] = member["parentId"].isNull() ? Json::Value() : Json::Value(id(member["parentId"]));
            row["existing"] = flag(member["existing"]); row["format"] = text(member["format"], 128);
            row["virtualSizeBytes"] = size_bytes(member["virtualSizeBytes"]); result["members"].append(std::move(row));
        }
        if (result["members"][0]["id"] != result["diskId"]) invalid();
        for (const auto& row : result["members"]) {
            if (!row["parentId"].isNull() && (!ids.contains(row["parentId"].asString()) || row["parentId"] == row["id"])) invalid();
        }
        std::set<std::pair<std::string, Json::UInt>> slots;
        for (const auto& attachment : value["attachments"]) {
            if (!attachment.isObject()) invalid();
            Json::Value row; const auto vm = id(attachment["vmId"]); const auto slot = number(attachment["slot"], UINT32_MAX);
            if (!slots.emplace(vm, slot).second) invalid();
            row["vmId"] = vm; row["slot"] = slot; row["beforePath"] = path(attachment["beforePath"]);
            row["afterPath"] = path(attachment["afterPath"]); row["beforeReadOnly"] = flag(attachment["beforeReadOnly"]);
            row["afterReadOnly"] = flag(attachment["afterReadOnly"]); result["attachments"].append(std::move(row));
        }
        return result;
    } catch (...) { return {}; }
}
Json::Value project_image_import(const Json::Value& value) {
    try {
        if (!value.isObject()) return {};
        Json::Value result; result["diskId"] = id(value["diskId"]);
        result["registered"] = flag(value["registered"]); result["registrationUncertain"] = flag(value["registrationUncertain"]);
        result["recoveryRequired"] = flag(value["recoveryRequired"]); result["added"] = number(value["added"], 64);
        return result;
    } catch (...) { return {}; }
}
ImageImportOperations image_imports(TaskService& tasks, ImageImportBindings bindings) {
    if (!bindings.preview || !bindings.commit) throw std::invalid_argument("Missing image import binding");
    auto lookup = [&tasks](std::string kind) {
        return [&tasks, kind = std::move(kind)](const CallContext& caller, const std::string& request_id) {
            access(caller); (void)id(request_id);
            const auto task = tasks.find_request(caller, request_id);
            if (!task) return Json::Value();
            require_task(*task, caller, request_id, kind); return task_view(*task);
        };
    };
    return {{
        [&tasks, preview = bindings.preview](const CallContext& caller, const Json::Value& input) {
            access(caller); if (!input.isObject() || input.size() != 2) invalid();
            const auto source = path(input["source"]);
            TaskSpec spec{"image_import_plan", "image", 256u << 10, true, true};
            spec.request_id = id(input["requestId"]); spec.request_signature = "image_import_plan:" + source;
            const auto ref = tasks.submit(caller, std::move(spec), [preview, caller, source](TaskControl& control) {
                auto plan = preview(caller, source, [&control] { return control.cancellation_requested(); });
                if (control.cancellation_requested()) return TaskCompletion::cancelled();
                if (project_image_import_plan(plan).isNull()) throw ServiceError(ErrorCode::internal, "Invalid image import preview");
                try { (void)wire::stringify_bounded(plan, 240u << 10); }
                catch (const std::length_error&) { throw ServiceError(ErrorCode::resource_exhausted, "Image import preview too large"); }
                // Keep the native proof private in the existing task store.
                return TaskCompletion::success(std::move(plan));
            });
            return task_view(tasks.get(caller, ref));
        }, lookup("image_import_plan")
    }, {
        [&tasks, commit = bindings.commit](const CallContext& caller, const Json::Value& input) {
            access(caller); if (!input.isObject() || input.size() != 2) invalid();
            const auto plan_id = id(input["planRequestId"]);
            TaskSpec spec{"image_import", "image", 8u << 10, true, true};
            spec.request_id = id(input["requestId"]); spec.request_signature = "image_import:" + plan_id;
            const auto ref = tasks.submit(caller, std::move(spec), [&tasks, commit, caller, plan_id](TaskControl& control) {
                if (control.cancellation_requested()) return TaskCompletion::cancelled();
                const auto plan = tasks.find_request(caller, plan_id);
                if (!plan) throw ServiceError(ErrorCode::not_found, "Image import preview expired or unknown");
                require_task(*plan, caller, plan_id, "image_import_plan");
                if (plan->state != TaskState::succeeded || project_image_import_plan(plan->result).isNull())
                    throw ServiceError(ErrorCode::conflict, "Image import preview is not ready");
                auto completion = commit(caller, plan->result, control);
                auto projected = project_image_import(completion.result);
                if (completion.state == TaskState::succeeded && projected.isNull())
                    throw ServiceError(ErrorCode::internal, "Invalid image import receipt");
                completion.result = std::move(projected); return completion;
            });
            return task_view(tasks.get(caller, ref));
        }, lookup("image_import")
    }};
}
}
