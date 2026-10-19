// SPDX-License-Identifier: GPL-3.0-or-later
#include "task_adapter.h"
#include "agent_rescue.h"
#include "agent_operations.h"
#include "package_exports.h"
#include "package_imports.h"
#include "backup_config.h"
#include "service_control.h"
#include "image_imports.h"
#include "image_uploads.h"
#include "hugepages.h"
#include "hugepage_processes.h"
#include "host_preferences.h"
#include "usb_acm.h"
#include "common/wire.h"

namespace droidvm::web {
namespace {
Json::Value project(const Json::Value& row) {
    Json::Value result;
    result["id"] = row["task_id"];
    result["revision"] = row["revision"];
    result["kind"] = row["kind"];
    result["resource"] = row["resource"];
    if (row["request_id"].isString()) result["requestId"] = row["request_id"];
    result["state"] = row["state"];
    result["cancellable"] = row["cancellable"];
    result["phase"] = row["phase"];
    result["unit"] = row["unit"];
    result["completed"] = row["completed"];
    result["total"] = row["total"];
    result["createdMs"] = row["created_monotonic_ms"];
    result["finishedMs"] = row["finished_monotonic_ms"];
    result["resultAvailable"] = row["result_available"];
    result["errorCode"] = row["error"].isObject() ? row["error"]["code"] : Json::Value();
    // Results and raw exception messages need operation-specific projections.
    // They can contain host paths, configuration, passwords or package content.
    return result;
}
Json::Value snapshot(TaskService& tasks, const CallContext& caller) {
    auto page = tasks.snapshot(caller);
    struct Release {
        TaskService& tasks; const CallContext& caller; std::string id;
        ~Release() { try { tasks.release_snapshot(caller, id); } catch (...) {} }
    } release{tasks, caller, page.id};
    Json::Value result;
    result["cursor"]["epoch"] = page.cursor.epoch;
    result["cursor"]["sequence"] = std::to_string(page.cursor.sequence);
    auto& rows = result["items"] = Json::Value(Json::arrayValue);
    size_t bytes = 0;
    // Consume one immutable, scoped snapshot; never combine live pages. Bound
    // construction before serializing the HTTP response, and release on error.
    if (page.total > 1024) throw ServiceError(ErrorCode::resource_exhausted, "Task view capacity exceeded");
    for (;;) {
        for (const auto& row : page.items) {
            bytes += row.size();
            if (bytes > (1u << 20)) throw ServiceError(ErrorCode::resource_exhausted, "Task view capacity exceeded");
            rows.append(project(wire::parse(row)));
        }
        if (!page.next) break;
        page = tasks.snapshot_page(caller, page.id, *page.next);
    }
    return result;
}
}
Json::Value task_view(const TaskView& task) {
    auto result = project(task_summary(task));
    if (task.kind == "disk_defaults" && task_terminal(task.state)) {
        auto projected = project_host_preference_result(task.result, task.state == TaskState::cancelled, HostPreferenceDomain::disk_operations);
        if (!projected.isNull()) result["diskDefaultResult"] = std::move(projected);
    }
    if (task.kind == "usb_acm" && task_terminal(task.state)) {
        auto projected = project_usb_acm_result(task.result, task.state == TaskState::cancelled);
        if (!projected.isNull()) result["usbAcmResult"] = std::move(projected);
    }
    if (task.kind == "host_preferences" && task_terminal(task.state)) {
        auto projected = project_host_preference_result(task.result, task.state == TaskState::cancelled);
        if (!projected.isNull()) result["hostPreferenceResult"] = std::move(projected);
    }
    if (task.kind == "hugepage_process_signal" && task_terminal(task.state)) {
        auto projected = project_hugepage_process_result(task.result, task.state == TaskState::cancelled);
        if (!projected.isNull()) result["hugepageProcessResult"] = std::move(projected);
    }
    if (task.kind == "hugepage_operation" && task_terminal(task.state)) {
        auto projected = project_hugepage_result(task.result);
        if (!projected.isNull()) result["hugepageResult"] = std::move(projected);
    }
    if (task.kind == "image_install" && task_terminal(task.state)) {
        auto projected = project_image_install(task.result);
        if (!projected.isNull()) result["imageInstall"] = std::move(projected);
    }
    if (task.kind == "image_import_plan" && task.state == TaskState::succeeded) {
        auto projected = project_image_import_plan(task.result);
        if (!projected.isNull()) result["imageImportPlan"] = std::move(projected);
    }
    if (task.kind == "image_import" && task_terminal(task.state)) {
        auto projected = project_image_import(task.result);
        if (!projected.isNull()) result["imageImport"] = std::move(projected);
    }
    if (task.kind == "web_service" && task.state == TaskState::succeeded) {
        auto projected = project_web_service_result(task.result);
        if (!projected.isNull()) result["webService"] = std::move(projected);
    }
    if (task.kind == "configuration_backup" && task_terminal(task.state)) {
        auto projected = project_configuration_backup(task.result);
        if (!projected.isNull()) result["configurationBackup"] = std::move(projected);
    }
    if (task.kind == "disk_operation" && task.state == TaskState::succeeded && task.result.isObject()) {
        const auto& id = task.result["disk_id"];
        if (id.isString() && !id.asString().empty() && id.asString().size() <= 128 &&
            id.asString().find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") == std::string::npos)
            result["diskId"] = id;
    }
    if ((task.kind == "disk_recovery" || task.kind == "agent_recovery") && task.state == TaskState::succeeded && task.result.isObject() &&
        task.result["pendingRecords"].isUInt64() && task.result["pendingRecords"].asUInt64() <= 64)
        result["pendingRecords"] = task.result["pendingRecords"];
    if (task.kind == "agent_operation" && task_terminal(task.state)) {
        auto projected = project_agent_result(task.result);
        if (!projected.isNull()) result["agentResult"] = std::move(projected);
    }
    if (task.kind == "agent_rescue_close" && task_terminal(task.state)) {
        auto projected = project_agent_rescue_cleanup(task.result);
        if (!projected.isNull()) result["agentRescueCleanup"] = std::move(projected);
    }
    if (task.kind == "vm_export" && task.state == TaskState::succeeded) {
        auto projected = project_package_export(task.result);
        if (!projected.isNull()) result["packageExport"] = std::move(projected);
    }
    if (task.kind == "package_import_plan" && task.state == TaskState::succeeded) {
        auto projected = project_package_import_plan(task.result);
        if (!projected.isNull()) result["packageImportPlan"] = std::move(projected);
    }
    if (task.kind == "vm_import" && task_terminal(task.state)) {
        auto projected = project_package_import(task.result);
        if (!projected.isNull()) result["packageImport"] = std::move(projected);
    }
    return result;
}
TaskOperations task_operations(TaskService& tasks) {
    return {
        [&tasks](const CallContext& caller) { return snapshot(tasks, caller); },
        [&tasks](const CallContext& caller, const std::string& id) {
            return project(task_summary(tasks.cancel(caller, {tasks.epoch(), id})));
        },
        tasks.receipt_host_id().empty() ? std::function<Json::Value(const CallContext&, const std::string&)>{} :
            [&tasks](const CallContext& caller, const std::string& id) { return tasks.receipt(caller, id); },
        tasks.receipt_host_id()
    };
}
}
