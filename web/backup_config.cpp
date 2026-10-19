// SPDX-License-Identifier: GPL-3.0-or-later
#include "backup_config.h"
#include "task_adapter.h"
#include "common/wire.h"
#include <set>

namespace droidvm::web {
namespace {
using namespace configuration_input;
bool category(const Json::Value& value) { return value == "vms" || value == "disks" || value == "networks"; }
bool stage(const Json::Value& value) { return value == "validation" || value == "networks" || value == "vm_disks"; }
ErrorCode error_code(const Json::Value& value) {
    for (auto code : {ErrorCode::invalid_argument, ErrorCode::unauthenticated, ErrorCode::permission_denied,
        ErrorCode::resource_exhausted, ErrorCode::unavailable, ErrorCode::internal, ErrorCode::io_error,
        ErrorCode::task_epoch_mismatch, ErrorCode::task_not_found, ErrorCode::not_cancellable,
        ErrorCode::resync_required, ErrorCode::snapshot_expired, ErrorCode::not_found, ErrorCode::conflict,
        ErrorCode::commit_uncertain})
        if (value == error_code_name(code)) return code;
    throw ServiceError(ErrorCode::internal, "Invalid backup error code");
}
Json::Value preview_view(const Json::Value& value) {
    Json::Value result;
    result["previewToken"] = id(value["previewToken"]);
    if (!value["categories"].isObject() || !value["revisions"].isObject()) invalid();
    for (const auto* name : {"vms", "disks", "networks"}) {
        result["revisions"][name] = id(value["revisions"][name]);
        const auto& category = value["categories"][name];
        if (!category.isObject() || !category["present"].isBool()) invalid();
        auto& row = result["categories"][name]; row["present"] = category["present"];
        const auto total = count(category["count"], backup_import_limit);
        const auto added = count(category["added"], total), replaced = count(category["replaced"], total);
        if (added + replaced != total || (!category["present"].asBool() && total)) invalid();
        row["count"] = Json::UInt64(total); row["added"] = Json::UInt64(added); row["replaced"] = Json::UInt64(replaced);
    }
    return result;
}
}
Json::Value project_configuration_backup(const Json::Value& value) {
    try {
        if (!value.isObject() || !value["completed"].isArray() || value["completed"].size() > 3 || !value["recoveryRequired"].isBool()) return {};
        Json::Value result; result["completed"] = Json::Value(Json::arrayValue);
        std::set<std::string> seen;
        for (const auto& item : value["completed"]) {
            if (!category(item) || !seen.insert(item.asString()).second) return {};
            result["completed"].append(item);
        }
        result["recoveryRequired"] = value["recoveryRequired"];
        for (const auto* name : {"failedStage", "uncertainStage"}) if (value.isMember(name)) {
            if (!stage(value[name])) return {};
            result[name] = value[name];
        }
        if (value.isMember("error")) result["errorCode"] = error_code_name(error_code(value["error"]["code"]));
        return result;
    } catch (...) { return {}; }
}
ConfigurationBackupOperations backup_configuration(TaskService& tasks, BackupConfigBindings bindings) {
    if (!bindings.begin || !bindings.append || !bindings.preview || !bindings.commit || !bindings.abort || !bindings.export_file)
        throw std::invalid_argument("Missing backup configuration binding");
    ConfigurationBackupOperations operations;
    operations.configuration.invoke = [&tasks, bindings](const CallContext& caller, const std::string& operation, const Json::Value& input) {
        access(caller);
        if (!input.isObject()) invalid();
        Json::Value result(Json::objectValue);
        if (operation == "begin") {
            if (input.size() != 1) invalid();
            const auto bytes = count(input["bytes"], backup_import_limit); if (!bytes) invalid();
            result["uploadId"] = id(bindings.begin(caller, bytes));
        } else if (operation == "append") {
            if (input.size() != 3 || !input["data"].isString()) invalid();
            std::string bytes;
            try { bytes = wire::decode_base64(input["data"].asString(), 48u << 10); } catch (const std::exception&) { invalid(); }
            if (bytes.empty()) invalid();
            const auto offset = count(input["offset"], backup_import_limit);
            if (bytes.size() > backup_import_limit - offset) invalid();
            const auto received = bindings.append(caller, id(input["uploadId"]), offset, bytes);
            if (received != offset + bytes.size()) throw ServiceError(ErrorCode::internal, "Invalid backup append receipt");
            result["received"] = Json::UInt64(received);
        } else if (operation == "preview") {
            if (input.size() != 1) invalid();
            result = preview_view(bindings.preview(caller, id(input["uploadId"])));
        } else if (operation == "abort") {
            if (input.size() != 1) invalid();
            bindings.abort(caller, id(input["uploadId"]));
        } else if (operation == "commit") {
            if (input.size() != 3) invalid();
            const auto upload = id(input["uploadId"]), token = id(input["previewToken"]);
            TaskSpec spec{"configuration_backup", "configuration", 2048, true, true};
            spec.request_id = id(input["requestId"]); spec.request_signature = "configuration_backup:" + upload + ":" + token;
            const auto ref = tasks.submit(caller, std::move(spec), [bindings, caller, upload, token](TaskControl& control) {
                if (!control.enter_commit()) {
                    try { bindings.abort(caller, upload); } catch (...) {}
                    return TaskCompletion::cancelled();
                }
                auto receipt = bindings.commit(caller, upload, token);
                auto projected = project_configuration_backup(receipt);
                if (projected.isNull()) throw ServiceError(ErrorCode::internal, "Invalid backup commit receipt");
                // Retain only the reviewed receipt, never the raw document or a
                // native exception containing paths/passwords/configuration.
                receipt = std::move(projected);
                if (receipt.isMember("errorCode")) {
                    receipt["error"]["code"] = receipt["errorCode"];
                    receipt.removeMember("errorCode");
                }
                if (receipt.isMember("error")) {
                    const auto code = error_code(receipt["error"]["code"]);
                    return TaskCompletion::failure(code, "Configuration backup import failed", std::move(receipt));
                }
                if (receipt.isMember("failedStage") || receipt.isMember("uncertainStage") || receipt["recoveryRequired"].asBool())
                    return TaskCompletion::failure(ErrorCode::commit_uncertain, "Configuration backup import requires recovery", std::move(receipt));
                return TaskCompletion::success(std::move(receipt));
            }, [bindings, caller, upload](const TaskRef&) { try { bindings.abort(caller, upload); } catch (...) {} });
            result["task"] = task_view(tasks.get(caller, ref));
        } else if (operation == "status") {
            if (input.size() != 1) invalid();
            const auto task = tasks.find_request(caller, id(input["requestId"]));
            if (task && (task->kind != "configuration_backup" || task->resource != "configuration"))
                throw ServiceError(ErrorCode::not_found, "Backup configuration request not found");
            result["task"] = task ? task_view(*task) : Json::Value();
        } else throw ServiceError(ErrorCode::not_found, "Unknown backup configuration operation");
        return result;
    };
    operations.file = [open = std::move(bindings.export_file)](const CallContext& caller) {
        access(caller); auto stream = open(caller);
        if (!stream || !stream->read || !stream->length || stream->length > backup_export_limit || !stream->chunk_bytes || stream->chunk_bytes > (256u << 10))
            throw ServiceError(ErrorCode::internal, "Invalid backup export source");
        return HttpResponse{200, {{"Content-Type", "application/json; charset=utf-8"},
            {"Content-Disposition", "attachment; filename=\"droidvm-config-backup.json\""},
            {"Cache-Control", "no-store"}, {"X-Content-Type-Options", "nosniff"}, {"Accept-Ranges", "none"}}, {}, std::move(stream)};
    };
    return operations;
}
}
