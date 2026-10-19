// SPDX-License-Identifier: GPL-3.0-or-later
#include "disk_operations.h"
#include "task_adapter.h"
#include "common/wire.h"
#include <charconv>
#include <set>

namespace droidvm::web {
namespace {
[[noreturn]] void invalid() { throw ServiceError(ErrorCode::invalid_argument, "Invalid disk operation"); }
void access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || !caller.manage_tasks || caller.principal.empty())
        throw ServiceError(ErrorCode::permission_denied, "Disk operation permission required");
}
std::string text(const Json::Value& value, size_t limit) {
    if (!value.isString()) invalid();
    auto result = value.asString();
    if (result.empty() || result.size() > limit || result.find('\0') != std::string::npos) invalid();
    return result;
}
std::string id(const Json::Value& value) {
    auto result = text(value, 128);
    if (result.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::string::npos) invalid();
    return result;
}
Json::Value native_request(const Json::Value& input) {
    if (!input.isObject() || input.size() != 4 || !input["operation"].isObject()) invalid();
    (void)id(input["requestId"]);
    Json::Value request;
    request["disk_revision"] = text(input["revision"], 128);
    request["vm_revision"] = text(input["vmRevision"], 128);
    const auto& op = input["operation"];
    const auto action = text(op["action"], 16);
    std::set<std::string> keys{"action", "cpus"};
    if (action == "create") keys.insert({"folder", "name", "format", "size", "backingId", "attach", "compress", "preallocate"});
    else {
        keys.insert("diskId");
        if (action == "clone") keys.insert({"folder", "name", "compress", "preallocate", "createFolder"});
        else if (action == "resize") keys.insert({"size", "shrink"});
        else if (action == "convert") keys.insert({"format", "folder", "name", "compress", "preallocate"});
        else if (action == "flatten") keys.insert({"format", "compress", "preallocate"});
        else if (action == "delete") keys.insert("deleteFiles");
        else if (action != "commit" && action != "reset") invalid();
        request["disk_id"] = id(op["diskId"]);
    }
    for (const auto& key : op.getMemberNames()) if (!keys.contains(key)) invalid();
    request["action"] = action;
    if (op.isMember("backingId")) request["backing_id"] = id(op["backingId"]);
    if (op.isMember("size")) {
        const auto size = text(op["size"], 19);
        int64_t bytes = 0;
        const auto [end, error] = std::from_chars(size.data(), size.data() + size.size(), bytes);
        if (error != std::errc() || end != size.data() + size.size() || bytes <= 0 || std::to_string(bytes) != size) invalid();
        request["size"] = Json::Int64(bytes);
    }
    if ((action == "resize" || (action == "create" && !op.isMember("backingId"))) && !op.isMember("size")) invalid();
    if (action == "create" || action == "clone" || op.isMember("folder") || op.isMember("name")) {
        const auto folder = text(op["folder"], 4096), name = text(op["name"], 255);
        if (folder.front() != '/' || (folder.size() > 1 && folder.back() == '/') || name == "." || name == ".." || name.find('/') != std::string::npos || name.starts_with(".dvm-")) invalid();
        request["folder"] = folder; request["name"] = name;
    }
    if (op.isMember("format")) {
        const auto format = text(op["format"], 16);
        if (format != "qcow2" && format != "raw" &&
            !(action == "create" && (format == "vhdx" || format == "vdi" || format == "vmdk"))) invalid();
        if (op.isMember("backingId") && format != "qcow2") invalid();
        request["format"] = format;
    } else if (action == "create" || action == "convert") invalid();
    if (op.isMember("attach")) {
        const auto attach = text(op["attach"], 16);
        if (!op.isMember("backingId") || (attach != "follow" && attach != "readonly")) invalid();
        request["attach"] = attach;
    }
    if (op.isMember("compress")) {
        const auto compression = text(op["compress"], 16);
        if (compression != "none" && compression != "deflate" && compression != "zstd") invalid();
        request["compress"] = compression;
    }
    for (const auto& [key, native] : {std::pair{"shrink", "shrink"}, std::pair{"deleteFiles", "delete_files"}, std::pair{"preallocate", "preallocate"}, std::pair{"createFolder", "create_folder"}}) {
        if (!op.isMember(key)) continue;
        if (!op[key].isBool()) invalid();
        request[native] = op[key];
    }
    if (op.isMember("cpus")) {
        const auto& cpus = op["cpus"];
        if (!cpus.isArray() || cpus.empty() || cpus.size() > 1024) invalid();
        std::set<int> seen;
        for (const auto& cpu : cpus)
            if (!cpu.isInt() || cpu.asInt() < 0 || cpu.asInt() >= 1024 || !seen.insert(cpu.asInt()).second) invalid();
        request["cpus"] = cpus;
    }
    return request;
}
}
BackgroundOperations disk_operations(TaskService& tasks, ExecuteDiskOperation execute) {
    if (!execute) throw std::invalid_argument("Missing native disk operation binding");
    return {
        [&tasks, execute](const CallContext& caller, const Json::Value& input) {
            access(caller);
            const auto request = native_request(input);
            const auto& op = input["operation"];
            const auto resource = op.isMember("diskId") ? id(op["diskId"]) : op.isMember("backingId") ? id(op["backingId"]) : "new";
            TaskSpec spec{"disk_operation", "disk:" + resource, 32u << 10, true, true};
            auto signature = input; signature.removeMember("requestId");
            spec.request_id = id(input["requestId"]);
            try { spec.request_signature = wire::stringify_bounded(signature, TaskSpec::max_signature_bytes); }
            catch (const std::length_error&) { throw ServiceError(ErrorCode::resource_exhausted, "Disk operation signature too large"); }
            const auto ref = tasks.submit(caller, std::move(spec), [execute, caller, request](TaskControl& control) {
                return execute(caller, request, control);
            });
            return task_view(tasks.get(caller, ref));
        },
        [&tasks](const CallContext& caller, const std::string& request_id) {
            access(caller); (void)id(Json::Value(request_id));
            const auto task = tasks.find_request(caller, request_id);
            if (task && task->kind != "disk_operation") throw ServiceError(ErrorCode::conflict, "Request belongs to another operation");
            return task ? task_view(*task) : Json::Value();
        }
    };
}
DiskRecoveryOperations disk_recovery(TaskService& tasks,
    std::function<size_t(const CallContext&)> pending,
    std::function<Json::Value(const CallContext&)> recover) {
    if (!pending || !recover) throw std::invalid_argument("Missing native disk recovery binding");
    return {
        [pending](const CallContext& caller) {
            access(caller);
            const auto count = pending(caller);
            if (count > 64) throw ServiceError(ErrorCode::internal, "Invalid recovery count");
            Json::Value result; result["pendingRecords"] = Json::UInt64(count); return result;
        }, {
            [&tasks, recover](const CallContext& caller, const Json::Value& input) {
                access(caller);
                if (!input.isObject() || input.size() != 1) invalid();
                TaskSpec spec{"disk_recovery", "disks", 1024, true, true};
                spec.request_id = id(input["requestId"]);
                spec.request_signature = "disk-recovery-v1";
                const auto ref = tasks.submit(caller, std::move(spec), [recover, caller](TaskControl& control) {
                    if (!control.enter_commit()) return TaskCompletion::cancelled();
                    auto result = recover(caller);
                    if (!result["pending"].isUInt64() || result["pending"].asUInt64() > 64)
                        throw ServiceError(ErrorCode::internal, "Invalid recovery result");
                    Json::Value view; view["pendingRecords"] = result["pending"];
                    return TaskCompletion::success(view);
                });
                return task_view(tasks.get(caller, ref));
            },
            [&tasks](const CallContext& caller, const std::string& request_id) {
                access(caller); (void)id(Json::Value(request_id));
                const auto task = tasks.find_request(caller, request_id);
                if (task && task->kind != "disk_recovery") throw ServiceError(ErrorCode::conflict, "Request belongs to another operation");
                return task ? task_view(*task) : Json::Value();
            }
        }
    };
}
}
