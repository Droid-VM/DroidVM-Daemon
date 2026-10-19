// SPDX-License-Identifier: GPL-3.0-or-later
#include "package_imports.h"
#include "staged_configuration.h"
#include "task_adapter.h"
#include <charconv>
#include <set>

namespace droidvm::web {
namespace {
using namespace configuration_input;
std::string text(const Json::Value& value, size_t limit, bool empty = false) {
    if (!value.isString()) invalid();
    auto result = value.asString();
    if ((!empty && result.empty()) || result.size() > limit || result.find('\0') != std::string::npos) invalid();
    return result;
}
std::string path(const Json::Value& value) {
    auto result = text(value, 4096);
    if (result.front() != '/') invalid();
    return result;
}
Json::UInt number(const Json::Value& value, Json::UInt maximum) {
    if ((value.type() != Json::intValue && value.type() != Json::uintValue) || !value.isUInt() || value.asUInt() > maximum) invalid();
    return value.asUInt();
}
bool flag(const Json::Value& value) {
    if (!value.isBool()) invalid();
    return value.asBool();
}
std::string bytes(const Json::Value& value) {
    auto result = text(value, 19);
    int64_t size = 0;
    const auto [end, error] = std::from_chars(result.data(), result.data() + result.size(), size);
    if (error != std::errc() || end != result.data() + result.size() || size < 0 || std::to_string(size) != result) invalid();
    return result;
}
void array(const Json::Value& value, Json::ArrayIndex limit) {
    if (!value.isArray() || value.size() > limit) invalid();
}
Json::Value native_request(const Json::Value& input) {
    if (!input.isObject() || input.size() != 3 || !input["operation"].isObject()) invalid();
    const auto& operation = input["operation"];
    if (operation.size() != 3 || !flag(operation["confirmed"])) invalid();
    Json::Value result; result["target_dir"] = path(operation["targetDirectory"]);
    array(operation["networks"], 1024);
    result["network_plan"] = Json::Value(Json::arrayValue);
    std::set<std::string> refs;
    for (const auto& choice : operation["networks"]) {
        if (!choice.isObject()) invalid();
        const auto action = text(choice["action"], 6);
        const bool join = action == "join";
        if ((!join && action != "create" && action != "skip") || choice.size() != (join ? 3u : 2u)) invalid();
        const auto ref = id(choice["ref"]);
        if (!refs.insert(ref).second) invalid();
        Json::Value row; row["ref"] = ref; row["action"] = action;
        if (join) row["network_id"] = id(choice["networkId"]);
        result["network_plan"].append(std::move(row));
    }
    return result;
}
void require_task(const TaskView& task, const CallContext& caller, const std::string& request_id, const std::string& kind) {
    if (task.kind != kind || task.resource != "package" || task.owner != caller.principal || task.request_id != request_id)
        throw ServiceError(ErrorCode::conflict, "Request belongs to another operation");
}
}
Json::Value project_package_import_plan(const Json::Value& value) {
    try {
        if (!value.isObject()) return {};
        Json::Value result;
        result["source"] = path(value["source_path"]);
        result["vmName"] = text(value["vm_name"], 1024, true);
        result["appVersion"] = text(value["app_version"], 128, true);
        if (value.isMember("backend")) result["backend"] = text(value["backend"], 128, true);
        if (value.isMember("cpu_count")) result["cpuCount"] = number(value["cpu_count"], 1024);
        if (value.isMember("memory_mib")) result["memoryMiB"] = number(value["memory_mib"], 2147483647);
        if (value.isMember("notes")) result["notes"] = text(value["notes"], 8192, true);
        result["manifestVersion"] = number(value["manifest_version"], 2);
        if (result["manifestVersion"].asUInt() == 0) invalid();
        const auto compression = text(value["compression"], 4);
        if (compression != "NONE" && compression != "GZIP" && compression != "XZ" && compression != "ZSTD") invalid();
        result["compression"] = compression;
        result["volumeCount"] = number(value["volume_count"], 999);
        result["vmRevision"] = id(value["vm_revision"]);
        result["diskRevision"] = id(value["disk_revision"]);
        result["networkRevision"] = id(value["network_revision"]);
        array(value["disks"], 1024); array(value["boots"], 16); array(value["networks"], 1024);
        result["disks"] = Json::Value(Json::arrayValue);
        for (const auto& disk : value["disks"]) {
            if (!disk.isObject()) invalid();
            Json::Value row; row["name"] = text(disk["name"], 1024, true); row["sizeBytes"] = bytes(disk["size_bytes"]);
            row["attached"] = flag(disk["attached"]); row["readonly"] = flag(disk["readonly"]);
            result["disks"].append(std::move(row));
        }
        result["boots"] = Json::Value(Json::arrayValue);
        for (const auto& boot : value["boots"]) {
            if (!boot.isObject()) invalid();
            Json::Value row; row["name"] = text(boot["name"], 1024, true); row["kind"] = text(boot["kind"], 128, true);
            row["sizeBytes"] = bytes(boot["size_bytes"]); result["boots"].append(std::move(row));
        }
        result["networks"] = Json::Value(Json::arrayValue);
        std::set<std::string> refs;
        for (const auto& network : value["networks"]) {
            if (!network.isObject()) invalid();
            Json::Value row; const auto ref = id(network["ref"]);
            if (!refs.insert(ref).second) invalid();
            row["ref"] = ref; row["name"] = text(network["name"], 1024, true);
            row["bridgeType"] = text(network["bridge_type"], 128, true);
            row["uplinkMode"] = text(network["uplink_mode"], 128, true);
            row["createAllowed"] = flag(network["create_allowed"]);
            const auto conflict = text(network["conflict_kind"], 6, true);
            if (conflict != "" && conflict != "ipv4" && conflict != "ipv6" && conflict != "uplink") invalid();
            row["conflictKind"] = conflict;
            array(network["candidates"], 1024);
            row["candidates"] = Json::Value(Json::arrayValue);
            std::set<std::string> candidates;
            for (const auto& candidate : network["candidates"]) {
                if (!candidate.isObject()) invalid();
                Json::Value projected; const auto candidate_id = id(candidate["id"]);
                if (!candidates.insert(candidate_id).second) invalid();
                projected["id"] = candidate_id; projected["name"] = text(candidate["name"], 1024, true);
                row["candidates"].append(std::move(projected));
            }
            result["networks"].append(std::move(row));
        }
        return result;
    } catch (...) { return {}; }
}
Json::Value project_package_import(const Json::Value& value) {
    try {
        if (!value.isObject()) return {};
        Json::Value result;
        for (const auto& [native, browser] : {std::pair{"registered", "registered"}, std::pair{"registration_uncertain", "registrationUncertain"},
            std::pair{"recovery_required", "recoveryRequired"}, std::pair{"cleanup_complete", "cleanupComplete"}})
            result[browser] = flag(value[native]);
        if (value.isMember("retained_directory")) result["retainedDirectory"] = path(value["retained_directory"]);
        if (value.isMember("vm_id")) result["vmId"] = id(value["vm_id"]);
        result["total"] = number(value["total"], 1040);
        result["done"] = number(value["done"], result["total"].asUInt());
        return result;
    } catch (...) { return {}; }
}
PackageImportOperations package_imports(TaskService& tasks, SubmitPackageImportPlan plan, SubmitPackageImport submit) {
    if (!plan || !submit) throw std::invalid_argument("Missing native package import binding");
    auto lookup = [&tasks](std::string kind) {
        return [&tasks, kind = std::move(kind)](const CallContext& caller, const std::string& request_id) {
            access(caller); (void)id(Json::Value(request_id));
            const auto task = tasks.find_request(caller, request_id);
            if (!task) return Json::Value();
            require_task(*task, caller, request_id, kind);
            return task_view(*task);
        };
    };
    return {
        {
            [&tasks, plan](const CallContext& caller, const Json::Value& input) {
                access(caller);
                if (!input.isObject() || input.size() != 2) invalid();
                const auto request_id = id(input["requestId"]);
                const auto ref = plan(caller, path(input["source"]), request_id);
                const auto task = tasks.get(caller, ref);
                require_task(task, caller, request_id, "package_import_plan");
                return task_view(task);
            }, lookup("package_import_plan")
        }, {
            [&tasks, submit](const CallContext& caller, const Json::Value& input) {
                access(caller);
                const auto request = native_request(input);
                const auto request_id = id(input["requestId"]), plan_request_id = id(input["planRequestId"]);
                const auto ref = submit(caller, request, plan_request_id, request_id);
                const auto task = tasks.get(caller, ref);
                require_task(task, caller, request_id, "vm_import");
                return task_view(task);
            }, lookup("vm_import")
        }
    };
}
}
