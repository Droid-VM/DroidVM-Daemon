// SPDX-License-Identifier: GPL-3.0-or-later
#include "package_exports.h"
#include "staged_configuration.h"
#include "task_adapter.h"
#include <charconv>
#include <limits>
#include <set>

namespace droidvm::web {
namespace {
using namespace configuration_input;
constexpr int64_t minimum_volume_bytes = 16ll << 20;
std::string text(const Json::Value& value, size_t limit) {
    if (!value.isString()) invalid();
    auto result = value.asString();
    if (result.empty() || result.size() > limit || result.find('\0') != std::string::npos) invalid();
    return result;
}
std::string absolute_path(const Json::Value& value) {
    auto result = text(value, 4096);
    if (result.front() != '/') invalid(); // Paths refer to the Android host, not the browser's OS.
    return result;
}
Json::UInt disk_index(const Json::Value& value) {
    if ((value.type() != Json::intValue && value.type() != Json::uintValue)
        || !value.isUInt() || value.asUInt() > static_cast<Json::UInt>(std::numeric_limits<int>::max())) invalid();
    return value.asUInt();
}
Json::Value project_plan(const Json::Value& value, const std::string& vm_id) {
    if (!value.isObject() || value["vm_id"] != vm_id || !value["disks"].isArray() || value["disks"].size() > 1024) invalid();
    Json::Value result;
    result["vmId"] = vm_id; result["vmName"] = text(value["vm_name"], 1024);
    result["vmRevision"] = id(value["vm_revision"]);
    result["diskRevision"] = id(value["disk_revision"]);
    result["networkRevision"] = id(value["network_revision"]);
    result["disks"] = Json::Value(Json::arrayValue);
    std::set<Json::UInt> seen;
    for (const auto& disk : value["disks"]) {
        if (!disk.isObject() || !disk["readonly"].isBool()) invalid();
        const auto index = disk_index(disk["index"]);
        if (!seen.insert(index).second) invalid();
        Json::Value row; row["index"] = index; row["path"] = absolute_path(disk["path"]); row["readonly"] = disk["readonly"];
        result["disks"].append(std::move(row));
    }
    result["compressions"] = Json::Value(Json::arrayValue);
    for (const char* compression : {"NONE", "GZIP", "XZ", "ZSTD"}) result["compressions"].append(compression);
    result["minVolumeBytes"] = std::to_string(minimum_volume_bytes);
    return result;
}
Json::Value native_request(const Json::Value& input) {
    if (!input.isObject() || input.size() != 6 || !input["operation"].isObject()) invalid();
    const auto& operation = input["operation"];
    if (operation.size() != 5 || !operation["overwriteConfirmed"].isBool() || !operation["overwriteConfirmed"].asBool()) invalid();
    Json::Value request;
    request["vm_id"] = id(input["vmId"]);
    request["dest_path"] = absolute_path(operation["destination"]);
    const auto compression = text(operation["compression"], 4);
    if (compression != "NONE" && compression != "GZIP" && compression != "XZ" && compression != "ZSTD") invalid();
    request["compression"] = compression;
    const auto volume = text(operation["volumeBytes"], 19);
    int64_t bytes = 0;
    const auto [end, error] = std::from_chars(volume.data(), volume.data() + volume.size(), bytes);
    if (error != std::errc() || end != volume.data() + volume.size() || bytes < 0 || std::to_string(bytes) != volume
        || (bytes > 0 && bytes < minimum_volume_bytes)) invalid();
    request["volume_size"] = Json::Int64(bytes);
    const auto& disks = operation["disks"];
    if (!disks.isArray() || disks.size() > 1024) invalid();
    std::set<Json::UInt> seen;
    for (const auto& disk : disks) if (!seen.insert(disk_index(disk)).second) invalid();
    request["disks"] = disks;
    return request;
}
void require_export_task(const TaskView& task, const CallContext& caller, const std::string& request_id) {
    if (task.kind != "vm_export" || task.resource != "package" || task.owner != caller.principal || task.request_id != request_id)
        throw ServiceError(ErrorCode::conflict, "Request belongs to another operation");
}
}
Json::Value project_package_export(const Json::Value& value) {
    if (!value.isObject()) return {};
    const auto count = value.get("volume_total", 0);
    if ((count.type() != Json::intValue && count.type() != Json::uintValue) || !count.isUInt() || count.asUInt() > 999) return {};
    Json::Value result; result["volumeCount"] = count; return result;
}
PackageExportOperations package_exports(TaskService& tasks, GetPackageExportPlan plan, SubmitPackageExport submit) {
    if (!plan || !submit) throw std::invalid_argument("Missing native package export binding");
    return {
        [plan](const CallContext& caller, const std::string& vm_id) {
            access(caller); (void)id(Json::Value(vm_id));
            const auto raw = plan(caller, vm_id);
            try { return project_plan(raw, vm_id); }
            catch (...) { throw ServiceError(ErrorCode::internal, "Invalid package export plan"); }
        }, {
            [&tasks, submit](const CallContext& caller, const Json::Value& input) {
                access(caller);
                const auto request = native_request(input);
                const auto request_id = id(input["requestId"]);
                const pkg::ExportConfirmation confirmed{id(input["vmRevision"]), id(input["diskRevision"]), id(input["networkRevision"])};
                const auto ref = submit(caller, request, confirmed, request_id);
                const auto task = tasks.get(caller, ref);
                require_export_task(task, caller, request_id);
                return task_view(task);
            },
            [&tasks](const CallContext& caller, const std::string& request_id) {
                access(caller); (void)id(Json::Value(request_id));
                const auto task = tasks.find_request(caller, request_id);
                if (!task) return Json::Value();
                require_export_task(*task, caller, request_id);
                return task_view(*task);
            }
        }
    };
}
}
