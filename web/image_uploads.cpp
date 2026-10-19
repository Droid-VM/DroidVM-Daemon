// SPDX-License-Identifier: GPL-3.0-or-later
#include "image_uploads.h"
#include "staged_configuration.h"
#include "task_adapter.h"
#include "common/wire.h"
#include <charconv>

namespace droidvm::web {
namespace {
using namespace configuration_input;
uint64_t decimal(const Json::Value& value) {
    if (!value.isString()) invalid();
    const auto text = value.asString(); uint64_t number = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), number);
    if (text.empty() || text.size() > 20 || error != std::errc() || end != text.data() + text.size() || std::to_string(number) != text) invalid();
    return number;
}
std::string name(const Json::Value& value) {
    if (!value.isString()) invalid();
    auto result = value.asString();
    if (result.empty() || result.size() > 255 || result == "." || result == "..") invalid();
    for (const unsigned char c : result) if (c < 32 || c == 127 || c == '/' || c == '\\') invalid();
    return result;
}
std::string path(const Json::Value& value) {
    if (!value.isString()) invalid();
    auto result = value.asString();
    if (result.empty() || result.front() != '/' || result.size() > 4096 || result.find('\0') != std::string::npos) invalid();
    return result;
}
bool flag(const Json::Value& value) { if (!value.isBool()) invalid(); return value.asBool(); }
Json::Value status(const ImageUploadBindings& bindings, const CallContext& caller, const std::string& upload_id) {
    access(caller); (void)id(upload_id);
    const auto raw = bindings.status(caller, upload_id);
    if (raw["id"] != upload_id || raw["kind"] != "upload" || raw["purpose"] != "image")
        throw ServiceError(ErrorCode::not_found, "Image upload not found");
    return project_image_upload(raw);
}
void require_task(const TaskView& task, const CallContext& caller, const std::string& request_id) {
    if (task.kind != "image_install" || task.resource != "image" || task.owner != caller.principal || task.request_id != request_id)
        throw ServiceError(ErrorCode::conflict, "Request belongs to another operation");
}
}
Json::Value project_image_install(const Json::Value& value) {
    try {
        if (!value.isObject()) return {};
        Json::Value result;
        result["uploadId"] = id(value["upload_id"]); result["source"] = path(value["path"]);
        const bool installed = flag(value["installed"]), durable = flag(value["durability_confirmed"]);
        const bool uncertain = flag(value["installation_uncertain"]), recovery = flag(value["recovery_required"]);
        if ((durable && (!installed || uncertain || recovery)) || (uncertain && !recovery)) invalid();
        result["installed"] = installed; result["durabilityConfirmed"] = durable;
        result["installationUncertain"] = uncertain; result["recoveryRequired"] = recovery;
        return result;
    } catch (...) { return {}; }
}
ImageUploadOperations image_uploads(TaskService& tasks, ImageUploadBindings bindings) {
    if (!bindings.begin_upload || !bindings.status || !bindings.append || !bindings.finish || !bindings.erase || !bindings.install)
        throw std::invalid_argument("Missing image upload binding");
    return {{
        [bindings](const CallContext& caller, const Json::Value& input) {
            access(caller);
            if (!input.isObject() || input.size() != 2 || !input["files"].isArray() || input["files"].size() != 1) invalid();
            const auto request_id = id(input["requestId"]); const auto& file = input["files"][0];
            if (!file.isObject() || file.size() != 2) invalid();
            PackageTransferFile selected{name(file["name"]), decimal(file["sizeBytes"])};
            if (!selected.size) invalid();
            const auto result = bindings.begin_upload(caller, request_id, selected);
            if (result["id"] != request_id) throw ServiceError(ErrorCode::internal, "Image upload identity changed");
            return project_image_upload(result);
        },
        [bindings](const CallContext& caller, const std::string& upload_id) { return status(bindings, caller, upload_id); },
        [bindings](const CallContext& caller, const std::string& upload_id) {
            (void)status(bindings, caller, upload_id);
            return project_image_upload(bindings.finish(caller, upload_id));
        },
        [bindings](const CallContext& caller, const std::string& upload_id, const Json::Value& input) {
            access(caller); (void)id(upload_id);
            if (!input.isObject() || input.size() != 3 || !input["data"].isString()
                || (input["index"].type() != Json::intValue && input["index"].type() != Json::uintValue)
                || !input["index"].isUInt() || input["index"].asUInt() != 0) invalid();
            const auto offset = decimal(input["offset"]); std::string bytes;
            try { bytes = wire::decode_base64(input["data"].asString(), 256u << 10); } catch (...) { invalid(); }
            if (bytes.empty()) invalid();
            (void)status(bindings, caller, upload_id);
            return project_image_upload(bindings.append(caller, upload_id, offset, bytes));
        },
        [bindings](const CallContext& caller, const std::string& upload_id) {
            (void)status(bindings, caller, upload_id); bindings.erase(caller, upload_id);
        }
    }, {
        [&tasks, bindings](const CallContext& caller, const Json::Value& input) {
            access(caller); if (!input.isObject() || input.size() != 4) invalid();
            const auto upload_id = id(input["uploadId"]), folder = path(input["folder"]), filename = name(input["name"]);
            if (folder.size() + filename.size() + 1 > 4096) invalid();
            TaskSpec spec{"image_install", "image", 8u << 10, true, true};
            spec.request_id = id(input["requestId"]);
            Json::Value signature; signature["uploadId"] = upload_id; signature["folder"] = folder; signature["name"] = filename;
            spec.request_signature = "image_install:" + wire::stringify(signature);
            const auto ref = tasks.submit(caller, std::move(spec), [bindings, caller, upload_id, folder, filename](TaskControl& control) {
                if (control.cancellation_requested()) return TaskCompletion::cancelled();
                const auto upload = status(bindings, caller, upload_id);
                if (upload["state"] != "ready") throw ServiceError(ErrorCode::conflict, "Image upload is not ready");
                auto completion = bindings.install(caller, upload_id, folder, filename, control);
                auto projected = project_image_install(completion.result);
                const auto target = (folder == "/" ? std::string() : folder) + "/" + filename;
                if (!projected.isNull() && (projected["uploadId"] != upload_id || projected["source"] != target))
                    throw ServiceError(ErrorCode::internal, "Image installation receipt identity changed");
                if (completion.state == TaskState::succeeded && (projected.isNull() || !projected["installed"].asBool()
                    || !projected["durabilityConfirmed"].asBool() || projected["installationUncertain"].asBool() || projected["recoveryRequired"].asBool()))
                    throw ServiceError(ErrorCode::internal, "Invalid image installation receipt");
                // Keep native receipt in bounded task storage; task_view projects it.
                return completion;
            });
            return task_view(tasks.get(caller, ref));
        },
        [&tasks](const CallContext& caller, const std::string& request_id) {
            access(caller); (void)id(request_id);
            const auto task = tasks.find_request(caller, request_id);
            if (!task) return Json::Value();
            require_task(*task, caller, request_id); return task_view(*task);
        }
    }};
}
}
