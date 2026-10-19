// SPDX-License-Identifier: GPL-3.0-or-later
#include "package_transfers.h"
#include "staged_configuration.h"
#include "common/wire.h"
#include <charconv>
#include <set>

namespace droidvm::web {
namespace {
using namespace configuration_input;
uint64_t decimal(const Json::Value& value) {
    if (!value.isString()) invalid();
    const auto text = value.asString();
    uint64_t number = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), number);
    if (text.empty() || text.size() > 20 || error != std::errc() || end != text.data() + text.size() || std::to_string(number) != text) invalid();
    return number;
}
uint64_t number(const Json::Value& value, uint64_t maximum) {
    if ((value.type() != Json::intValue && value.type() != Json::uintValue) || !value.isUInt64() || value.asUInt64() > maximum) invalid();
    return value.asUInt64();
}
std::string name(const Json::Value& value) {
    if (!value.isString()) invalid();
    auto text = value.asString();
    if (text.empty() || text.size() > 255 || text == "." || text == "..") invalid();
    for (const unsigned char c : text) if (c < 32 || c == 127 || c == '/' || c == '\\') invalid();
    return text;
}
std::string disposition(const std::string& filename) {
    std::string result = "attachment; filename=\"download.vmpkg\"; filename*=UTF-8''";
    constexpr char hex[] = "0123456789ABCDEF";
    for (const unsigned char c : filename) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') result += static_cast<char>(c);
        else { result += '%'; result += hex[c >> 4]; result += hex[c & 15]; }
    }
    return result;
}
Json::Value status(const PackageTransferBindings& bindings, const CallContext& caller, const std::string& transfer_id, const std::string& kind) {
    access(caller); (void)id(Json::Value(transfer_id));
    const auto raw = bindings.status(caller, transfer_id);
    if (raw["id"] != transfer_id || raw["kind"] != kind) throw ServiceError(ErrorCode::not_found, "Package transfer not found");
    return project_package_transfer(raw, kind);
}
}
namespace {
Json::Value project_transfer(const Json::Value& value, const std::string& kind, bool image) {
    try {
        if (!value.isObject() || value["kind"] != kind || (kind != "upload" && kind != "download")) invalid();
        if (image ? value["purpose"] != "image" : value.isMember("purpose") && value["purpose"] != "package") invalid();
        Json::Value result; result["id"] = id(value["id"]); result["kind"] = kind;
        const auto& state = value["state"];
        if (state != "receiving" && state != "ready" && state != "failed" && state != "closing") invalid();
        if (kind == "download" && state == "receiving") invalid();
        result["state"] = state;
        const auto& limits = value["limits"];
        if (!limits.isObject()) invalid();
        result["limits"]["maxFiles"] = Json::UInt64(number(limits["max_files"], 1000));
        result["limits"]["chunkBytes"] = Json::UInt64(number(limits["chunk_bytes"], 256u << 10));
        result["limits"]["ttlMs"] = Json::UInt64(number(limits["ttl_ms"], 86400000));
        if (!result["limits"]["maxFiles"].asUInt64() || !result["limits"]["chunkBytes"].asUInt64() || !result["limits"]["ttlMs"].asUInt64()) invalid();
        for (const auto& [native, browser] : {std::pair{"max_file_bytes", "maxFileBytes"}, std::pair{"max_session_bytes", "maxSessionBytes"}, std::pair{"max_total_bytes", "maxTotalBytes"}}) {
            if (!decimal(limits[native])) invalid();
            result["limits"][browser] = limits[native];
        }
        if (!value["files"].isArray() || value["files"].empty() || value["files"].size() > result["limits"]["maxFiles"].asUInt64()) invalid();
        if (image && value["files"].size() != 1) invalid();
        result["files"] = Json::Value(Json::arrayValue);
        std::set<std::string> names;
        for (Json::ArrayIndex index = 0; index < value["files"].size(); ++index) {
            const auto& file = value["files"][index];
            if (!file.isObject() || number(file["index"], 999) != index) invalid();
            Json::Value row; row["index"] = index; row["name"] = name(file["name"]);
            if (!names.insert(row["name"].asString()).second) invalid();
            const auto size = decimal(file["size_bytes"]), offset = decimal(file["offset_bytes"]);
            if (image && !size) invalid();
            if (offset > size || ((state == "ready" || kind == "download") && offset != size)) invalid();
            row["sizeBytes"] = file["size_bytes"]; row["offsetBytes"] = file["offset_bytes"];
            result["files"].append(std::move(row));
        }
        if (!image && kind == "upload" && state == "ready") {
            if (!value["master_path"].isString()) invalid();
            const auto source = value["master_path"].asString();
            if (source.empty() || source.front() != '/' || source.size() > 4096 || source.find('\0') != std::string::npos) invalid();
            result["source"] = source;
        }
        return result;
    } catch (...) { throw ServiceError(ErrorCode::internal, "Invalid package transfer status"); }
}
}
Json::Value project_package_transfer(const Json::Value& value, const std::string& kind) {
    return project_transfer(value, kind, false);
}
Json::Value project_image_upload(const Json::Value& value) {
    return project_transfer(value, "upload", true);
}
PackageTransferOperations package_transfers(TaskService& tasks, PackageTransferBindings bindings) {
    if (!bindings.begin_upload || !bindings.status || !bindings.append || !bindings.finish || !bindings.erase
        || !bindings.prepare_download || !bindings.open_download) throw std::invalid_argument("Missing package transfer binding");
    return {
        {
            [bindings](const CallContext& caller, const Json::Value& input) {
                access(caller);
                if (!input.isObject() || input.size() != 2 || !input["files"].isArray() || input["files"].empty() || input["files"].size() > 1000) invalid();
                const auto request_id = id(input["requestId"]);
                std::vector<PackageTransferFile> files; std::set<std::string> names;
                for (const auto& file : input["files"]) {
                    if (!file.isObject() || file.size() != 2) invalid();
                    auto filename = name(file["name"]);
                    if (!names.insert(filename).second) invalid();
                    files.push_back({std::move(filename), decimal(file["sizeBytes"])});
                }
                return project_package_transfer(bindings.begin_upload(caller, request_id, files), "upload");
            },
            [bindings](const CallContext& caller, const std::string& transfer_id) { return status(bindings, caller, transfer_id, "upload"); },
            [bindings](const CallContext& caller, const std::string& transfer_id) {
                (void)status(bindings, caller, transfer_id, "upload");
                return project_package_transfer(bindings.finish(caller, transfer_id), "upload");
            },
            [bindings](const CallContext& caller, const std::string& transfer_id, const Json::Value& input) {
                access(caller); (void)id(Json::Value(transfer_id));
                if (!input.isObject() || input.size() != 3 || !input["data"].isString()) invalid();
                const auto index = number(input["index"], 999), offset = decimal(input["offset"]);
                std::string bytes;
                try { bytes = wire::decode_base64(input["data"].asString(), 256u << 10); }
                catch (...) { invalid(); }
                if (bytes.empty()) invalid();
                return project_package_transfer(bindings.append(caller, transfer_id, static_cast<size_t>(index), offset, bytes), "upload");
            },
            [bindings](const CallContext& caller, const std::string& transfer_id) {
                (void)status(bindings, caller, transfer_id, "upload"); bindings.erase(caller, transfer_id);
            }
        }, {
            [&tasks, bindings](const CallContext& caller, const Json::Value& input) {
                access(caller);
                if (!input.isObject() || input.size() != 2) invalid();
                const auto request_id = id(input["requestId"]), export_id = id(input["exportRequestId"]);
                const auto task = tasks.find_request(caller, export_id);
                if (!task || task->owner != caller.principal || task->kind != "vm_export" || task->resource != "package" || task->state != TaskState::succeeded || !task->result.isObject())
                    throw ServiceError(ErrorCode::not_found, "Completed package export not found");
                return project_package_transfer(bindings.prepare_download(caller, request_id, task->result), "download");
            },
            [bindings](const CallContext& caller, const std::string& transfer_id) { return status(bindings, caller, transfer_id, "download"); },
            [bindings](const CallContext& caller, const std::string& transfer_id, uint32_t index) {
                const auto view = status(bindings, caller, transfer_id, "download");
                if (view["state"] != "ready") throw ServiceError(ErrorCode::unavailable, "Package download is closing");
                if (index >= view["files"].size()) invalid();
                const auto& file = view["files"][index];
                auto stream = bindings.open_download(caller, transfer_id, index);
                if (!stream || !stream->read || stream->length != decimal(file["sizeBytes"]))
                    throw ServiceError(ErrorCode::io_error, "Download size changed");
                stream->chunk_bytes = static_cast<size_t>(view["limits"]["chunkBytes"].asUInt64());
                return HttpResponse{200, {{"Content-Type", "application/octet-stream"}, {"Cache-Control", "no-store"},
                    {"X-Content-Type-Options", "nosniff"}, {"Accept-Ranges", "none"}, {"Content-Disposition", disposition(file["name"].asString())}}, {}, std::move(stream)};
            },
            [bindings](const CallContext& caller, const std::string& transfer_id) {
                (void)status(bindings, caller, transfer_id, "download"); bindings.erase(caller, transfer_id);
            }
        }
    };
}
}
