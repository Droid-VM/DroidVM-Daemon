// SPDX-License-Identifier: GPL-3.0-or-later
#include "usb_rules.h"
#include "common/wire.h"
#include "resource_catalog.h"
#include <algorithm>
#include <set>

namespace droidvm::web {
namespace {
constexpr size_t document_limit = 8u << 20, chunk_bytes = 48u << 10;
using namespace configuration_input;
Json::Value metadata(const Json::Value& snapshot) {
    Json::Value result;
    result["revision"] = id(snapshot["revision"]);
    const auto& persistence = snapshot["persistence"];
    if (persistence != "persisted" && persistence != "unpersisted" && persistence != "uncertain")
        throw ServiceError(ErrorCode::unavailable, "USB rules save in progress");
    result["persistence"] = persistence;
    return result;
}
Json::Value target_catalog(const Json::Value& rows) {
    if (!rows.isArray() || rows.size() > 4096)
        throw ServiceError(ErrorCode::resource_exhausted, "USB rule targets exceed limit");
    Json::Value result; result["items"] = Json::Value(Json::arrayValue);
    std::set<std::string> seen;
    size_t total = 1024;
    for (const auto& row : rows) {
        Json::Value item;
        const auto vm = id(row["vmId"]);
        if (!seen.insert(vm).second) throw ServiceError(ErrorCode::unavailable, "Duplicate USB rule VM");
        if (!row["vmName"].isString() || row["vmName"].asString().size() > 4096 || !row.isMember("controllerId") ||
            (!row["controllerId"].isNull() && (!row["controllerId"].isString() || row["controllerId"].asString().size() > 128)))
            throw ServiceError(ErrorCode::unavailable, "Invalid USB rule target");
        item["vmId"] = vm; item["vmName"] = row["vmName"]; item["controllerId"] = row["controllerId"];
        total += wire::stringify(item).size();
        if (total > (2u << 20)) throw ServiceError(ErrorCode::resource_exhausted, "USB rule target catalogue exceeds limit");
        result["items"].append(std::move(item));
    }
    return result;
}
Json::Value preview_catalog(const Json::Value& snapshot, const std::string& revision) {
    auto result = metadata(snapshot);
    if (result["revision"] != revision) throw ServiceError(ErrorCode::conflict, "USB rules changed");
    const auto catalogue = usb_catalog(snapshot);
    if (!catalogue["available"].asBool() || !snapshot["enabled"].isBool())
        throw ServiceError(ErrorCode::unavailable, "USB rules preview unavailable");
    result["enabled"] = snapshot["enabled"];
    result["items"] = Json::Value(Json::arrayValue);
    const bool enabled = snapshot["enabled"].asBool();
    for (Json::ArrayIndex index = 0; index < catalogue["items"].size(); ++index) {
        const auto& device = catalogue["items"][index];
        const auto& source = snapshot["devices"][index];
        if (!source["eligible"].isBool()) throw ServiceError(ErrorCode::unavailable, "Invalid USB preview eligibility");
        Json::Value row; row["device"] = device; row["eligible"] = source["eligible"]; row["match"] = Json::Value();
        if (row["eligible"].asBool() != (enabled && device["state"] != "claimed" && !device["locked"].asBool()) || device["state"] == "unknown")
            throw ServiceError(ErrorCode::unavailable, "Inconsistent USB preview eligibility");
        const auto& decision = source["result"];
        if (enabled != !decision.isNull()) throw ServiceError(ErrorCode::unavailable, "Inconsistent USB preview switch");
        if (!decision.isNull()) {
            if (!decision.isObject() || !decision["index"].isInt())
                throw ServiceError(ErrorCode::unavailable, "Invalid USB preview decision");
            const auto& layer = decision["layer"];
            const auto number = decision["index"].asInt();
            if (layer.isNull() ? number != -1 :
                ((layer != "exact" && layer != "port" && layer != "device" && layer != "any") || number < 0 || number > 8388608))
                throw ServiceError(ErrorCode::unavailable, "Invalid USB preview rule");
            const auto& target = decision["target"];
            if (target != "host" && target != "vm" && target != "sink")
                throw ServiceError(ErrorCode::unavailable, "Invalid USB preview target");
            if ((layer.isNull() && target != "host") || (!decision.isMember("vm") || !decision.isMember("controller")))
                throw ServiceError(ErrorCode::unavailable, "Invalid USB preview reference");
            Json::Value match; match["layer"] = layer; match["index"] = number; match["target"] = target;
            match["vmId"] = Json::Value(); match["controllerId"] = Json::Value();
            if (target == "vm") {
                match["vmId"] = id(decision["vm"]);
                if (!decision["controller"].isNull()) {
                    if (!decision["controller"].isString() || decision["controller"].asString().empty() || decision["controller"].asString().size() > 128)
                        throw ServiceError(ErrorCode::unavailable, "Invalid USB preview controller");
                    match["controllerId"] = decision["controller"];
                }
            } else if (!decision["vm"].isNull() || !decision["controller"].isNull())
                throw ServiceError(ErrorCode::unavailable, "Invalid USB preview target reference");
            row["match"] = std::move(match);
        }
        result["items"].append(std::move(row));
    }
    try { (void)wire::stringify_bounded(result, 2u << 20); }
    catch (const std::length_error&) { throw ServiceError(ErrorCode::resource_exhausted, "USB preview exceeds response limit"); }
    return result;
}
}
ConfigOperations usb_rules_configuration(TaskService& tasks, JsonConfigurationStaging staging,
        std::function<Json::Value(const CallContext&)> read,
        std::function<Json::Value(const CallContext&)> targets,
        std::function<Json::Value(const CallContext&, const std::string&)> preview) {
    if (!read || !targets || !staging.commit) throw std::invalid_argument("Missing USB rules bindings");
    const auto commit = std::move(staging.commit);
    staging.commit = [commit](const CallContext& caller, const std::string& upload) {
        const auto saved = commit(caller, upload);
        if (saved["persistence"] != "persisted")
            throw ServiceError(ErrorCode::commit_uncertain, "USB rules persistence was not confirmed");
        auto result = metadata(saved);
        if (!saved["applied"].isUInt()) throw ServiceError(ErrorCode::commit_uncertain, "USB rules application count unavailable");
        result["applied"] = saved["applied"];
        return result;
    };
    auto writes = staged_configuration(tasks, std::move(staging), "usb_rules", "usb-rules", document_limit);
    ConfigOperations operations{ [writes = std::move(writes), read = std::move(read), targets = std::move(targets)]
        (const CallContext& caller, const std::string& operation, const Json::Value& input) {
        access(caller);
        if (!input.isObject()) invalid();
        if (operation == "targets") {
            if (!input.empty()) invalid();
            return target_catalog(targets(caller));
        }
        if (operation != "read") return writes.invoke(caller, operation, input);
        if (input.size() != 2 || !input.isMember("revision")) invalid();
        const auto offset = count(input["offset"], document_limit);
        if (input["revision"].isNull() && offset) invalid();
        const auto snapshot = read(caller);
        if (!snapshot["available"].isBool() || !snapshot["available"].asBool())
            throw ServiceError(ErrorCode::unavailable, "USB manager unavailable");
        auto result = metadata(snapshot);
        if (!input["revision"].isNull() && id(input["revision"]) != result["revision"].asString())
            throw ServiceError(ErrorCode::conflict, "USB rules changed during read");
        if (!snapshot["rules"].isObject()) throw ServiceError(ErrorCode::unavailable, "USB rules unavailable");
        std::string encoded;
        try { encoded = wire::stringify_bounded(snapshot["rules"], document_limit); }
        catch (const std::length_error&) { throw ServiceError(ErrorCode::resource_exhausted, "USB rules exceed document limit"); }
        if (offset > encoded.size()) invalid();
        const auto length = std::min(chunk_bytes, encoded.size() - offset);
        result["offset"] = Json::UInt64(offset); result["total"] = Json::UInt64(encoded.size());
        result["next"] = offset + length < encoded.size() ? Json::Value(Json::UInt64(offset + length)) : Json::Value();
        result["data"] = wire::encode_base64(std::string_view(encoded).substr(offset, length));
        return result;
    }, {} };
    if (preview) operations.preview = [preview = std::move(preview)](const CallContext& caller, const Json::Value& input) {
        access(caller);
        if (!input.isObject() || input.size() != 1 || !input.isMember("revision")) invalid();
        const auto revision = id(input["revision"]);
        return preview_catalog(preview(caller, revision), revision);
    };
    return operations;
}
}
