// SPDX-License-Identifier: GPL-3.0-or-later
#include "vm_logs.h"
#include "common/wire.h"
#include <charconv>
#include <set>

namespace droidvm::web {
namespace {
[[noreturn]] void invalid() { throw ServiceError(ErrorCode::invalid_argument, "Invalid log request"); }
void access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || caller.principal.empty()) throw ServiceError(ErrorCode::permission_denied, "Log permission required");
}
std::string field(const Json::Value& value, size_t maximum = 128) {
    if (!value.isString()) invalid();
    auto text = value.asString();
    if (text.empty() || text.size() > maximum || text.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::string::npos) invalid();
    return text;
}
std::string instance(const Json::Value& value) {
    auto id = field(value, 32);
    if (id.size() != 32 || id.find_first_not_of("0123456789abcdef") != std::string::npos) invalid();
    return id;
}
VmLogRead parse(const Json::Value& input) {
    if (!input.isObject() || input.size() != 5 || !input["tail"].isBool() || !input.isMember("cursor")) invalid();
    VmLogRead result;
    result.vm_id = field(input["vmId"]); result.instance_id = instance(input["instanceId"]);
    result.stream = field(input["stream"], 64); result.tail = input["tail"].asBool();
    // Agent is an internal protocol stream, not a textual diagnostic log.
    if (result.stream == "agent") throw ServiceError(ErrorCode::permission_denied, "Not a log stream");
    const auto& cursor = input["cursor"];
    if (!cursor.isNull()) {
        if (!cursor.isObject() || cursor.size() != 2 || result.tail) invalid();
        vm::LogCursor value;
        value.generation = field(cursor["generation"]);
        const auto offset = field(cursor["offset"], 20);
        const auto [end, error] = std::from_chars(offset.data(), offset.data() + offset.size(), value.offset);
        if (error != std::errc() || end != offset.data() + offset.size() || std::to_string(value.offset) != offset) invalid();
        result.cursor = std::move(value);
    }
    return result;
}
}
VmLogs vm_logs(VmLogSource source) {
    if (!source.list || !source.read) throw std::invalid_argument("Missing VM log source");
    return {
        [source](const CallContext& caller, const std::string& id) {
            access(caller); field(Json::Value(id));
            const auto target = source.list(caller, id);
            if (target.vm_id != id || target.streams.size() > 64) throw ServiceError(ErrorCode::unavailable, "Invalid log source");
            Json::Value result;
            result["vmId"] = id; result["instanceId"] = instance(target.instance_id);
            auto& streams = result["streams"] = Json::Value(Json::arrayValue);
            std::set<std::string> seen;
            for (const auto& stream : target.streams) {
                field(Json::Value(stream), 64);
                if (stream != "agent" && seen.insert(stream).second) streams.append(stream);
            }
            return result;
        },
        [source](const CallContext& caller, const Json::Value& input) {
            access(caller);
            const auto request = parse(input);
            vm::LogSlice slice;
            try { slice = source.read(caller, request); }
            catch (const std::invalid_argument&) { invalid(); }
            if (slice.bytes.size() > vm::ConsoleHistory::chunk_bytes || slice.start < slice.floor || slice.next < slice.start ||
                slice.end < slice.next || slice.next - slice.start != slice.bytes.size())
                throw ServiceError(ErrorCode::unavailable, "Invalid log slice");
            Json::Value result;
            result["vmId"] = request.vm_id; result["instanceId"] = request.instance_id; result["stream"] = request.stream;
            result["generation"] = field(Json::Value(slice.generation));
            result["floor"] = std::to_string(slice.floor); result["start"] = std::to_string(slice.start);
            result["next"] = std::to_string(slice.next); result["end"] = std::to_string(slice.end);
            result["reset"] = slice.reset; result["more"] = slice.next < slice.end;
            result["data"] = wire::encode_base64(slice.bytes);
            return result;
        }
    };
}
}
