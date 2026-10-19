// SPDX-License-Identifier: GPL-3.0-or-later
#include "vm_terminal.h"
#include "common/wire.h"
#include "vm/console_busy.h"
#include <algorithm>
#include <charconv>
#include <limits>
#include <set>

namespace droidvm::web {
namespace {
[[noreturn]] void invalid() { throw ServiceError(ErrorCode::invalid_argument, "Invalid terminal request"); }
[[noreturn]] void unavailable() { throw ServiceError(ErrorCode::unavailable, "Terminal unavailable"); }
void access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || caller.principal.empty())
        throw ServiceError(ErrorCode::permission_denied, "Terminal permission required");
}
std::string field(const Json::Value& value, size_t maximum = 128) {
    if (!value.isString()) invalid();
    auto result = value.asString();
    if (result.empty() || result.size() > maximum ||
        result.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::string::npos) invalid();
    return result;
}
std::string instance(const Json::Value& value) {
    auto result = field(value, 32);
    if (result.size() != 32 || result.find_first_not_of("0123456789abcdef") != std::string::npos) invalid();
    return result;
}
uint64_t number(const Json::Value& value) {
    if (!value.isString()) invalid();
    const auto input = value.asString();
    if (input.empty() || input.size() > 20) invalid();
    uint64_t result = 0;
    const auto [end, error] = std::from_chars(input.data(), input.data() + input.size(), result);
    if (error != std::errc() || end != input.data() + input.size() || std::to_string(result) != input) invalid();
    return result;
}
vm::Observation observation(const Json::Value& value) {
    if (!value.isObject() || value.size() != 2) invalid();
    return {instance(value["instanceId"]), number(value["revision"])};
}
Json::Value observed(const vm::Observation& value) {
    Json::Value result;
    result["instanceId"] = instance(Json::Value(value.instance));
    result["revision"] = std::to_string(value.revision);
    return result;
}
vm::LogCursor cursor(const Json::Value& value) {
    if (!value.isObject() || value.size() != 2) invalid();
    return {field(value["generation"]), number(value["offset"])};
}
void check_source(const VmTerminalSource& source) {
    if (!source.list || !source.read || !source.write) throw std::invalid_argument("Missing terminal source");
}
}
Json::Value vm_terminal_list(const VmTerminalSource& source, const CallContext& caller, const std::string& id) {
    check_source(source); access(caller); field(Json::Value(id));
    const auto target = source.list(caller, id);
    if (target.vm_id != id || target.streams.size() > 64) unavailable();
    Json::Value result;
    result["vmId"] = id; result["expected"] = observed(target.observed);
    result["resizeSupported"] = false;
    auto& streams = result["streams"] = Json::Value(Json::arrayValue);
    std::set<std::string> seen;
    for (const auto& stream : target.streams) {
        field(Json::Value(stream), 64);
        if (stream != "agent" && seen.insert(stream).second) streams.append(stream);
    }
    return result;
}
VmTerminalChannel::VmTerminalChannel(VmTerminalSource source, std::string daemon_epoch, Authorize authorize, Now now)
    : source_(std::move(source)), daemon_epoch_(std::move(daemon_epoch)), authorize_(std::move(authorize)), now_(std::move(now)) {
    check_source(source_);
    if (!authorize_ || !now_) throw std::invalid_argument("Missing terminal channel dependencies");
    field(Json::Value(daemon_epoch_));
    session_ = authorize_(Json::Value()); access(session_.caller);
    field(Json::Value(session_.id));
}
void VmTerminalChannel::authorize(const Json::Value& frame) {
    auto current = authorize_(frame); access(current.caller);
    if (current.id != session_.id || current.caller.principal != session_.caller.principal)
        throw ServiceError(ErrorCode::unauthenticated, "Terminal session changed");
    session_ = std::move(current);
}
HttpResponse VmTerminalChannel::message(Json::Value value) {
    value["context"]["daemonEpoch"] = daemon_epoch_;
    value["context"]["sessionId"] = session_.id;
    sent_ = now_();
    return {200, {}, wire::stringify_bounded(value, 96u << 10)};
}
HttpResponse VmTerminalChannel::next(const HttpRequest& input) {
    if (closed_) return {410, {}, {}};
    try { return advance(input); }
    catch (const ServiceError& error) {
        closed_ = true;
        const auto code = error.code();
        const int status = code == ErrorCode::unauthenticated ? 401 : code == ErrorCode::permission_denied ? 403 :
            code == ErrorCode::conflict ? 409 : code == ErrorCode::not_found ? 404 :
            code == ErrorCode::unavailable ? 503 : code == ErrorCode::resource_exhausted ? 429 : 400;
        return {status, {}, {}};
    } catch (...) { closed_ = true; return {500, {}, {}}; }
}
HttpResponse VmTerminalChannel::advance(const HttpRequest& input) {
    if (!initialized_) {
        const auto frame = HttpApi::parse_stream_frame(input.body);
        if (frame.size() != 7 || frame["type"] != "open" || !frame["csrfToken"].isString() || !frame.isMember("cursor")) invalid();
        authorize(frame);
        const auto& context = frame["context"];
        if (!context.isObject() || context.size() != 2 || context["daemonEpoch"] != daemon_epoch_ || context["sessionId"] != session_.id)
            throw ServiceError(ErrorCode::conflict, "Terminal context changed");
        read_.vm_id = field(frame["vmId"]); read_.stream = field(frame["stream"], 64);
        read_.observed = observation(frame["expected"]);
        if (read_.stream == "agent") throw ServiceError(ErrorCode::permission_denied, "Not a terminal stream");
        if (!frame["cursor"].isNull()) { read_.cursor = cursor(frame["cursor"]); read_.tail = false; }
        const auto target = vm_terminal_list(source_, session_.caller, read_.vm_id);
        if (target["expected"] != frame["expected"]) throw ServiceError(ErrorCode::conflict, "Terminal runtime changed");
        bool present = false;
        for (const auto& stream : target["streams"]) if (stream == read_.stream) present = true;
        if (!present) throw ServiceError(ErrorCode::not_found, "Terminal stream unavailable");
        initialized_ = true;
        Json::Value ready; ready["type"] = "ready"; ready["vmId"] = read_.vm_id;
        ready["expected"] = observed(read_.observed); ready["stream"] = read_.stream; ready["resizeSupported"] = false;
        return message(std::move(ready));
    }
    authorize(Json::Value()); // Periodic/input checks must not extend idle expiry.
    if (!input.body.empty()) {
        const auto frame = HttpApi::parse_stream_frame(input.body);
        if (frame["type"] == "ackOutput") {
            if (frame.size() != 3 || !awaiting_output_) invalid();
            const auto generation = field(frame["generation"]);
            const auto offset = number(frame["offset"]);
            if (generation != awaiting_output_->generation || offset != awaiting_output_->offset) invalid();
            read_.cursor = std::move(awaiting_output_); awaiting_output_.reset(); read_.tail = false;
            return {204, {}, {}};
        }
        if (frame.size() != 3 || frame["type"] != "input" || !frame["data"].isString()) invalid();
        const auto sequence = number(frame["sequence"]);
        if (input_sequence_ == std::numeric_limits<uint64_t>::max() || sequence != input_sequence_ + 1) invalid();
        const auto encoded = frame["data"].asString();
        std::string bytes;
        try { bytes = wire::decode_base64(encoded, 512); }
        catch (const std::exception&) { invalid(); }
        if (bytes.empty() || wire::encode_base64(bytes) != encoded) invalid();
        input_sequence_ = sequence;
        const auto accepted = source_.write(session_.caller, {read_.vm_id, read_.stream, read_.observed, bytes});
        if (accepted > bytes.size()) unavailable();
        Json::Value ack; ack["type"] = "ack"; ack["sequence"] = std::to_string(sequence); ack["accepted"] = Json::UInt64(accepted);
        return message(std::move(ack));
    }
    if (awaiting_output_) {
        // Rendering may be paused indefinitely. Keep validating the runtime
        // while retaining only the cursor, without reading another output chunk.
        Json::Value target;
        try { target = vm_terminal_list(source_, session_.caller, read_.vm_id); }
        catch (const vm::ConsoleBusy&) { return {204, {}, {}}; }
        bool present = false;
        for (const auto& stream : target["streams"]) if (stream == read_.stream) present = true;
        if (target["expected"] != observed(read_.observed) || !present)
            throw ServiceError(ErrorCode::conflict, "Terminal runtime changed");
    } else {
        vm::LogSlice slice;
        try { slice = source_.read(session_.caller, read_); }
        catch (const vm::ConsoleBusy&) { return {204, {}, {}}; }
        catch (const std::invalid_argument&) { invalid(); }
        field(Json::Value(slice.generation));
        if (slice.bytes.size() > vm::ConsoleHistory::chunk_bytes || slice.start < slice.floor || slice.next < slice.start ||
            slice.end < slice.next || slice.next - slice.start != slice.bytes.size()) unavailable();
        if (read_.cursor && !slice.reset && (slice.generation != read_.cursor->generation || slice.start != read_.cursor->offset)) unavailable();
        if (!emitted_output_ || !slice.bytes.empty() || slice.reset) {
            Json::Value output; output["type"] = "output"; output["generation"] = slice.generation;
            output["floor"] = std::to_string(slice.floor); output["start"] = std::to_string(slice.start);
            output["next"] = std::to_string(slice.next); output["end"] = std::to_string(slice.end);
            output["reset"] = slice.reset; output["more"] = slice.next < slice.end;
            output["data"] = wire::encode_base64(slice.bytes);
            awaiting_output_ = vm::LogCursor{slice.generation, slice.next}; emitted_output_ = true;
            return message(std::move(output));
        }
    }
    if (now_() - sent_ >= std::chrono::seconds(15)) {
        Json::Value heartbeat; heartbeat["type"] = "heartbeat"; return message(std::move(heartbeat));
    }
    return {204, {}, {}};
}
}
