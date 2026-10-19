// SPDX-License-Identifier: GPL-3.0-or-later
#include "vm_display.h"
#include "common/wire.h"
#include <algorithm>
#include <charconv>
#include <set>

namespace droidvm::web {
namespace {
[[noreturn]] void invalid() { throw ServiceError(ErrorCode::invalid_argument, "Invalid display frame"); }
void access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || caller.principal.empty()) throw ServiceError(ErrorCode::permission_denied, "Display permission required");
}
std::string field(const Json::Value& value, size_t maximum = 128) {
    if (!value.isString()) invalid();
    auto result = value.asString();
    if (result.empty() || result.size() > maximum || result.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::string::npos) invalid();
    return result;
}
vm::Observation observation(const Json::Value& value) {
    if (!value.isObject() || value.size() != 2) invalid();
    auto instance = field(value["instanceId"], 32);
    if (instance.size() != 32 || instance.find_first_not_of("0123456789abcdef") != std::string::npos || !value["revision"].isString()) invalid();
    const auto text = value["revision"].asString(); uint64_t revision = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), revision);
    if (text.empty() || text.size() > 20 || error != std::errc() || end != text.data() + text.size() || std::to_string(revision) != text) invalid();
    return {std::move(instance), revision};
}
Json::Value observed(const vm::Observation& value) {
    Json::Value result; result["instanceId"] = value.instance; result["revision"] = std::to_string(value.revision);
    (void)observation(result); return result;
}
}
VmDisplayChannel::VmDisplayChannel(VmDisplaySource source, std::string epoch, Authorize authorize, std::shared_ptr<void> quota, Now now)
    : source_(std::move(source)), epoch_(std::move(epoch)), authorize_(std::move(authorize)), quota_(std::move(quota)), now_(std::move(now)) {
    if (!source_.list || !source_.open || !authorize_ || !quota_ || !now_) throw std::invalid_argument("Missing display dependencies");
    field(epoch_); session_ = authorize_(Json::Value()); access(session_.caller); created_ = opening_ = stalled_ = now_();
}
VmDisplayChannel::~VmDisplayChannel() { close(); }
void VmDisplayChannel::close() noexcept {
    closed_ = true;
    if (stream_) {
        std::fill(stream_->password.begin(), stream_->password.end(), '\0'); stream_->password.clear();
        try { if (stream_->close) stream_->close(); } catch (...) {}
        stream_.reset();
    }
    pending_.clear(); quota_.reset();
}
void VmDisplayChannel::authorize(const Json::Value& frame) {
    const auto current = authorize_(frame); access(current.caller);
    if (current.id != session_.id || current.caller.principal != session_.caller.principal)
        throw ServiceError(ErrorCode::unauthenticated, "Display owner changed");
    if (now_() - created_ >= std::chrono::hours(1)) throw ServiceError(ErrorCode::unavailable, "Display lifetime exceeded");
}
HttpResponse VmDisplayChannel::next(const HttpRequest& input) {
    if (closed_) return {410, {}, {}};
    try { return advance(input); }
    catch (const ServiceError& error) {
        close(); const auto code = error.code();
        return {code == ErrorCode::unauthenticated ? 401 : code == ErrorCode::permission_denied ? 403 : code == ErrorCode::invalid_argument ? 400 :
            code == ErrorCode::conflict ? 409 : code == ErrorCode::resource_exhausted ? 429 : 503, {}, {}};
    } catch (...) { close(); return {500, {}, {}}; }
}
HttpResponse VmDisplayChannel::advance(const HttpRequest& input) {
    if (!opened_) {
        if (input.binary) invalid();
        const auto frame = HttpApi::parse_stream_frame(input.body);
        if (frame.size() != 6 || frame["type"] != "open" || !frame["csrfToken"].isString()) invalid();
        authorize(frame);
        const auto& context = frame["context"];
        if (!context.isObject() || context.size() != 2 || context["daemonEpoch"] != epoch_ || context["sessionId"] != session_.id)
            throw ServiceError(ErrorCode::conflict, "Display context changed");
        vm_ = field(frame["vmId"]); screen_ = field(frame["screenId"], 32); expected_ = observation(frame["expected"]);
        const auto catalog = vm_display_list(source_, session_.caller, vm_);
        if (catalog["expected"] != frame["expected"]) throw ServiceError(ErrorCode::conflict, "Display runtime changed");
        bool found = false; for (const auto& screen : catalog["screens"]) if (screen["id"] == screen_ && screen["available"].asBool()) found = true;
        if (!found) throw ServiceError(ErrorCode::unavailable, "Display screen unavailable");
        stream_ = source_.open(session_.caller, vm_, screen_, expected_);
        if (!stream_->connected || !stream_->read || !stream_->write || !stream_->close || stream_->password.size() > 255)
            throw ServiceError(ErrorCode::unavailable, "Invalid display connection");
        opened_ = true; opening_ = now_();
    } else {
        authorize(Json::Value());
        if (!input.body.empty()) {
            if (!ready_ || !input.binary || input.body.size() > (64u << 10) || input.body.size() > (256u << 10) - pending_.size()) invalid();
            if (pending_.empty()) stalled_ = now_();
            pending_ += input.body;
        }
    }
    const bool connected = stream_->connected();
    if (!connected) {
        if (now_() - opening_ >= std::chrono::seconds(5)) throw ServiceError(ErrorCode::unavailable, "Display connection deadline exceeded");
        return {204, {}, {}};
    }
    if (input.method == "CHECK") return {204, {}, {}};
    if (!ready_) {
        ready_ = true; Json::Value value;
        value["type"] = "ready"; value["context"]["daemonEpoch"] = epoch_; value["context"]["sessionId"] = session_.id;
        value["vmId"] = vm_; value["screenId"] = screen_; value["expected"] = observed(expected_);
        value["password"] = stream_->password;
        std::fill(stream_->password.begin(), stream_->password.end(), '\0'); stream_->password.clear();
        return {200, {}, wire::stringify_bounded(value, 4096)};
    }
    if (!pending_.empty()) {
        const auto count = std::min(pending_.size(), size_t(64u << 10));
        const auto accepted = stream_->write(std::string_view(pending_).substr(0, count));
        if (accepted > count) throw ServiceError(ErrorCode::unavailable, "Invalid display write count");
        if (accepted) { pending_.erase(0, accepted); stalled_ = now_(); }
        else if (now_() - stalled_ >= std::chrono::seconds(10)) throw ServiceError(ErrorCode::unavailable, "Display input stalled");
    }
    auto bytes = stream_->read(64u << 10);
    if (bytes.size() > (64u << 10)) throw ServiceError(ErrorCode::resource_exhausted, "Display output exceeded its bound");
    if (bytes.empty()) return {204, {}, {}};
    return {200, {}, std::move(bytes), {}, true};
}
}
