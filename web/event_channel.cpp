// SPDX-License-Identifier: GPL-3.0-or-later
#include "event_channel.h"
#include "common/wire.h"
#include <set>

namespace droidvm::web {
EventChannel::EventChannel(TaskService& tasks, Authorize authorize)
    : tasks_(tasks), authorize_(std::move(authorize)), session_(authorize_(Json::Value())) {}
EventChannel::~EventChannel() { release(); }
void EventChannel::release() noexcept {
    if (subscription_.empty()) return;
    try { tasks_.unsubscribe(session_.caller, subscription_); } catch (...) {}
    subscription_.clear();
}
HttpResponse EventChannel::message(const char* type, const Json::Value& resources) {
    Json::Value result;
    result["type"] = type;
    result["context"]["daemonEpoch"] = tasks_.epoch();
    result["context"]["sessionId"] = session_.id;
    result["cursor"]["epoch"] = cursor_.epoch;
    result["cursor"]["sequence"] = std::to_string(cursor_.sequence);
    result["resources"] = resources;
    sent_ = std::chrono::steady_clock::now();
    return {200, {}, wire::stringify_bounded(result, 4096)};
}
HttpResponse EventChannel::next(const HttpRequest& input) {
    try { return advance(input); }
    catch (const ServiceError& error) {
        release();
        const int status = error.code() == ErrorCode::unauthenticated || error.code() == ErrorCode::permission_denied ? 401 : 400;
        return {status, {}, {}};
    }
}
HttpResponse EventChannel::advance(const HttpRequest& input) {
    if (!initialized_) {
        const auto frame = HttpApi::parse_stream_frame(input.body);
        session_ = authorize_(frame);
        const auto& supplied = frame["cursor"];
        if (supplied.isNull()) cursor_ = tasks_.event_cursor(session_.caller);
        else {
            if (!supplied.isObject() || supplied.size() != 2 || !supplied["epoch"].isString() ||
                supplied["epoch"].asString().empty() || supplied["epoch"].asString().size() > 128 ||
                !supplied["sequence"].isString()) throw ServiceError(ErrorCode::invalid_argument, "Invalid event cursor");
            cursor_ = EventCursor::parse(supplied["epoch"].asString(), supplied["sequence"].asString());
        }
        initialized_ = true;
        try { subscription_ = tasks_.subscribe(session_.caller, cursor_); }
        catch (const ServiceError& error) {
            if (error.code() != ErrorCode::resync_required) throw;
            cursor_ = tasks_.event_cursor(session_.caller);
            subscription_ = tasks_.subscribe(session_.caller, cursor_);
            return message("resync");
        }
        // Clients fetch their baseline only AFTER ready. A non-atomic VM/task
        // read is safe because subsequent invalidations trigger another read.
        return message("ready");
    }
    if (!input.body.empty()) throw ServiceError(ErrorCode::invalid_argument, "Already subscribed");
    if (authorize_(Json::Value()).id != session_.id) throw ServiceError(ErrorCode::unauthenticated, "Session changed");
    EventBatch batch;
    try { batch = tasks_.poll(session_.caller, subscription_, 64, 64u << 10); }
    catch (const ServiceError& error) {
        if (error.code() != ErrorCode::resync_required) throw;
        release();
        cursor_ = tasks_.event_cursor(session_.caller);
        subscription_ = tasks_.subscribe(session_.caller, cursor_);
        return message("resync");
    }
    std::set<std::string> invalidated;
    for (const auto& item : batch.events) {
        const auto event = wire::parse(item.encoded);
        const auto kind = event["kind"].asString();
        if (kind == "task.changed" || kind == "task.removed") invalidated.insert("tasks");
        else if (kind == "vm.config.invalidated" || kind == "vm.runtime.invalidated") invalidated.insert("vms");
        else if (kind == "disk.config.invalidated") invalidated.insert("disks");
        else if (kind == "network.config.invalidated") invalidated.insert("networks");
    }
    const bool advanced = cursor_.sequence != batch.covered.sequence;
    cursor_ = batch.covered; // Includes covered events hidden by journal scope.
    Json::Value resources(Json::arrayValue);
    for (const auto& resource : invalidated) resources.append(resource);
    if (advanced || !resources.empty()) return message("invalidate", resources);
    if (std::chrono::steady_clock::now() - sent_ >= std::chrono::seconds(15)) return message("heartbeat");
    return {204, {}, {}};
}
}
