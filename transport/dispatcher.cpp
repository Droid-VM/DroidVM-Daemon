// SPDX-License-Identifier: GPL-3.0-or-later
#include "dispatcher.h"
#include "common/wire.h"
#include <algorithm>
#include <array>
#include <limits>

namespace droidvm {
namespace {
constexpr std::array commands{"task_get", "task_cancel", "task_snapshot", "task_snapshot_page",
                              "task_snapshot_release", "task_subscribe", "task_unsubscribe"};
CallContext context(const ClientSession& session) {
    // The existing IPC token grants local administrator rights. Never accept
    // principal/permissions from fields in the request, or use client_id as owner.
    return {"local-admin", session.caller.authorized, true, true};
}
std::string string_field(const Json::Value& request, const char* key) {
    if (!request[key].isString() || request[key].asString().size() > 128)
        throw ServiceError(ErrorCode::invalid_argument, std::string("Invalid ") + key);
    return request[key].asString();
}
size_t size_field(const Json::Value& request, const char* key, size_t fallback) {
    if (!request.isMember(key)) return fallback;
    if (!request[key].isUInt64() || request[key].asUInt64() > std::numeric_limits<size_t>::max())
        throw ServiceError(ErrorCode::invalid_argument, std::string("Invalid ") + key);
    return static_cast<size_t>(request[key].asUInt64());
}
Json::Value failure(const ServiceError& error) {
    Json::Value result;
    result["success"] = false;
    result["message"] = error.what();
    result["error"]["code"] = error_code_name(error.code());
    result["error"]["message"] = error.what();
    return result;
}
Json::Value snapshot_json(const SnapshotPage& page) {
    Json::Value value;
    value["success"] = true;
    value["snapshot_id"] = page.id;
    value["epoch"] = page.cursor.epoch;
    value["cursor"] = std::to_string(page.cursor.sequence);
    value["total"] = Json::UInt64(page.total);
    value["next_offset"] = page.next ? Json::Value(Json::UInt64(*page.next)) : Json::Value();
    auto& items = value["items"] = Json::Value(Json::arrayValue);
    for (const auto& row : page.items) items.append(wire::parse(row));
    return value;
}
}
Json::Value RequestDispatcher::execute(ClientSession& session, const std::string& command, const Json::Value& request) {
    if (std::find(commands.begin(), commands.end(), command) == commands.end()) {
        auto result = system_.execute(session.caller, command, request);
        if (command == "capabilities" && result["success"].asBool()) {
            result["service_api_minor"] = 1;
            for (const auto* name : commands) result["commands"].append(name);
            result["task_events"] = "explicit-subscription-v1";
        }
        return result;
    }
    try {
        const auto caller = context(session);
        if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
        Json::Value result;
        result["success"] = true;
        if (command == "task_get" || command == "task_cancel") {
            TaskRef ref{string_field(request, "epoch"), string_field(request, "task_id")};
            const auto task = command == "task_get" ? tasks_.get(caller, ref) : tasks_.cancel(caller, ref);
            result["task"] = task_summary(task);
            if (task.state == TaskState::succeeded) result["task"]["result"] = task.result;
        } else if (command == "task_snapshot") {
            return snapshot_json(tasks_.snapshot(caller, size_field(request, "max_bytes", 256u << 10)));
        } else if (command == "task_snapshot_page") {
            return snapshot_json(tasks_.snapshot_page(caller, string_field(request, "snapshot_id"),
                size_field(request, "offset", 0), size_field(request, "max_bytes", 256u << 10)));
        } else if (command == "task_snapshot_release") {
            tasks_.release_snapshot(caller, string_field(request, "snapshot_id"));
        } else if (command == "task_subscribe") {
            if (!session.subscription.empty()) throw ServiceError(ErrorCode::invalid_argument, "Unsubscribe before changing streams");
            auto cursor = EventCursor::parse(string_field(request, "epoch"), string_field(request, "cursor"));
            auto id = tasks_.subscribe(caller, cursor);
            session.subscription = std::move(id);
            session.cursor = cursor.sequence;
            result["epoch"] = cursor.epoch;
            result["cursor"] = std::to_string(cursor.sequence);
        } else if (command == "task_unsubscribe") disconnected(session);
        return result;
    } catch (const ServiceError& error) { return failure(error); }
}
std::optional<Json::Value> RequestDispatcher::events(ClientSession& session) {
    if (session.subscription.empty()) return {};
    try {
        auto batch = tasks_.poll(context(session), session.subscription);
        if (batch.covered.sequence == session.cursor) return {};
        Json::Value result;
        result["type"] = "event";
        result["event"] = "task_events";
        result["epoch"] = batch.covered.epoch;
        result["cursor"] = std::to_string(batch.covered.sequence);
        auto& items = result["events"] = Json::Value(Json::arrayValue);
        for (const auto& item : batch.events) items.append(wire::parse(item.encoded));
        session.cursor = batch.covered.sequence;
        return result;
    } catch (const ServiceError& error) {
        disconnected(session);
        auto result = failure(error);
        result["type"] = "event";
        result["event"] = "task_stream_error";
        return result;
    }
}
void RequestDispatcher::disconnected(ClientSession& session) noexcept {
    if (session.subscription.empty()) return;
    try { tasks_.unsubscribe(context(session), session.subscription); } catch (...) {}
    session.subscription.clear();
}
}
