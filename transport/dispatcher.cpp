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
constexpr std::array network_commands{"network_create", "network_modify", "network_list", "network_info", "network_exists"};
constexpr std::array host_commands{"network_list_interfaces", "network_list_uplinks", "network_list_host_addresses"};
bool host_command(const std::string& command) {
    return std::find(host_commands.begin(), host_commands.end(), command) != host_commands.end();
}
constexpr std::array runtime_commands{"network_start", "network_stop", "network_status", "network_tool_log"};
bool runtime_command(const std::string& command) {
    return std::find(runtime_commands.begin(), runtime_commands.end(), command) != runtime_commands.end();
}
void runtime_fields(Json::Value& row, const NetworkView& view, bool lowercase) {
    // Legacy UI knows four states. Unresolved cleanup must never look STOPPED;
    // publish the exact native state separately for capable clients.
    auto projected = view.state;
    if (projected == NetworkState::recovering) projected = NetworkState::starting;
    if (projected == NetworkState::failed) projected = view.desired_running ? NetworkState::starting : NetworkState::stopping;
    std::string state = network_state_name(projected);
    if (lowercase) for (auto& c : state) c += 'a' - 'A';
    row["state"] = state;
    row["runtime_state"] = network_state_name(view.state);
    row["runtime_error"] = view.error;
    row["runtime_generation"] = std::to_string(view.generation);
    row["desired_running"] = view.desired_running;
    row["tools"] = view.tools;
}
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
std::string legacy_id(const Json::Value& request) {
    // JSONObject.optString distinguishes an absent key from JSONObject.NULL
    // and stringifies other JSON values. DataItem's strict accessor is different.
    if (!request.isMember("network_id")) return {};
    const auto& value = request["network_id"];
    if (value.isString()) return value.asString();
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    builder["emitUTF8"] = true;
    return Json::writeString(builder, value);
}
}
bool RequestDispatcher::background(const std::string& command) const {
    return (host_network_ && host_command(command)) ||
        (runtime_ && runtime_command(command)) ||
        (networks_ && std::find(network_commands.begin(), network_commands.end(), command) != network_commands.end());
}
Json::Value RequestDispatcher::execute_background(const CallContext& caller, const std::string& command, const Json::Value& request) {
    Json::Value result;
    result["success"] = false;
    if (!caller.authenticated) { result["message"] = "client is not authorized to perform this action"; return result; }
    try {
        if (host_command(command) && host_network_) {
            result["data"] = command == "network_list_uplinks" ? host_network_->uplinks(caller) :
                command == "network_list_host_addresses" ? host_network_->addresses(caller) : host_network_->available_interfaces(caller);
            result["success"] = true;
            return result;
        }
        if (!networks_) { result["message"] = "internal error"; return result; }
        if (runtime_ && runtime_command(command)) {
            const auto id = legacy_id(request);
            if (id.empty()) { result["message"] = "missing network_id"; return result; }
            if (!networks_->exists(caller, id)) { result["message"] = "network " + id + " not found"; return result; }
            if (command == "network_tool_log") {
                if (!request["tool"].isString() || request["tool"].asString().empty()) { result["message"] = "missing tool"; return result; }
                result["lines"] = runtime_->tool_log(caller, id, string_field(request, "tool"));
            } else {
                const auto view = command == "network_start" ? runtime_->start(caller, id) :
                    command == "network_stop" ? runtime_->stop(caller, id) : runtime_->get(caller, id);
                result["network_id"] = id;
                runtime_fields(result, view, true);
            }
            result["success"] = true; return result;
        }
        if (command == "network_create" || command == "network_modify") {
            if (!request.isMember("config")) { result["message"] = "missing config"; return result; }
            result["network_id"] = command == "network_create" ? networks_->create(caller, request["config"]) : networks_->update(caller, request["config"]);
        } else if (command == "network_list") {
            auto rows = networks_->list(caller);
            for (auto& row : rows) {
                if (runtime_) runtime_fields(row, runtime_->get(caller, row["id"].asString()), true);
                else row["state"] = "stopped";
            }
            result["data"] = std::move(rows);
        } else {
            auto id = legacy_id(request);
            if (id.empty()) { result["message"] = "missing network_id"; return result; }
            if (command == "network_exists") {
                result["network_id"] = id;
                result["exists"] = networks_->exists(caller, id);
            } else {
                auto row = networks_->get(caller, id);
                row["state"] = "STOPPED";
                row["tools"] = Json::Value(Json::arrayValue);
                if (runtime_) runtime_fields(row, runtime_->get(caller, id), false);
                result["data"] = std::move(row);
            }
        }
        result["success"] = true;
        return result;
    } catch (const ServiceError& error) {
        if (runtime_command(command)) return failure(error);
        if (runtime_ && command == "network_modify" && error.code() == ErrorCode::conflict) return failure(error);
        if (host_command(command)) return failure(error);
        if (error.code() == ErrorCode::commit_uncertain || error.code() == ErrorCode::io_error || error.code() == ErrorCode::resource_exhausted)
            return failure(error);
        if (command == "network_create" && error.code() == ErrorCode::conflict) result["message"] = "failed to create network";
        else if (command == "network_modify" && error.code() == ErrorCode::not_found) result["message"] = "failed to modify network";
        else if (command == "network_info" && error.code() == ErrorCode::not_found) result["message"] = "network not found";
        else result["message"] = "internal error";
        return result;
    } catch (...) { result["message"] = "internal error"; return result; }
}
Json::Value RequestDispatcher::execute(ClientSession& session, const std::string& command, const Json::Value& request) {
    if (std::find(commands.begin(), commands.end(), command) == commands.end()) {
        auto result = system_.execute(session.caller, command, request);
        if (command == "capabilities" && result["success"].asBool()) {
            result["service_api_minor"] = 1;
            for (const auto* name : commands) result["commands"].append(name);
            result["task_events"] = "explicit-subscription-v1";
            if (networks_) {
                for (const auto* name : network_commands) result["commands"].append(name);
                result["network_config_persistence"] = true;
                result["network_runtime"] = false;
                result["service_api_minor"] = 2;
            }
            if (host_network_) {
                for (const auto* name : host_commands) result["commands"].append(name);
                result["network_host_interfaces"] = true;
                result["network_uplinks"] = true;
                result["network_host_addresses"] = true;
                result["service_api_minor"] = 3;
            }
            if (runtime_) {
                for (const auto* name : runtime_commands) result["commands"].append(name);
                result["network_lifecycle_backends"] = Json::Value(Json::arrayValue);
                result["network_lifecycle_backends"].append("gvisor");
                result["network_watchdog"] = true;
                result["network_auto_up"] = true;
                result["network_live_details"] = false;
                result["service_api_minor"] = 4;
            }
            if (host_network_) result["service_api_minor"] = 5;
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
