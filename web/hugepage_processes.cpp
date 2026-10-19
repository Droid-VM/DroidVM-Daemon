// SPDX-License-Identifier: GPL-3.0-or-later
#include "hugepage_processes.h"
#include "task_adapter.h"
#include "common/wire.h"
#include <charconv>
#include <limits>

namespace droidvm::web {
namespace {
[[noreturn]] void invalid() { throw ServiceError(ErrorCode::invalid_argument, "Invalid hugepage process request"); }
[[noreturn]] void unavailable() { throw ServiceError(ErrorCode::unavailable, "Hugepage process observation unavailable"); }
bool source(const Json::Value& value) { return value == "ko" || value == "scan"; }
bool decimal(const Json::Value& value) {
    if (!value.isString()) return false;
    const auto text = value.asString(); uint64_t number = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), number);
    return !text.empty() && error == std::errc() && end == text.data() + text.size() && std::to_string(number) == text;
}
bool token(const Json::Value& value, size_t limit) {
    if (!value.isString()) return false;
    const auto text = value.asString();
    return !text.empty() && text.size() <= limit && text.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-") == std::string::npos;
}
Json::Value quantity(const Json::Value& value) { return decimal(value) ? value : Json::Value(); }
Json::Value reason(const Json::Value& value) { return token(value, 64) ? value : Json::Value(); }
Json::Value bounded_text(const Json::Value& value, size_t limit) {
    if (!value.isString() || value.asString().size() > limit) unavailable();
    return value;
}
Json::Value expected(const Json::Value& value) {
    if (!value.isObject() || value.size() != 4 || !value["pid"].isInt() || value["pid"].asInt() <= 1 ||
        !decimal(value["startTicks"]) || value["startTicks"] == "0" || !source(value["source"]) || !token(value["membership"], 256)) invalid();
    Json::Value result;
    for (const auto* key : {"pid", "startTicks", "source", "membership"}) result[key] = value[key];
    return result;
}
void access(const CallContext& caller, bool mutation) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || (mutation && !caller.manage_tasks))
        throw ServiceError(ErrorCode::permission_denied, "Hugepage process permission required");
}
Json::Value stack_result(const Json::Value& native, const Json::Value& identity) {
    if (!native.isObject() || expected(native["expected"]) != identity || !native["truncated"].isBool() || !native["available"].isBool()) unavailable();
    Json::Value result;
    result["expected"] = identity; result["truncated"] = native["truncated"]; result["available"] = native["available"];
    result["reason"] = reason(native["reason"]);
    result["text"] = native["text"].isNull() ? Json::Value() : bounded_text(native["text"], 32768);
    return result;
}
void task_identity(const TaskView& task, const std::string& request_id) {
    if (task.kind != "hugepage_process_signal" || task.resource != "hugepage-processes" || task.request_id != request_id)
        throw ServiceError(ErrorCode::conflict, "Hugepage process task identity mismatch");
}
}
Json::Value hugepage_process_catalog(const Json::Value& native) {
    if (!native.isObject() || native["capability"] != "hugepage-processes-v1" ||
        (!source(native["requestedSource"]) && native["requestedSource"] != "auto") || !source(native["source"]) ||
        !native["available"].isBool() || !native["partial"].isBool() ||
        (native["coverage"] != "module-owners" && native["coverage"] != "running-vms") ||
        !decimal(native["observedAtMs"]) || native["pageBytes"] != "2097152" ||
        !native["entries"].isArray() || native["entries"].size() > 512 ||
        !native["issues"].isArray() || native["issues"].size() > 32) unavailable();
    Json::Value result;
    for (const auto* key : {"requestedSource", "source", "available", "partial", "coverage", "observedAtMs", "pageBytes"}) result[key] = native[key];
    result["fallbackReason"] = reason(native["fallbackReason"]);
    for (const auto* key : {"pages", "bytes", "knownPages", "knownBytes"}) result["totals"][key] = quantity(native["totals"][key]);
    if (result["totals"]["knownPages"].isNull() || result["totals"]["knownBytes"].isNull()) unavailable();
    auto& entries = result["entries"] = Json::Value(Json::arrayValue);
    for (const auto& row : native["entries"]) {
        if (!row.isObject() || !row["pid"].isInt() || row["pid"].asInt() < 1 || !source(row["source"]) || !row["attributionVerified"].isBool()) unavailable();
        const auto status = row["identityStatus"];
        if (status != "verified" && status != "unverified" && status != "exited" && status != "changed" && status != "unreadable") unavailable();
        Json::Value entry;
        for (const auto* key : {"pid", "source", "identityStatus", "attributionVerified"}) entry[key] = row[key];
        entry["name"] = bounded_text(row["name"], 256);
        for (const auto* key : {"pages", "bytes", "startTicks"}) entry[key] = quantity(row[key]);
        entry["alive"] = row["alive"].isBool() ? row["alive"] : Json::Value();
        entry["state"] = row["state"].isString() && row["state"].asString().size() == 1 ? row["state"] : Json::Value();
        entry["reason"] = reason(row["reason"]); entry["vm"] = Json::Value();
        if (!row["vm"].isNull()) {
            const auto& vm = row["vm"];
            if (!vm.isObject() || !token(vm["id"], 128) || !token(vm["runtimeInstance"], 128) || !decimal(vm["runtimeRevision"])) unavailable();
            for (const auto* key : {"id", "runtimeInstance", "runtimeRevision"}) entry["vm"][key] = vm[key];
            entry["vm"]["name"] = bounded_text(vm["name"], 256);
        }
        entry["expected"] = Json::Value();
        if (!row["expected"].isNull()) {
            entry["expected"] = expected(row["expected"]);
            if (entry["expected"]["pid"] != row["pid"] || entry["expected"]["startTicks"] != entry["startTicks"] || status != "verified") unavailable();
        }
        // A legacy KO entry may only be controllable through its current VM's
        // scan membership. Do not infer KO attribution from this identity.
        entry["canSignal"] = !entry["expected"].isNull() && row["canSignal"] == true && entry["alive"] == true;
        entry["canStack"] = !entry["expected"].isNull() && row["canStack"] == true && entry["alive"] == true && entry["state"] == "D";
        entries.append(std::move(entry));
    }
    auto& issues = result["issues"] = Json::Value(Json::arrayValue);
    for (const auto& issue : native["issues"]) { const auto code = reason(issue); if (!code.isNull()) issues.append(code); }
    (void)wire::stringify_bounded(result, 1u << 20);
    return result;
}
Json::Value project_hugepage_process_result(const Json::Value& native, bool cancelled) {
    if (cancelled && native.isObject() && native.isMember("signal") && native["signal"].isNull() &&
        native.isMember("expected") && native["expected"].isNull() && native["sent"] == false &&
        native["uncertain"] == false && native["exited"] == false) {
        Json::Value result;
        for (const auto* key : {"signal", "expected", "sent", "uncertain", "exited"}) result[key] = native[key];
        return result;
    }
    if (!native.isObject() || (native["signal"] != "term" && native["signal"] != "kill") || !native["sent"].isBool() || !native["uncertain"].isBool()) return {};
    Json::Value result;
    try { result["expected"] = expected(native["expected"]); } catch (const ServiceError&) { return {}; }
    for (const auto* key : {"signal", "sent", "uncertain"}) result[key] = native[key];
    if (native["exited"].isBool()) result["exited"] = native["exited"];
    return result;
}
HugepageProcessOperations hugepage_process_operations(HugepageProcessBindings bindings) {
    if (!bindings.list || !bindings.stack || !bindings.start || !bindings.status) throw std::invalid_argument("Missing hugepage process binding");
    return {
        [bindings](const CallContext& caller, const std::string& selected) {
            access(caller, false); if (selected != "auto" && selected != "ko" && selected != "scan") invalid();
            auto result = hugepage_process_catalog(bindings.list(caller, selected));
            if (result["requestedSource"] != selected) unavailable();
            return result;
        },
        [bindings](const CallContext& caller, const Json::Value& input) {
            access(caller, false); const auto identity = expected(input);
            return stack_result(bindings.stack(caller, identity), identity);
        },
        {
            [bindings](const CallContext& caller, const Json::Value& input) {
                access(caller, true);
                if (!input.isObject() || input.size() != 3 || !token(input["requestId"], 128) || (input["signal"] != "term" && input["signal"] != "kill")) invalid();
                (void)expected(input["expected"]);
                const auto task = bindings.start(caller, input); task_identity(task, input["requestId"].asString());
                return task_view(task);
            },
            [bindings](const CallContext& caller, const std::string& request_id) {
                access(caller, true); if (!token(request_id, 128)) invalid();
                try { const auto task = bindings.status(caller, request_id); task_identity(task, request_id); return task_view(task); }
                catch (const ServiceError& error) { if (error.code() != ErrorCode::task_not_found) throw; return Json::Value(); }
            }
        }
    };
}
}
