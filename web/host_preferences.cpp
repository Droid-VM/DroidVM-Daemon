// SPDX-License-Identifier: GPL-3.0-or-later
#include "host_preferences.h"
#include "task_adapter.h"

namespace droidvm::web {
namespace {
bool disk(HostPreferenceDomain domain) { return domain == HostPreferenceDomain::disk_operations; }
[[noreturn]] void invalid() { throw ServiceError(ErrorCode::invalid_argument, "Invalid host preference request"); }
bool token(const Json::Value& value, size_t limit = 128) {
    if (!value.isString()) return false;
    const auto text = value.asString();
    return !text.empty() && text.size() <= limit && text.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-") == std::string::npos;
}
Json::Value expected(const Json::Value& value) {
    if (!value.isObject() || value.size() != 1 || !token(value["revision"])) invalid();
    return value;
}
Json::Value values(const Json::Value& value, HostPreferenceDomain domain, bool partial = false) {
    validate_host_preference_values(value, !partial, domain);
    return value;
}
void access(const CallContext& caller, bool write) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || (write && !caller.manage_tasks))
        throw ServiceError(ErrorCode::permission_denied, "Host preference permission required");
}
void identity(const TaskView& task, const std::string& id, HostPreferenceDomain domain) {
    if (task.kind != (disk(domain) ? "disk_defaults" : "host_preferences") ||
        task.resource != (disk(domain) ? "disk-defaults" : "host-preferences") || task.request_id != id)
        throw ServiceError(ErrorCode::conflict, "Host preference task identity mismatch");
}
}
Json::Value host_preference_catalog(const Json::Value& native, HostPreferenceDomain domain) {
    try {
        if (!native.isObject() || native["capability"] != (disk(domain) ? "disk-defaults-v1" : "host-preferences-v1") ||
            !native["initialized"].isBool() || !native["uncertain"].isBool()) invalid();
        Json::Value result;
        result["capability"] = native["capability"];
        result["expected"] = expected(native["expected"]);
        result["values"] = values(native["values"], domain);
        result["initialized"] = native["initialized"]; result["uncertain"] = native["uncertain"];
        return result;
    } catch (const ServiceError&) {
        throw ServiceError(ErrorCode::unavailable, "Host preferences unavailable");
    }
}
Json::Value project_host_preference_result(const Json::Value& native, bool cancelled, HostPreferenceDomain domain) {
    if (!native.isObject() || !native["saved"].isBool() || !native["uncertain"].isBool() ||
        !native.isMember("expected") || !native.isMember("values") || !native.isMember("revision")) return {};
    Json::Value result;
    if (cancelled && native["expected"].isNull() && native["values"].isNull() &&
        native["revision"].isNull() && native["saved"] == false && native["uncertain"] == false) {
        for (const auto* key : {"expected", "values", "revision", "saved", "uncertain"}) result[key] = native[key];
        return result;
    }
    try {
        result["expected"] = expected(native["expected"]);
        result["values"] = native["values"].isNull() ? Json::Value() : values(native["values"], domain);
        if (!native["revision"].isNull() && !token(native["revision"])) return {};
        for (const auto* key : {"revision", "saved", "uncertain"}) result[key] = native[key];
        if (result["saved"] == true && (result["values"].isNull() || result["revision"].isNull())) return {};
        return result;
    } catch (const ServiceError&) { return {}; }
}
WebServiceOperations host_preference_operations(HostPreferenceBindings bindings, HostPreferenceDomain domain) {
    if (!bindings.read || !bindings.start || !bindings.status) throw std::invalid_argument("Missing host preference binding");
    return {
        [bindings, domain](const CallContext& caller) { access(caller, false); return host_preference_catalog(bindings.read(caller), domain); },
        {
            [bindings, domain](const CallContext& caller, const Json::Value& input) {
                access(caller, true);
                if (!input.isObject() || input.size() != 3 || !token(input["requestId"])) invalid();
                (void)expected(input["expected"]); (void)values(input["changes"], domain, true);
                const auto task = bindings.start(caller, input); identity(task, input["requestId"].asString(), domain);
                return task_view(task);
            },
            [bindings, domain](const CallContext& caller, const std::string& id) {
                access(caller, true); if (!token(id)) invalid();
                try { const auto task = bindings.status(caller, id); identity(task, id, domain); return task_view(task); }
                catch (const ServiceError& error) { if (error.code() != ErrorCode::task_not_found) throw; return Json::Value(); }
            }
        }
    };
}
}
