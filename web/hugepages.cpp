// SPDX-License-Identifier: GPL-3.0-or-later
#include "hugepages.h"
#include "task_adapter.h"
#include <charconv>
#include <limits>
#include <array>

namespace droidvm::web {
namespace {
[[noreturn]] void invalid() { throw ServiceError(ErrorCode::invalid_argument, "Invalid hugepage operation"); }
struct AdvancedSetting { const char* key; uint64_t minimum, maximum; };
constexpr std::array advanced_settings{
    AdvancedSetting{"system_reserve_mb", 64, 1048576},
    AdvancedSetting{"cma_reservoir_floor_mb", 0, 1048576},
    AdvancedSetting{"boot_acquire", 0, 3}, AdvancedSetting{"boot_acquire_runs", 1, 99},
    AdvancedSetting{"boot_acquire_wait", 0, 3600}};
std::string token(const Json::Value& value, size_t limit = 128) {
    if (!value.isString()) invalid();
    const auto text = value.asString();
    if (text.empty() || text.size() > limit || text.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:") != std::string::npos) invalid();
    return text;
}
Json::Value quantity(const Json::Value& value) {
    if ((value.type() == Json::intValue || value.type() == Json::uintValue) && value.isUInt64())
        return std::to_string(value.asUInt64());
    if (!value.isString()) return {};
    const auto text = value.asString(); uint64_t number = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), number);
    if (text.empty() || error != std::errc() || end != text.data() + text.size() || std::to_string(number) != text) return {};
    return text;
}
Json::Value flag(const Json::Value& value) { return value.isBool() ? value : Json::Value(); }
Json::Value binary_flag(const Json::Value& value) {
    const auto number = quantity(value);
    return number == "0" ? Json::Value(false) : number == "1" ? Json::Value(true) : Json::Value();
}
Json::Value selected_lever(const Json::Value& value) { return value == "flag" || value == "hook" ? value : Json::Value(); }
void access(const CallContext& caller, bool mutation) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || (mutation && !caller.manage_tasks))
        throw ServiceError(ErrorCode::permission_denied, "Hugepage permission required");
}
void pages(const Json::Value& value) {
    const auto number = quantity(value);
    if (!value.isString() || number.isNull() || std::stoull(number.asString()) > 1073741824ULL) invalid();
}
void validate(const Json::Value& value) {
    if (!value.isObject() || value.size() != 3) invalid();
    (void)token(value["requestId"]);
    if (!value["expected"].isObject() || value["expected"].size() != 1) invalid();
    (void)token(value["expected"]["fingerprint"], 256);
    const auto& operation = value["operation"];
    if (!operation.isObject() || !operation["kind"].isString()) invalid();
    const auto kind = operation["kind"].asString();
    if (kind == "acquire") {
        if (operation.size() != 2 || !operation["mode"].isInt() || operation["mode"].asInt() < 1 || operation["mode"].asInt() > 3) invalid();
    } else if (kind == "stop-acquire" || kind == "unload" || kind == "reconcile" || kind == "migrate-settings" || kind == "dismiss-crash") {
        if (operation.size() != 1) invalid();
    } else if (kind == "targets") {
        if (operation.size() != 4 || operation["persist"] != true || !operation.isMember("cmaPages")) invalid();
        pages(operation["poolPages"]);
        if (!operation["cmaPages"].isNull()) pages(operation["cmaPages"]);
    } else if (kind == "runtime" || kind == "boot") {
        if (operation.size() != 2 || !operation["enabled"].isBool()) invalid();
    } else if (kind == "cma" || kind == "cma-save") {
        if (operation.size() != (kind == "cma" ? 5u : 3u) || !operation.isMember("lever")) invalid();
        if (!operation["lever"].isNull() && selected_lever(operation["lever"]).isNull()) invalid();
        pages(operation["pages"]);
        if (kind == "cma" && (!operation["enabled"].isBool() || !operation["persist"].isBool() ||
            (operation["enabled"].asBool() && operation["pages"] == "0"))) invalid();
    } else if (kind == "advanced") {
        if (operation.size() != 3 || !operation["key"].isString() || !operation.isMember("value")) invalid();
        const auto key = operation["key"].asString();
        bool found = false;
        for (const auto& setting : advanced_settings) if (key == setting.key) {
            found = true;
            if (!operation["value"].isNull()) {
                pages(operation["value"]);
                const auto number = std::stoull(operation["value"].asString());
                if (number < setting.minimum || number > setting.maximum) invalid();
            }
        }
        if (!found) invalid();
    } else invalid(); // Fixed domain operations only; no knob, path or shell dispatch.
}
}
Json::Value hugepage_snapshot(const Json::Value& native) {
    if (!native.isObject() || native["capability"] != "coordinated-hugepages-v1")
        throw ServiceError(ErrorCode::unavailable, "Hugepage observation unavailable");
    Json::Value result(Json::objectValue);
    result["fingerprint"] = token(native["fingerprint"], 256);
    result["revision"] = quantity(native["revision"]);
    if (result["revision"].isNull()) throw ServiceError(ErrorCode::unavailable, "Hugepage observation unavailable");
    for (const auto* key : {"installed", "loaded", "bootEnabled", "hasPoolWant", "hasCma", "busy"}) result[key] = flag(native[key]);
    result["consumerPages"] = quantity(native["consumerPages"]);
    result["manualPoolPages"] = quantity(native["manualPoolPages"]);
    result["consumerCount"] = native["consumerCount"].isUInt() ? native["consumerCount"] : Json::Value();
    const auto& controls = native["controls"];
    result["actualPoolPages"] = quantity(controls["pool_want"]);
    if (native["hasPoolWant"] == false && result["actualPoolPages"].isNull()) result["actualPoolPages"] = quantity(controls["pool_target"]);
    result["actualCmaPages"] = quantity(controls["pool_want_with_cma"]);
    const auto& settings = native["settings"];
    result["savedPoolPages"] = quantity(settings.isMember("pool_want") ? settings["pool_want"] : settings["pool_target"]);
    result["savedCmaPages"] = quantity(settings["pool_want_with_cma"]);
    const auto& stats = native["stats"];
    result["poolTotalPages"] = quantity(stats["pool_total"]);
    result["poolAvailablePages"] = quantity(stats["pool_avail"]);
    result["servedPages"] = quantity(stats["served"]);
    result["cmaPoolPages"] = quantity(stats["pool_cma"]);
    const auto active = quantity(stats["acquire_active"]);
    result["acquireActive"] = active == "0" ? Json::Value(false) : active == "1" ? Json::Value(true) : Json::Value();
    const auto mode = quantity(stats["acquire_mode"]);
    result["acquireMode"] = mode == "1" ? Json::Value(1) : mode == "2" ? Json::Value(2) : mode == "3" ? Json::Value(3) : Json::Value();
    result["hasCrash"] = flag(native["hasCrash"]);
    result["hasLegacySettings"] = flag(native["hasLegacySettings"]);
    auto& features = result["features"] = Json::Value(Json::objectValue);
    for (const auto* key : {"acquire", "stopAcquire", "reconcile", "restrict", "gfpHook"})
        features[key] = native["features"][key].isBool() && native["features"][key].asBool();
    auto& cma = result["cma"] = Json::Value(Json::objectValue);
    cma["vendorAllowed"] = binary_flag(controls["moveable_to_cma_vender_already_allowed"]);
    cma["restrictEnabled"] = binary_flag(controls["moveable_to_cma_restrict_cma_redirect_disabled"]);
    cma["gfpHookEnabled"] = binary_flag(controls["moveable_to_cma_gfp_cma_hook"]);
    cma["savedLever"] = selected_lever(settings["cma_movable_lever"]);
    cma["savedLastPages"] = quantity(settings["pool_want_with_cma_last"]);
    result["systemReserveDefaultMb"] = quantity(controls["system_reserve_mb_default"]);
    auto& advanced = result["advanced"] = Json::Value(Json::arrayValue);
    for (const auto& setting : advanced_settings) {
        Json::Value row;
        row["key"] = setting.key;
        row["saved"] = quantity(settings[setting.key]); row["live"] = quantity(controls[setting.key]);
        const auto& writable = native["advancedLiveWritable"][setting.key];
        const bool live = std::string_view(setting.key) == "cma_reservoir_floor_mb" && writable.isBool() && writable.asBool();
        row["liveWritable"] = live; row["application"] = live ? "live" : "next-load";
        auto desired = row["saved"];
        // Absence can mean module defaults; an invalid saved value cannot.
        if (!settings.isMember(setting.key) && std::string_view(setting.key) == "system_reserve_mb") desired = result["systemReserveDefaultMb"];
        row["reloadRequired"] = desired.isNull() || row["live"].isNull() ? Json::Value() : Json::Value(desired != row["live"]);
        row["minimum"] = std::to_string(setting.minimum); row["maximum"] = std::to_string(setting.maximum);
        advanced.append(std::move(row));
    }
    return result;
}
Json::Value project_hugepage_result(const Json::Value& native) {
    if (!native.isObject()) return {};
    Json::Value result(Json::objectValue);
    for (const auto* key : {"saved", "applied", "degraded", "uncertain"}) {
        if (!native[key].isBool()) return {};
        result[key] = native[key];
    }
    result["implementation"] = Json::Value();
    try { result["implementation"] = token(native["implementation"], 64); } catch (const ServiceError&) {}
    result["snapshot"] = Json::Value();
    if (native["snapshot"].isObject()) {
        try { result["snapshot"] = hugepage_snapshot(native["snapshot"]); } catch (const ServiceError&) {}
    }
    return result;
}
HugepageOperations hugepage_operations(HugepageBindings source) {
    if (!source.snapshot || !source.start || !source.status) throw std::invalid_argument("Missing hugepage binding");
    return {
        [source](const CallContext& caller) { access(caller, false); return hugepage_snapshot(source.snapshot(caller)); },
        {
            [source](const CallContext& caller, const Json::Value& input) {
                access(caller, true); validate(input);
                const auto task = source.start(caller, input);
                if (task.kind != "hugepage_operation" || task.resource != "hugepages" || task.request_id != input["requestId"].asString())
                    throw ServiceError(ErrorCode::internal, "Hugepage task identity mismatch");
                return task_view(task);
            },
            [source](const CallContext& caller, const std::string& request_id) {
                access(caller, true); (void)token(request_id);
                try {
                    const auto task = source.status(caller, request_id);
                    if (task.kind != "hugepage_operation" || task.resource != "hugepages" || task.request_id != request_id)
                        throw ServiceError(ErrorCode::conflict, "Hugepage task identity mismatch");
                    return task_view(task);
                } catch (const ServiceError& error) {
                    if (error.code() != ErrorCode::task_not_found) throw;
                    return Json::Value();
                }
            }
        }
    };
}
}
