// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "web/hugepages.h"
#include "common/wire.h"
#include <mutex>

namespace droidvm::web {
// Synthetic state only. No sysfs, kernel module or settings mutation.
struct FixtureHugepages {
    std::mutex mutex;
    uint64_t revision = 1, reads = 0, effects = 0;
    std::string mode = "ready", pool = "1024", cma = "2048";
    std::string saved_pool = "1024", saved_cma = "2048", manual_pool = "768", last_cma = "2048";
    bool module_loaded = true, boot_enabled = true, crash = false, legacy_settings = false;
    bool restrict_enabled = false, hook_enabled = false;
    unsigned consumers = 1;
    Json::Value saved_lever = Json::Value("hook");
    Json::Value advanced_saved = wire::parse(R"({"system_reserve_mb":"768","cma_reservoir_floor_mb":"64","boot_acquire":"1","boot_acquire_runs":"4","boot_acquire_wait":"30"})");
    Json::Value advanced_live = wire::parse(R"({"system_reserve_mb":"512","cma_reservoir_floor_mb":"64","boot_acquire":"0","boot_acquire_runs":"4","boot_acquire_wait":"30"})");
    bool acquiring = false;
    unsigned acquire_mode = 1;
    std::string fingerprint() const { return "hugepage-fixture:" + std::to_string(revision); }
    void set_mode(const std::string& next) {
        mode = next; module_loaded = next != "unloaded";
        consumers = next == "idle" || next == "unloaded" || next == "legacy" ? 0u : 1u;
        legacy_settings = next == "legacy"; crash = next == "legacy";
        ++revision;
    }
    Json::Value snapshot_locked() const {
        Json::Value value;
        value["capability"] = "coordinated-hugepages-v1";
        value["fingerprint"] = fingerprint(); value["revision"] = std::to_string(revision);
        const bool legacy = mode == "legacy", unknown = mode == "unknown";
        value["installed"] = unknown ? Json::Value() : Json::Value(true);
        value["loaded"] = unknown ? Json::Value() : Json::Value(module_loaded);
        value["bootEnabled"] = unknown ? Json::Value() : Json::Value(boot_enabled);
        value["hasPoolWant"] = unknown ? Json::Value() : Json::Value(module_loaded && !legacy);
        value["hasCma"] = unknown ? Json::Value() : Json::Value(module_loaded && !legacy);
        value["hasCrash"] = unknown ? Json::Value() : Json::Value(crash);
        value["hasLegacySettings"] = unknown ? Json::Value() : Json::Value(legacy_settings);
        value["features"]["acquire"] = !unknown && module_loaded;
        value["features"]["stopAcquire"] = !unknown && module_loaded && !legacy;
        value["features"]["reconcile"] = !unknown && module_loaded;
        value["features"]["restrict"] = !unknown && module_loaded && !legacy;
        value["features"]["gfpHook"] = !unknown && module_loaded && !legacy;
        for (const auto* key : {"system_reserve_mb", "cma_reservoir_floor_mb", "boot_acquire", "boot_acquire_runs", "boot_acquire_wait"})
            value["advancedLiveWritable"][key] = !unknown && module_loaded && !legacy && mode != "readonly" && std::string_view(key) == "cma_reservoir_floor_mb";
        value["busy"] = mode == "busy";
        value["consumerPages"] = unknown ? Json::Value() : Json::Value(consumers ? "512" : "0");
        value["manualPoolPages"] = unknown ? Json::Value() : Json::Value(manual_pool);
        value["consumerCount"] = unknown ? Json::Value() : Json::Value(consumers);
        value["controls"] = Json::Value(Json::objectValue);
        value["settings"] = Json::Value(Json::objectValue);
        value["stats"] = Json::Value(Json::objectValue);
        if (!unknown) {
            value["settings"] = advanced_saved;
            value["settings"]["pool_want"] = saved_pool;
            value["settings"]["pool_want_with_cma"] = saved_cma;
            value["settings"]["pool_want_with_cma_last"] = last_cma;
            value["settings"]["cma_movable_lever"] = saved_lever;
        }
        if (!unknown && module_loaded) {
            value["controls"] = advanced_live;
            value["controls"][legacy ? "pool_target" : "pool_want"] = pool;
            value["controls"]["system_reserve_mb_default"] = "256";
            if (!legacy) {
                value["controls"]["pool_want_with_cma"] = cma;
                value["controls"]["moveable_to_cma_vender_already_allowed"] = 0;
                value["controls"]["moveable_to_cma_restrict_cma_redirect_disabled"] = restrict_enabled ? 1 : 0;
                value["controls"]["moveable_to_cma_gfp_cma_hook"] = hook_enabled ? 1 : 0;
            }
            value["stats"]["pool_total"] = "768"; value["stats"]["pool_avail"] = "256";
            value["stats"]["served"] = "512"; value["stats"]["pool_cma"] = "256";
            if (!legacy) {
                value["stats"]["acquire_active"] = acquiring ? "1" : "0";
                value["stats"]["acquire_mode"] = std::to_string(acquire_mode);
            }
        }
        value["settings"]["private-path"] = "/private/do-not-project";
        return value;
    }
    HugepageBindings bindings(TaskService& tasks) {
        return {
            [this](const CallContext&) { std::lock_guard lock(mutex); ++reads; return snapshot_locked(); },
            [this, &tasks](const CallContext& caller, const Json::Value& request) {
                TaskSpec spec{"hugepage_operation", "hugepages", 16u << 10, true, true};
                spec.request_id = request["requestId"].asString();
                auto signature = request; signature.removeMember("requestId");
                spec.request_signature = wire::stringify_bounded(signature, 4096);
                const auto ref = tasks.submit(caller, spec, [this, request](TaskControl& control) {
                    std::lock_guard lock(mutex);
                    if (request["expected"]["fingerprint"] != fingerprint())
                        throw ServiceError(ErrorCode::conflict, "Hugepage observation changed");
                    if (mode == "busy" || mode == "unknown")
                        throw ServiceError(ErrorCode::unavailable, "Hugepage control unavailable");
                    const auto& operation = request["operation"];
                    const auto kind = operation["kind"].asString();
                    if (kind == "targets" && consumers && std::stoull(operation["poolPages"].asString()) < 512)
                        throw ServiceError(ErrorCode::conflict, "Below consumer floor");
                    if (consumers && (kind == "unload" || (kind == "runtime" && operation["enabled"] == false)))
                        throw ServiceError(ErrorCode::conflict, "Fixture consumer still active");
                    if (!module_loaded && (kind == "acquire" || kind == "stop-acquire" || kind == "reconcile" || kind == "cma" || kind == "cma-save"))
                        throw ServiceError(ErrorCode::unavailable, "Fixture module not loaded");
                    if (mode == "legacy" && (kind == "cma" || kind == "cma-save"))
                        throw ServiceError(ErrorCode::unavailable, "Fixture CMA unsupported");
                    if (kind == "cma-save" && (operation["pages"] != cma ||
                        (operation["lever"] == "flag" && !restrict_enabled) || (operation["lever"] == "hook" && !hook_enabled)))
                        throw ServiceError(ErrorCode::conflict, "Fixture CMA trial changed");
                    if (!control.enter_commit()) return TaskCompletion::cancelled();
                    ++effects; ++revision;
                    const bool partial = mode == "uncertain" || mode == "partial";
                    bool saved = false, applied = false;
                    std::string implementation = "fixture";
                    if (kind == "acquire") { acquiring = true; acquire_mode = operation["mode"].asUInt(); applied = true; }
                    else if (kind == "stop-acquire") { acquiring = false; applied = true; }
                    else if (kind == "targets") {
                        const auto requested_pool = operation["poolPages"].asString();
                        if (module_loaded && mode != "legacy") {
                            pool = requested_pool;
                            if (!operation["cmaPages"].isNull()) cma = operation["cmaPages"].asString();
                            manual_pool = pool; applied = true;
                        }
                        if (!partial) { saved_pool = requested_pool; if (!operation["cmaPages"].isNull()) saved_cma = operation["cmaPages"].asString(); saved = true; }
                    } else if (kind == "boot") { boot_enabled = operation["enabled"].asBool(); saved = true; }
                    else if (kind == "unload") { module_loaded = false; acquiring = false; manual_pool = "0"; applied = true; }
                    else if (kind == "runtime") {
                        if (operation["enabled"].asBool()) { module_loaded = true; pool = saved_pool; manual_pool = pool; acquiring = true; acquire_mode = 1; }
                        else { pool = "0"; manual_pool = "0"; acquiring = false; if (mode == "legacy") module_loaded = false; }
                        applied = true;
                    } else if (kind == "cma" || kind == "cma-save") {
                        if (kind == "cma") {
                            const bool enabled = operation["enabled"].asBool();
                            cma = enabled ? operation["pages"].asString() : "0";
                            if (!enabled) { restrict_enabled = false; hook_enabled = false; acquiring = false; }
                            else {
                                if (operation["lever"] == "flag") restrict_enabled = true;
                                if (operation["lever"] == "hook") hook_enabled = true;
                                acquiring = true; acquire_mode = 3;
                            }
                            applied = true;
                        }
                        if (!partial && (kind == "cma-save" || operation["persist"] == true)) {
                            saved_cma = cma; if (cma != "0") last_cma = cma;
                            saved_lever = operation["lever"]; saved = true;
                        }
                    } else if (kind == "advanced") {
                        const auto key = operation["key"].asString();
                        if (!partial) { if (operation["value"].isNull()) advanced_saved.removeMember(key); else advanced_saved[key] = operation["value"]; saved = true; }
                        if (key == "cma_reservoir_floor_mb" && module_loaded && mode != "legacy" && mode != "readonly" && !operation["value"].isNull()) {
                            advanced_live[key] = operation["value"]; applied = true;
                        } else implementation = "next-load";
                    } else if (kind == "reconcile") applied = true;
                    else if (kind == "migrate-settings") { legacy_settings = false; saved = true; }
                    else if (kind == "dismiss-crash") { crash = false; saved = true; }
                    else {
                        throw ServiceError(ErrorCode::invalid_argument, "Unsupported fixture operation");
                    }
                    Json::Value receipt;
                    receipt["saved"] = saved; receipt["applied"] = applied; receipt["degraded"] = false;
                    receipt["uncertain"] = partial; receipt["implementation"] = implementation;
                    receipt["snapshot"] = snapshot_locked();
                    return partial ? TaskCompletion::failure(ErrorCode::commit_uncertain, "Fixture partial outcome", receipt)
                        : TaskCompletion::success(receipt);
                });
                return tasks.get(caller, ref);
            },
            [&tasks](const CallContext& caller, const std::string& id) {
                auto task = tasks.find_request(caller, id);
                if (!task) throw ServiceError(ErrorCode::task_not_found, "Task not found");
                return *task;
            }
        };
    }
};
}
