// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "services/host_preferences.h"
#include "web/host_preferences.h"
#include <chrono>
#include <mutex>
#include <thread>

namespace droidvm::web {
// Actual shared service with injected memory persistence; no device writes.
struct FixtureHostPreferences {
    std::mutex mutex;
    std::optional<HostPreferencesLoaded> stored;
    std::string mode = "ready";
    size_t effects = 0;
    uint64_t external_id = 0;
    HostPreferenceDomain domain;
    HostPreferencesService service;
    explicit FixtureHostPreferences(TaskService& tasks, HostPreferenceDomain profile = HostPreferenceDomain::vm_start) : domain(profile), service(tasks, {
        [this] { std::lock_guard lock(mutex); return stored; },
        [this](const Json::Value& document) {
            std::lock_guard lock(mutex);
            if (mode == "not-saved") return HostPreferencesSave::not_saved;
            stored = HostPreferencesLoaded{document, false}; ++effects;
            return mode == "installed-uncertain" ? HostPreferencesSave::installed_uncertain : HostPreferencesSave::saved;
        }, profile
    }) {}
    HostPreferenceBindings bindings() {
        return {
            [this](const CallContext& caller) {
                auto result = service.snapshot(caller); result["private"] = "/private/host-preferences"; return result;
            },
            [this](const CallContext& caller, const Json::Value& request) { return service.start(caller, request); },
            [this](const CallContext& caller, const std::string& id) { return service.status(caller, id); }
        };
    }
    Json::Value stats(const CallContext& caller) {
        auto snapshot = service.snapshot(caller);
        Json::Value result;
        result["initialized"] = snapshot["initialized"]; result["uncertain"] = snapshot["uncertain"];
        std::lock_guard lock(mutex);
        result["effects"] = Json::UInt64(effects); result["mode"] = mode;
        return result;
    }
    void external() {
        const CallContext caller{"fixture-preferences-external", true, true, true};
        Json::Value request;
        request["requestId"] = (domain == HostPreferenceDomain::disk_operations ? "disk-default-external-" : "external-") + std::to_string(++external_id);
        request["expected"] = service.snapshot(caller)["expected"];
        if (domain == HostPreferenceDomain::disk_operations) {
            request["changes"]["optimizeCompression"] = "none";
            request["changes"]["qemuImgCpus"] = Json::Value(Json::arrayValue);
            request["changes"]["qemuImgCpus"].append(2); request["changes"]["qemuImgCpus"].append(3);
        } else request["changes"]["optimize_sdcard"] = false;
        auto task = service.start(caller, request);
        const auto until = TaskService::Clock::now() + std::chrono::seconds(5);
        while (!task_terminal(task.state)) {
            if (TaskService::Clock::now() >= until) throw std::runtime_error("Host preference fixture task timed out");
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            task = service.status(caller, request["requestId"].asString());
        }
        if (task.state != TaskState::succeeded) throw std::runtime_error("Host preference fixture external edit failed");
    }
};
}
