// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "services/usb_acm.h"
#include "web/usb_acm.h"
#include <chrono>
#include <mutex>
#include <thread>

namespace droidvm::web {
// Synthetic gadget observation/IO around the real application service.
struct FixtureAcmPool : vm::AcmControl, vm::AcmTransaction {
    mutable std::mutex mutex;
    std::optional<vm::AcmDesired> desired;
    vm::AcmDesired actual;
    std::string mode = "ready";
    size_t applies = 0;
    bool unreadable = false;
    void transaction(const std::function<void(vm::AcmTransaction&)>& work) override {
        std::lock_guard lock(mutex); work(*this);
    }
    Json::Value live(const vm::AcmDesired& target) const override {
        Json::Value out;
        const bool available = mode != "unavailable" && !unreadable;
        const bool applied = available && actual.enabled == target.enabled && (!target.enabled || actual.ports == target.ports);
        out["available"] = available; out["applied"] = applied;
        out["udcBound"] = available ? Json::Value(true) : Json::Value();
        out["ports"] = available ? Json::Value(actual.enabled ? actual.ports : 0) : Json::Value();
        out["reason"] = !available ? Json::Value("gadget-unavailable") : applied ? Json::Value() : Json::Value("pool-size-mismatch");
        out["owners"] = Json::Value(Json::arrayValue);
        if (mode == "busy") {
            Json::Value owner; owner["slot"] = 0; owner["vmId"] = "fixture-acm-vm";
            owner["private"] = "/private/acm-owner"; out["owners"].append(owner);
        }
        return out;
    }
    void admit(const vm::AcmDesired& target) const override {
        if (mode == "busy" && !live(target)["applied"].asBool())
            throw ServiceError(ErrorCode::conflict, "Active ACM slot prevents rebinding");
    }
    void bind(std::optional<vm::AcmDesired> target) override { desired = target; }
    void apply() override {
        if (!desired) throw ServiceError(ErrorCode::commit_uncertain, "ACM desired settings unavailable");
        ++applies;
        if (mode == "apply-unknown") { unreadable = true; throw std::runtime_error("ACM observation lost"); }
        if (mode == "apply-failed" || mode == "unavailable") throw ServiceError(ErrorCode::io_error, "ACM fixture apply failed");
        admit(*desired); actual = *desired;
    }
};
struct FixtureUsbAcm {
    FixtureAcmPool pool;
    std::mutex storage_mutex;
    std::optional<UsbAcmLoaded> stored;
    std::string mode = "ready";
    size_t saves = 0;
    uint64_t external_id = 0;
    UsbAcmService service;
    explicit FixtureUsbAcm(TaskService& tasks) : service(tasks, {
        [this] { std::lock_guard lock(storage_mutex); return stored; },
        [this](const Json::Value& value) {
            std::lock_guard lock(storage_mutex);
            if (mode == "not-saved") return UsbAcmSave::not_saved;
            stored = UsbAcmLoaded{value, false}; ++saves;
            return mode == "installed-uncertain" ? UsbAcmSave::installed_uncertain : UsbAcmSave::saved;
        }, &pool
    }) {}
    UsbAcmBindings bindings() {
        return {
            [this](const CallContext& caller) { auto out = service.snapshot(caller); out["private"] = "/private/acm-config"; return out; },
            [this](const CallContext& caller, const Json::Value& request) { return service.start(caller, request); },
            [this](const CallContext& caller, const std::string& id) { return service.status(caller, id); }
        };
    }
    Json::Value stats(const CallContext& caller) {
        const auto observation = service.snapshot(caller);
        Json::Value out;
        out["initialized"] = observation["initialized"]; out["persistenceUncertain"] = observation["persistenceUncertain"];
        { std::lock_guard lock(storage_mutex); out["saves"] = Json::UInt64(saves); out["mode"] = mode; }
        { std::lock_guard lock(pool.mutex); out["applies"] = Json::UInt64(pool.applies); }
        return out;
    }
    void set_mode(const std::string& value) {
        if (value != "ready" && value != "busy" && value != "unavailable" && value != "apply-failed" &&
            value != "not-saved" && value != "installed-uncertain" && value != "apply-unknown")
            throw std::invalid_argument("Invalid USB ACM fixture mode");
        { std::lock_guard lock(storage_mutex); mode = value; }
        { std::lock_guard lock(pool.mutex); pool.mode = value; pool.unreadable = false; }
    }
    void external() {
        const CallContext caller{"fixture-acm-external", true, true, true};
        Json::Value request; request["requestId"] = "external-acm-" + std::to_string(++external_id);
        request["expected"] = service.snapshot(caller)["expected"];
        request["operation"]["kind"] = "configure"; request["operation"]["enabled"] = true; request["operation"]["ports"] = 3;
        auto task = service.start(caller, request);
        const auto until = TaskService::Clock::now() + std::chrono::seconds(5);
        while (!task_terminal(task.state)) {
            if (TaskService::Clock::now() >= until) throw std::runtime_error("USB ACM fixture task timed out");
            std::this_thread::sleep_for(std::chrono::milliseconds(1)); task = service.status(caller, request["requestId"].asString());
        }
        if (task.state != TaskState::succeeded) throw std::runtime_error("USB ACM fixture external edit failed");
    }
};
}
