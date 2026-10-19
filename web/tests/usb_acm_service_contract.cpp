// SPDX-License-Identifier: GPL-3.0-or-later
#include "services/usb_acm.h"
#include <chrono>
#include <future>
#include <iostream>
#include <mutex>
#include <thread>

namespace {
using namespace droidvm;
const CallContext admin{"acm-contract", true, true, true};
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class F> void rejects(ErrorCode code, F work) {
    try { work(); } catch (const ServiceError& error) { check(error.code() == code, "wrong rejection"); return; }
    throw std::runtime_error("expected rejection");
}
struct Pool final : vm::AcmControl, vm::AcmTransaction {
    std::mutex mutex;
    std::optional<vm::AcmDesired> bound;
    vm::AcmDesired actual;
    bool occupied = false, readable = true, fail_apply = false, lose_observation = false, locked = false;
    unsigned applications = 0;
    void transaction(const std::function<void(vm::AcmTransaction&)>& work) override {
        std::lock_guard lock(mutex); locked = true;
        try { work(*this); } catch (...) { locked = false; throw; }
        locked = false;
    }
    Json::Value live(const vm::AcmDesired& desired) const override {
        check(locked, "live without pool lock"); Json::Value out;
        out["available"] = readable; out["applied"] = readable && actual == desired;
        out["udcBound"] = readable ? Json::Value(true) : Json::Value();
        out["ports"] = readable ? Json::Value(actual.enabled ? actual.ports : 0) : Json::Value();
        out["reason"] = out["applied"].asBool() ? Json::Value() : Json::Value("fixture-mismatch");
        out["owners"] = Json::Value(Json::arrayValue);
        if (occupied) { Json::Value owner; owner["slot"] = 0; owner["vmId"] = "vm-a"; out["owners"].append(owner); }
        return out;
    }
    void admit(const vm::AcmDesired& desired) const override {
        check(locked, "admission without pool lock");
        if (occupied && actual != desired) throw ServiceError(ErrorCode::conflict, "active owner");
    }
    void bind(std::optional<vm::AcmDesired> desired) override { check(locked, "bind without pool lock"); bound = desired; }
    void apply() override {
        check(locked && bound.has_value(), "apply without authority"); ++applications;
        if (fail_apply) { if (lose_observation) readable = false; throw std::runtime_error("partial apply"); }
        actual = *bound;
    }
};
TaskLimits limits() { TaskLimits out; out.background_workers = 1; return out; }
struct Fixture {
    Pool pool;
    std::optional<UsbAcmLoaded> disk;
    UsbAcmSave save_mode = UsbAcmSave::saved;
    bool unknown_save = false;
    unsigned saves = 0;
    TaskService tasks{limits()};
    std::unique_ptr<UsbAcmService> service;
    UsbAcmOptions options() {
        return {
            [this] { return disk; },
            [this](const Json::Value& document) {
                check(pool.locked, "save outside slot lock"); ++saves;
                if (unknown_save) { disk = UsbAcmLoaded{document, false}; throw std::runtime_error("unknown rename"); }
                if (save_mode != UsbAcmSave::not_saved) disk = UsbAcmLoaded{document, false};
                return save_mode;
            }, &pool
        };
    }
    Fixture() { service = std::make_unique<UsbAcmService>(tasks, options()); }
    ~Fixture() { tasks.shutdown(); }
    Json::Value configure(const std::string& id, bool enabled = true, int ports = 3) {
        Json::Value out; out["requestId"] = id; out["expected"] = service->snapshot(admin)["expected"];
        out["operation"]["kind"] = "configure"; out["operation"]["enabled"] = enabled; out["operation"]["ports"] = ports; return out;
    }
    Json::Value apply(const std::string& id) {
        auto out = configure(id); out["operation"] = Json::Value(Json::objectValue); out["operation"]["kind"] = "apply"; return out;
    }
    TaskView finish(const TaskView& task) {
        for (unsigned i = 0; i < 2000; ++i) {
            const auto current = service->status(admin, task.request_id);
            if (task_terminal(current.state)) return current;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        throw std::runtime_error("ACM task timed out");
    }
    TaskView run(const Json::Value& request) { return finish(service->start(admin, request)); }
};
}
int main() {
    try {
        {
            Fixture f;
            check(f.pool.applications == 0 && f.saves == 0 && !f.pool.bound, "first-run initialization changed gadget");
            Json::Value local; local["theme"] = "dark";
            check(!f.service->sync_legacy(admin, local)["initialized"].asBool(), "non-ACM config consumed migration");
            auto request = f.configure("web-first"); const auto saved = f.run(request);
            check(saved.state == TaskState::succeeded && saved.result["saved"].asBool() && saved.result["applied"].asBool(), "configure failed");
            const auto repeated = f.finish(f.service->start(admin, request));
            check(repeated.ref.id == saved.ref.id && f.saves == 1 && f.pool.applications == 1, "dedup repeated UDC application");
            Json::Value legacy; legacy["usb_acm_enable"] = false; legacy["usb_acm_ports"] = 1;
            check(f.service->sync_legacy(admin, legacy)["desired"]["enabled"].asBool() && f.saves == 1 && f.pool.applications == 1, "App reconnect overwrote Web");
            request["requestId"] = "stale"; check(f.run(request).error == ErrorCode::conflict && f.saves == 1, "stale CAS saved");
            f.pool.occupied = true;
            check(f.run(f.configure("active", false)).error == ErrorCode::conflict && f.saves == 1 && f.pool.applications == 1, "active pool changed before rejection");
            f.pool.occupied = false;
            f.service = std::make_unique<UsbAcmService>(f.tasks, f.options());
            check(f.pool.bound == std::optional(vm::AcmDesired{true, 3}) && f.pool.applications == 2, "startup did not load and apply desired");
        }
        {
            Fixture f; f.pool.fail_apply = true;
            const auto failed = f.run(f.configure("known-failure"));
            check(failed.state == TaskState::failed && failed.result["saved"].asBool() && !failed.result["applied"].asBool() &&
                !failed.result["uncertain"].asBool() && !f.pool.bound, "known partial failure was not separated from save");
            f.pool.fail_apply = false;
            const auto retried = f.run(f.apply("explicit-apply"));
            check(retried.state == TaskState::succeeded && retried.result["revision"] == failed.result["revision"] && f.saves == 1 &&
                retried.result["saved"].asBool() && retried.result["applied"].asBool(), "explicit apply saved/rebased unexpectedly");
        }
        {
            Fixture f; f.pool.fail_apply = true; f.pool.lose_observation = true;
            const auto request = f.configure("unknown-apply"); const auto unknown = f.run(request);
            check(unknown.result["saved"].asBool() && unknown.result["uncertain"].asBool() && !unknown.result["applied"].asBool(), "unknown live outcome omitted");
            f.service->snapshot(admin); f.service->status(admin, "unknown-apply");
            f.finish(f.service->start(admin, request));
            check(f.pool.applications == 1 && f.saves == 1 && !f.pool.bound, "unknown outcome caused automatic reapply");
            f.pool.readable = true; f.pool.fail_apply = false;
            check(f.run(f.apply("no-unknown-apply")).error == ErrorCode::commit_uncertain &&
                f.run(f.configure("no-unknown-configure")).error == ErrorCode::commit_uncertain &&
                f.pool.applications == 1 && f.saves == 1, "restored observation bypassed unknown outcome latch");
        }
        {
            Fixture f; f.save_mode = UsbAcmSave::not_saved;
            const auto failed = f.run(f.configure("not-saved"));
            check(!failed.result["saved"].asBool() && !failed.result["uncertain"].asBool() && failed.result["revision"].isNull() && f.pool.applications == 0, "failed save applied gadget");
            f.save_mode = UsbAcmSave::installed_uncertain;
            const auto installed = f.run(f.configure("installed"));
            check(installed.result["revision"].isString() && !installed.result["saved"].asBool() && installed.result["applied"].asBool() && installed.result["uncertain"].asBool(), "installed persistence uncertainty lost");
        }
        {
            Fixture f; f.unknown_save = true;
            const auto unknown = f.run(f.configure("unknown-save"));
            check(unknown.result["uncertain"].asBool() && unknown.result["revision"].isNull() && f.pool.applications == 0 && !f.pool.bound, "unknown save applied gadget");
            check(f.run(f.configure("no-retry")).error == ErrorCode::commit_uncertain && f.saves == 1, "unknown save was repeated");
            Json::Value legacy; legacy["usb_acm_enable"] = false;
            f.service->sync_legacy(admin, legacy); check(f.saves == 1, "unknown save allowed migration");
        }
        {
            Fixture f; Json::Value legacy; legacy["usb_acm_enable"] = true; legacy["usb_acm_ports"] = 2;
            const auto imported = f.service->sync_legacy(admin, legacy);
            check(imported["initialized"].asBool() && imported["desired"]["ports"] == 2 && f.saves == 1, "legacy import failed");
            f.disk->recovered = true; f.service = std::make_unique<UsbAcmService>(f.tasks, f.options());
            check(f.service->snapshot(admin)["persistenceUncertain"].asBool() && f.pool.applications == 1, "backup recovery automatically reapplied");
            auto bad = f.configure("bad", true, 7);
            rejects(ErrorCode::invalid_argument, [&] { f.service->start(admin, bad); });
        }
        std::cout << "PASS USB ACM persistence, migration, CAS, owners and save/apply outcomes\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
