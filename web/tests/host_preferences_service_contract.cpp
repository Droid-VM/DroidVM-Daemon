// SPDX-License-Identifier: GPL-3.0-or-later
#include "services/host_preferences.h"
#include <atomic>
#include <chrono>
#include <future>
#include <iostream>
#include <mutex>
#include <thread>

namespace {
using namespace droidvm;
const CallContext admin{"preferences-contract", true, true, true};
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class F> void rejects(ErrorCode code, F work) {
    try { work(); } catch (const ServiceError& error) { check(error.code() == code, "wrong error"); return; }
    throw std::runtime_error("expected failure");
}
TaskLimits limits() { TaskLimits out; out.background_workers = 1; return out; }
struct Fixture {
    std::mutex mutex;
    std::optional<HostPreferencesLoaded> disk;
    HostPreferencesSave mode = HostPreferencesSave::saved;
    bool throw_save = false;
    unsigned writes = 0;
    HostPreferenceDomain domain;
    TaskService tasks{limits()};
    std::unique_ptr<HostPreferencesService> service;
    HostPreferencesOptions io() {
        return {
            [this] { std::lock_guard lock(mutex); return disk; },
            [this](const Json::Value& document) {
                std::lock_guard lock(mutex); ++writes;
                if (throw_save) { disk = HostPreferencesLoaded{document, false}; throw std::runtime_error("unknown rename"); }
                if (mode != HostPreferencesSave::not_saved) disk = HostPreferencesLoaded{document, false};
                return mode;
            }, domain
        };
    }
    explicit Fixture(HostPreferenceDomain selected = HostPreferenceDomain::vm_start) : domain(selected) {
        service = std::make_unique<HostPreferencesService>(tasks, io());
    }
    ~Fixture() { tasks.shutdown(); }
    Json::Value request(const std::string& id, bool clear = true) {
        Json::Value out;
        out["requestId"] = id; out["expected"] = service->snapshot(admin)["expected"];
        out["changes"]["vm_clear_logs_before_start"] = clear;
        return out;
    }
    Json::Value disk_request(const std::string& id, Json::Value cpus = Json::Value(Json::arrayValue)) {
        Json::Value out; out["requestId"] = id; out["expected"] = service->snapshot(admin)["expected"];
        out["changes"]["qemuImgCpus"] = std::move(cpus); out["changes"]["optimizeCompression"] = "none";
        return out;
    }
    TaskView finish(const TaskView& started) {
        for (unsigned i = 0; i < 2000; ++i) {
            const auto out = service->status(admin, started.request_id);
            if (task_terminal(out.state)) return out;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        throw std::runtime_error("preference task timed out");
    }
    TaskView run(const Json::Value& request) { return finish(service->start(admin, request)); }
};
}
int main() {
    try {
        {
            Fixture f;
            const auto initial = f.service->snapshot(admin);
            check(!initial["initialized"].asBool() && initial["values"]["optimize_sdcard"].asBool() &&
                initial["values"]["vm_hugepage_auto_reserve"].asBool() && !initial["values"]["vm_clear_logs_before_start"].asBool(), "wrong defaults");
            Json::Value local; local["theme"] = "dark";
            check(!f.service->sync_legacy(admin, local)["initialized"].asBool() && f.writes == 0, "local config consumed migration");
            Json::Value legacy; legacy["optimize_sdcard"] = false;
            const auto imported = f.service->sync_legacy(admin, legacy);
            check(imported["initialized"].asBool() && !f.service->values()["optimize_sdcard"].asBool(), "first import failed");
            auto request = f.request("edit"); request["changes"]["optimize_sdcard"] = true;
            const auto saved = f.run(request);
            check(saved.state == TaskState::succeeded && saved.result["saved"].asBool() && saved.result["expected"] == request["expected"], "save receipt failed");
            check(f.finish(f.service->start(admin, request)).ref.id == saved.ref.id && f.writes == 2, "request replay wrote twice");
            const auto after = f.service->sync_legacy(admin, legacy);
            check(after["values"]["optimize_sdcard"].asBool() && after["expected"]["revision"] == saved.result["revision"] && f.writes == 2, "App reconnect overwrote Web");
            auto stale = request; stale["requestId"] = "stale";
            check(f.run(stale).error == ErrorCode::conflict && f.writes == 2, "stale CAS wrote");
            request["changes"]["optimize_sdcard"] = false;
            rejects(ErrorCode::conflict, [&] { f.service->start(admin, request); });
            f.service = std::make_unique<HostPreferencesService>(f.tasks, f.io());
            check(f.service->snapshot(admin)["expected"]["revision"] == saved.result["revision"] && f.service->values()["vm_clear_logs_before_start"].asBool(), "startup did not load saved preferences");
        }
        {
            Fixture f; auto request = f.request("first-web");
            Json::Value legacy; legacy["vm_clear_logs_before_start"] = false;
            auto first = std::async(std::launch::async, [&] { return f.service->sync_legacy(admin, legacy); });
            const auto result = f.run(request); first.get();
            const auto snapshot = f.service->snapshot(admin);
            check(f.writes == 1 && snapshot["initialized"].asBool(), "first Web/import raced into two writes");
            check((result.state == TaskState::succeeded && snapshot["values"]["vm_clear_logs_before_start"].asBool()) ||
                (result.error == ErrorCode::conflict && !snapshot["values"]["vm_clear_logs_before_start"].asBool()), "first writer did not win");
        }
        {
            Fixture f; f.mode = HostPreferencesSave::not_saved;
            const auto result = f.run(f.request("no-install"));
            check(result.error == ErrorCode::io_error && !result.result["uncertain"].asBool() && result.result["revision"].isNull() &&
                !f.service->snapshot(admin)["initialized"].asBool(), "definite failure changed preferences");
            f.mode = HostPreferencesSave::installed_uncertain;
            const auto uncertain = f.run(f.request("installed"));
            check(uncertain.error == ErrorCode::commit_uncertain && !uncertain.result["saved"].asBool() && uncertain.result["uncertain"].asBool() &&
                uncertain.result["revision"].isString() && f.service->values()["vm_clear_logs_before_start"].asBool(), "installed uncertainty lost runtime value");
            check(f.finish(f.service->start(admin, f.request("next", false))).result["uncertain"].asBool(), "uncertain receipt omitted");
            f.mode = HostPreferencesSave::saved;
            { std::lock_guard lock(f.mutex); f.disk->recovered = true; }
            f.service = std::make_unique<HostPreferencesService>(f.tasks, f.io());
            Json::Value legacy; legacy["vm_clear_logs_before_start"] = true;
            check(f.service->sync_legacy(admin, legacy)["uncertain"].asBool() && !f.service->values()["vm_clear_logs_before_start"].asBool(), "backup recovery allowed legacy overwrite");
            check(f.run(f.request("explicit-save")).result["saved"].asBool() && !f.service->snapshot(admin)["uncertain"].asBool(), "explicit save failed to restore durability");
        }
        {
            Fixture f; f.throw_save = true;
            const auto request = f.request("unknown"); const auto unknown = f.run(request);
            check(unknown.error == ErrorCode::commit_uncertain && unknown.result["uncertain"].asBool() && unknown.result["revision"].isNull(), "unknown outcome claimed success");
            rejects(ErrorCode::commit_uncertain, [&] { f.service->values(); });
            check(f.finish(f.service->start(admin, request)).ref.id == unknown.ref.id && f.writes == 1, "unknown retry repeated save");
            check(f.run(f.request("do-not-retry")).error == ErrorCode::commit_uncertain && f.writes == 1, "unknown installation allowed another write");
            f.throw_save = false; f.service = std::make_unique<HostPreferencesService>(f.tasks, f.io());
            check(f.service->values()["vm_clear_logs_before_start"].asBool(), "restart did not reconcile installed value");
        }
        {
            Fixture f;
            auto bad = f.request("bad"); bad["changes"]["unknown"] = false;
            rejects(ErrorCode::invalid_argument, [&] { f.service->start(admin, bad); });
            bad = f.request("bad"); bad["changes"]["vm_clear_logs_before_start"] = "true";
            rejects(ErrorCode::invalid_argument, [&] { f.service->start(admin, bad); });
            auto caller = admin; caller.administrator = false;
            rejects(ErrorCode::permission_denied, [&] { f.service->snapshot(caller); });
            HostPreferencesOptions unreadable = f.io(); unreadable.load = []() -> std::optional<HostPreferencesLoaded> { throw std::runtime_error("broken store"); };
            bool failed = false; try { HostPreferencesService invalid(f.tasks, unreadable); } catch (const std::runtime_error&) { failed = true; }
            check(failed && f.writes == 0, "load failure became editable defaults");
        }
        {
            Fixture f; std::promise<void> entered, release;
            auto gate = release.get_future().share();
            TaskSpec blocker; blocker.kind = "blocker"; blocker.resource = "blocker"; blocker.background = true;
            f.tasks.submit(admin, blocker, [&](TaskControl&) { entered.set_value(); gate.wait(); return TaskCompletion::success(); });
            entered.get_future().wait();
            const auto queued = f.service->start(admin, f.request("cancelled"));
            f.tasks.cancel(admin, queued.ref); release.set_value();
            const auto cancelled = f.finish(queued);
            check(cancelled.state == TaskState::cancelled && cancelled.result["expected"].isNull() && cancelled.result["values"].isNull() &&
                !cancelled.result["saved"].asBool() && !cancelled.result["uncertain"].asBool() && f.writes == 0, "queued cancellation lacks no-effect receipt");
        }
        {
            Fixture f(HostPreferenceDomain::disk_operations);
            const auto initial = f.service->snapshot(admin);
            check(initial["capability"] == "disk-defaults-v1" && initial["values"]["optimizeCompression"] == "ask" &&
                initial["values"]["qemuImgCpus"].isArray() && initial["values"]["qemuImgCpus"].empty(), "disk defaults changed legacy semantics");
            Json::Value local; local["optimize_sdcard"] = true;
            check(!f.service->sync_legacy(admin, local)["initialized"].asBool(), "VM preference consumed disk migration");
            Json::Value legacy; legacy["vm_optimize_compression"] = "zstd"; legacy["qemu_img_cpu_affinity"] = " 4-6, 1,5 ";
            const auto imported = f.service->sync_legacy(admin, legacy);
            check(imported["values"]["optimizeCompression"] == "ask" && imported["values"]["qemuImgCpus"].size() == 4 &&
                imported["values"]["qemuImgCpus"][0] == 1 && imported["values"]["qemuImgCpus"][3] == 6, "legacy disk preference normalization failed");
            legacy["qemu_img_cpu_affinity"] = "invalid old data";
            check(f.service->sync_legacy(admin, legacy)["expected"] == imported["expected"] && f.writes == 1, "old App parsed or overwrote initialized disk owner");
        }
        for (const auto* bad : {"1,", ",1", "1,,2", "-1", "1024", "0-1024", "3-1", "0-a", "0-1-2", "all", "999999999999999999999"}) {
            Fixture f(HostPreferenceDomain::disk_operations);
            Json::Value legacy; legacy["vm_optimize_compression"] = "none"; legacy["qemu_img_cpu_affinity"] = bad;
            rejects(ErrorCode::invalid_argument, [&] { f.service->sync_legacy(admin, legacy); });
            check(f.writes == 0 && !f.service->snapshot(admin)["initialized"].asBool(), "invalid legacy CPUs silently became unrestricted");
        }
        {
            Fixture f(HostPreferenceDomain::disk_operations);
            Json::Value cpus(Json::arrayValue); for (int cpu = 1023; cpu >= 0; --cpu) cpus.append(cpu);
            auto request = f.disk_request("all-cpus", cpus); const auto saved = f.run(request);
            check(saved.state == TaskState::succeeded && saved.kind == "disk_defaults" && saved.resource == "disk-defaults" &&
                saved.result["values"]["qemuImgCpus"].size() == 1024 && saved.result["values"]["qemuImgCpus"][0] == 0 &&
                saved.result["values"]["qemuImgCpus"][1023] == 1023, "full CPU range exceeded task receipt or failed normalization");
            check(f.finish(f.service->start(admin, request)).ref.id == saved.ref.id && f.writes == 1, "disk default request replay wrote twice");
            request["requestId"] = "stale-disk-defaults";
            check(f.run(request).error == ErrorCode::conflict && f.writes == 1, "disk defaults bypassed CAS");
            f.service = std::make_unique<HostPreferencesService>(f.tasks, f.io());
            check(f.service->snapshot(admin)["expected"]["revision"] == saved.result["revision"] &&
                f.service->values()["qemuImgCpus"].size() == 1024, "disk defaults not reloaded");
            auto bad = f.disk_request("duplicate", cpus); bad["changes"]["qemuImgCpus"][1] = 1023;
            rejects(ErrorCode::invalid_argument, [&] { f.service->start(admin, bad); });
            bad = f.disk_request("compressed"); bad["changes"]["optimizeCompression"] = "deflate";
            rejects(ErrorCode::invalid_argument, [&] { f.service->start(admin, bad); });
            bad = f.disk_request("cross-domain"); bad["changes"]["optimize_sdcard"] = false;
            rejects(ErrorCode::invalid_argument, [&] { f.service->start(admin, bad); });
            check(f.run(f.disk_request("unrestricted")).result["values"]["qemuImgCpus"].empty(), "explicit empty CPU defaults not retained");
            HostPreferencesOptions host;
            host.load = [] { return std::optional<HostPreferencesLoaded>{}; };
            host.save = [](const Json::Value&) { return HostPreferencesSave::saved; };
            HostPreferencesService vm_preferences(f.tasks, host);
            rejects(ErrorCode::task_not_found, [&] { vm_preferences.status(admin, "all-cpus"); });
            check(vm_preferences.snapshot(admin)["capability"] == "host-preferences-v1" && vm_preferences.values().size() == 3,
                "disk domain changed original VM preferences contract");
        }
        std::cout << "PASS host and disk preference persistence, migration, CAS, deduplication and uncertainty\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
