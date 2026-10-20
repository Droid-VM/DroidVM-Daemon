// SPDX-License-Identifier: GPL-3.0-or-later
// Android display ownership over a modelled Android init/proc/sysfs and an
// in-process sentinel. Proves ordering and receipts, not the real HAL.
#include "services/android_display.h"
#include "web/android_display.h"
#include <chrono>
#include <condition_variable>
#include <deque>
#include <iostream>
#include <map>
#include <mutex>
#include <set>
#include <thread>

using namespace droidvm;
using namespace std::chrono_literals;
namespace {
const CallContext admin{"display-contract", true, true, true};
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class F> void rejects(ErrorCode code, F work) {
    try { work(); } catch (const ServiceError& error) { check(error.code() == code, "wrong rejection code"); return; }
    throw std::runtime_error("expected rejection");
}
// init + /proc + sysfs as the stop/restore sequence observes them.
struct Phone {
    std::mutex mutex;
    std::map<std::string, std::string> props{
        {"init.svc.surfaceflinger", "running"}, {"init.svc.vendor.qti.hardware.display.composer", "running"},
        {"init.svc.zygote", "running"}, {"init.svc.zygote_secondary", "running"}, {"init.svc.system_suspend", "running"},
        {"init.svc.bootanim", "stopped"}, {"service.bootanim.exit", "1"}, {"sys.boot_completed", "1"},
        {"init.svc_debug_pid.surfaceflinger", "100"}, {"init.svc_debug_pid.vendor.qti.hardware.display.composer", "101"},
        {"persist.sys.stability.scout.enable", "true"}, {"persist.sys.stability.nativehang.enable", "true"},
        {"persist.sys.stability.nativehangII.enable", "true"}, {"persist.sys.stability.qcom_hang_task.enable", "true"}};
    std::map<std::string, std::string> files{{"/sys/class/backlight/panel0-backlight/brightness", "379\n"}, {"/sys/class/net/wlan0/operstate", "up\n"}};
    int server_pid = 2000, server_generation = 1;
    bool server_frozen = false, dark_after_freeze = false, refuse_zygote_stop = false, panel_dark = false;
    std::vector<std::string> log; // every mutation in order
    uint64_t clock = 1'000'000;
    std::string prop(const std::string& key) { std::lock_guard lock(mutex); auto it = props.find(key); return it == props.end() ? "" : it->second; }
    void set(const std::string& key, const std::string& value) {
        std::lock_guard lock(mutex);
        log.push_back(key + "=" + value);
        if (key == "ctl.stop" || key == "ctl.start") {
            const bool start = key == "ctl.start";
            if (value == "zygote" && !start && refuse_zygote_stop) return;
            if (value == "zygote" && !start) { server_frozen = false; server_pid = 0; }
            if (value == "zygote" && start) { server_pid = 2000 + 10 * server_generation++; server_frozen = false; }
            if (value == "surfaceflinger" && start) props["init.svc_debug_pid.surfaceflinger"] = std::to_string(300 + server_generation);
            props["init.svc." + value] = start ? "running" : "stopped";
            return;
        }
        props[key] = value;
    }
};
struct FakeSentinel final : AndroidSentinel {
    Phone& phone;
    AndroidDisplayIo io;
    AndroidDisplayPlan plan;
    std::mutex mutex;
    std::condition_variable ready;
    std::deque<std::string> lines;
    bool closed = false, restored_once = false;
    std::vector<std::string> commands;
    std::thread worker;
    FakeSentinel(Phone& device, AndroidDisplayIo hooks, AndroidDisplayPlan request) : phone(device), io(std::move(hooks)), plan(std::move(request)) {
        push(plan.daemon_pid == 4242 ? "ready" : "failed daemon identity mismatch");
    }
    ~FakeSentinel() override { if (worker.joinable()) worker.join(); }
    void push(const std::string& line) { std::lock_guard lock(mutex); lines.push_back(line); ready.notify_all(); }
    void send(const std::string& line) override {
        { std::lock_guard lock(mutex); commands.push_back(line); }
        if (line != "restore" || restored_once) return;
        restored_once = true;
        worker = std::thread([this] {
            try { android_display_restore(io, plan, nullptr, [this](const std::string& phase) { push("progress " + phase); }); push("restored"); }
            catch (const std::exception& error) { push(std::string("failed ") + error.what()); }
        });
    }
    std::optional<std::string> read_line(std::chrono::milliseconds timeout) override {
        std::unique_lock lock(mutex);
        if (!ready.wait_for(lock, timeout, [&] { return !lines.empty() || closed; })) return std::nullopt;
        if (lines.empty()) return std::string();
        auto line = lines.front(); lines.pop_front(); return line;
    }
    void close() override { std::lock_guard lock(mutex); closed = true; ready.notify_all(); }
};
TaskLimits limits() { TaskLimits out; out.background_workers = 1; return out; }
struct Fixture {
    Phone phone;
    TaskService tasks{limits()};
    std::vector<FakeSentinel*> sentinels;
    std::string watchdog_reason;
    std::unique_ptr<AndroidDisplayService> service;
    AndroidDisplayIo io() {
        AndroidDisplayIo hooks;
        hooks.android = true;
        hooks.property = [this](const std::string& key) { return phone.prop(key); };
        hooks.set_property = [this](const std::string& key, const std::string& value) { phone.set(key, value); };
        hooks.read = [this](const std::string& path) -> std::optional<std::string> {
            std::lock_guard lock(phone.mutex);
            if (path.ends_with("brightness") && phone.panel_dark) return "0\n";
            auto it = phone.files.find(path); if (it == phone.files.end()) return std::nullopt; return it->second;
        };
        hooks.write = [this](const std::string& path, const std::string& value) { std::lock_guard lock(phone.mutex); phone.log.push_back(path + "<" + value); };
        hooks.processes = [this](const std::string& comm) { std::lock_guard lock(phone.mutex); return comm == "system_server" && phone.server_pid ? std::vector<int>{phone.server_pid} : std::vector<int>{}; };
        hooks.self_pid = [] { return 4242; };
        hooks.start_ticks = [this](int pid) -> std::optional<std::string> {
            std::lock_guard lock(phone.mutex);
            if (pid == 4242) return "77";
            if (pid == phone.server_pid) return "start" + std::to_string(pid);
            return std::nullopt;
        };
        hooks.stopped = [this](int pid) { std::lock_guard lock(phone.mutex); return pid == phone.server_pid && phone.server_frozen; };
        hooks.signal = [this](int pid, int number) {
            std::lock_guard lock(phone.mutex);
            check(pid == phone.server_pid, "signal sent to a stale pid");
            phone.log.push_back("kill " + std::to_string(number));
            phone.server_frozen = number == 19;
            if (phone.server_frozen && phone.dark_after_freeze) phone.panel_dark = true;
        };
        hooks.sleep = [this](std::chrono::milliseconds duration) { std::lock_guard lock(phone.mutex); phone.clock += static_cast<uint64_t>(duration.count()); };
        hooks.wall_ms = [this] { std::lock_guard lock(phone.mutex); return phone.clock; };
        hooks.default_interface = [] { return std::string("wlan0"); };
        hooks.watchdog_status = [this] { return watchdog_reason; };
        hooks.spawn_sentinel = [this](const AndroidDisplayPlan& plan) -> std::unique_ptr<AndroidSentinel> {
            auto sentinel = std::make_unique<FakeSentinel>(phone, io(), plan);
            sentinels.push_back(sentinel.get());
            return sentinel;
        };
        return hooks;
    }
    Fixture() { service = std::make_unique<AndroidDisplayService>(tasks, io()); }
    ~Fixture() { tasks.shutdown(); }
    web::WebServiceOperations api() {
        return web::android_display_operations({
            [this](const CallContext& caller) { return service->snapshot(caller); },
            [this](const CallContext& caller, const Json::Value& request) { return service->start(caller, request); },
            [this](const CallContext& caller, const std::string& id) { return service->status(caller, id); }});
    }
    Json::Value request(const std::string& id, const std::string& kind, const Json::Value& snapshot) {
        Json::Value out; out["requestId"] = id; out["expected"] = snapshot["expected"]; out["operation"]["kind"] = kind; return out;
    }
    Json::Value finish(web::WebServiceOperations& api, const Json::Value& input) {
        auto task = api.tasks.submit(admin, input);
        const auto until = std::chrono::steady_clock::now() + 10s;
        while (task["state"] == "queued" || task["state"] == "running") {
            check(std::chrono::steady_clock::now() < until, "task timed out");
            std::this_thread::sleep_for(1ms);
            task = api.tasks.find(admin, input["requestId"].asString());
        }
        return task;
    }
    Json::Value wait_state(web::WebServiceOperations& api, const char* state) {
        const auto until = std::chrono::steady_clock::now() + 10s;
        for (;;) {
            auto value = api.read(admin);
            if (value["state"] == state) return value;
            check(std::chrono::steady_clock::now() < until, "state wait timed out");
            std::this_thread::sleep_for(1ms);
        }
    }
    size_t index(const std::string& entry) {
        std::lock_guard lock(phone.mutex);
        for (size_t i = 0; i < phone.log.size(); ++i) if (phone.log[i] == entry) return i;
        throw std::runtime_error("missing log entry " + entry);
    }
};
}
int main() {
    try {
        {
            // Manual stop over the browser adapter, then restore.
            Fixture f; auto api = f.api();
            const auto initial = api.read(admin);
            check(initial["state"] == "android" && initial["supported"] == true && initial["owner"].isNull() &&
                initial["watchdog"]["verified"] == true && initial["network"]["interface"] == "wlan0" && initial["panelLit"] == true, "initial observation");
            rejects(ErrorCode::unauthenticated, [&] { api.read({}); });
            auto bad = f.request("bad", "stop", initial); bad["operation"]["autoRestoreSeconds"] = 5;
            rejects(ErrorCode::invalid_argument, [&] { api.tasks.submit(admin, bad); });
            bad = f.request("bad", "stop", initial); bad["operation"]["path"] = "/x";
            rejects(ErrorCode::invalid_argument, [&] { api.tasks.submit(admin, bad); });
            auto stop = f.request("stop-1", "stop", initial); stop["operation"]["autoRestoreSeconds"] = 600;
            auto task = f.finish(api, stop);
            check(task["state"] == "succeeded", "manual stop succeeded");
            const auto& receipt = task["androidDisplayResult"];
            check(receipt["stopped"] == true && receipt["state"] == "stopped" && receipt["network"]["operstate"] == "up" && receipt["kind"] == "stop", "stop receipt");
            // Restoration is armed before the first mutation, and the order is the verified one.
            check(f.sentinels.size() == 1 && f.sentinels[0]->plan.auto_restore_seconds == 600 && f.sentinels[0]->plan.restore_on_network_loss, "sentinel plan");
            check(f.index("/sys/power/wake_lock<droidvm_android_display") < f.index("ctl.stop=system_suspend"), "wake lock before suspend stop");
            check(f.index("persist.sys.stability.scout.enable=false") < f.index("kill 19"), "stability off before freeze");
            check(f.index("kill 19") < f.index("ctl.stop=surfaceflinger") && f.index("ctl.stop=surfaceflinger") < f.index("ctl.stop=vendor.qti.hardware.display.composer"), "freeze, SF, composer order");
            auto stopped = api.read(admin);
            check(stopped["state"] == "stopped" && stopped["owner"]["kind"] == "manual" && stopped["autoRestoreAtMs"].isString() && stopped["sinceMs"].isString(), "stopped observation");
            check(api.tasks.submit(admin, stop)["id"] == task["id"] && f.sentinels.size() == 1, "repeated request deduplicated");
            auto again = f.request("stop-2", "stop", stopped);
            check(f.finish(api, again)["errorCode"] == "CONFLICT", "second stop rejected while stopped");
            auto restore = f.request("restore-1", "restore", stopped);
            task = f.finish(api, restore);
            check(task["state"] == "succeeded" && task["androidDisplayResult"]["restored"] == true && task["androidDisplayResult"]["state"] == "android", "restore receipt");
            check(f.index("ctl.stop=zygote_secondary") < f.index("ctl.stop=zygote") && f.index("ctl.stop=zygote") < f.index("ctl.start=vendor.qti.hardware.display.composer") &&
                f.index("ctl.start=vendor.qti.hardware.display.composer") < f.index("ctl.start=surfaceflinger") && f.index("ctl.start=surfaceflinger") < f.index("ctl.start=zygote") &&
                f.index("ctl.start=zygote") < f.index("/sys/power/wake_unlock<droidvm_android_display") && f.index("ctl.start=system_suspend") < f.index("persist.sys.stability.scout.enable=true"), "restore order");
            const auto back = api.read(admin);
            check(back["state"] == "android" && back["owner"].isNull() && back["lastRestore"]["ok"] == true && back["expected"]["revision"] != stopped["expected"]["revision"], "restored observation");
            auto stale = f.request("stale", "restore", stopped);
            check(f.finish(api, stale)["errorCode"] == "CONFLICT", "stale revision rejected");
        }
        {
            // VM lease: stop before launch, restore after release; manual restore refused meanwhile.
            Fixture f; auto api = f.api();
            auto lease = f.service->acquire("vm-a", "Windows");
            auto owned = api.read(admin);
            check(owned["state"] == "stopped" && owned["owner"]["kind"] == "vm" && owned["owner"]["vmId"] == "vm-a" && owned["autoRestoreAtMs"].isNull() && owned["restoreOnNetworkLoss"] == false, "vm ownership");
            lease->watch(555);
            check(f.sentinels.size() == 1 && f.sentinels[0]->commands.back() == "watch 555", "sentinel watches the VMM");
            check(f.finish(api, f.request("manual-restore", "restore", owned))["errorCode"] == "CONFLICT", "manual restore refused for a VM session");
            try { f.service->acquire("vm-b", "Other"); throw std::runtime_error("second lease granted"); }
            catch (const std::runtime_error& error) { check(std::string(error.what()).find("already") != std::string::npos, "second lease reason"); }
            lease.reset();
            const auto restored = f.wait_state(api, "android");
            check(restored["lastRestore"]["ok"] == true && f.sentinels[0]->commands.back() == "restore", "release restores through the sentinel");
        }
        {
            // Preconditions: dark panel and unverified watchdog refuse before any mutation.
            Fixture f; auto api = f.api();
            f.phone.panel_dark = true;
            try { f.service->acquire("vm-a", "x"); throw std::runtime_error("dark panel accepted"); } catch (const std::runtime_error&) {}
            check(f.phone.log.empty() && f.sentinels.empty(), "dark panel left Android untouched");
            f.phone.panel_dark = false; f.watchdog_reason = "stale hangdetect status";
            auto task = f.finish(api, f.request("wd", "stop", api.read(admin)));
            check(task["state"] == "failed" && task["androidDisplayResult"]["stopped"] == false && f.phone.log.empty(), "unverified watchdog refused");
            check(api.read(admin)["watchdog"]["verified"] == false, "watchdog reason surfaced");
        }
        {
            // The panel blanks after the freeze: the partial stop is handed to the sentinel and restored.
            Fixture f; auto api = f.api();
            f.phone.dark_after_freeze = true;
            auto task = f.finish(api, f.request("blank", "stop", api.read(admin)));
            check(task["state"] == "failed" && task["androidDisplayResult"]["stopped"] == false, "blanked panel fails the stop");
            const auto restored = f.wait_state(api, "android");
            check(restored["lastRestore"]["ok"] == true && f.sentinels.size() == 1 && f.sentinels[0]->commands.back() == "restore", "partial stop restored");
            check(f.index("kill 19") < f.index("ctl.stop=zygote"), "frozen framework rebuilt");
            bool sf_stopped = false; for (const auto& entry : f.phone.log) sf_stopped = sf_stopped || entry == "ctl.stop=surfaceflinger";
            check(!sf_stopped, "SurfaceFlinger untouched after the blank check");
        }
        {
            // init refuses to stop zygote: the old framework is thawed and the failure is reported.
            Fixture f; auto api = f.api();
            f.phone.refuse_zygote_stop = true;
            check(f.finish(api, f.request("s", "stop", api.read(admin)))["state"] == "succeeded", "stop");
            auto task = f.finish(api, f.request("r", "restore", api.read(admin)));
            check(task["state"] == "failed" && task["androidDisplayResult"]["restored"] == false && task["androidDisplayResult"]["uncertain"] == false, "restore failure reported");
            check(f.index("kill 19") < f.index("kill 18"), "frozen framework thawed when zygote cannot stop");
            check(api.read(admin)["lastRestore"]["ok"] == false, "failure recorded");
        }
        {
            // Unsupported host: observable, never mutating.
            TaskService tasks(limits());
            AndroidDisplayIo io; io.android = false;
            AndroidDisplayService service(tasks, io);
            auto api = web::android_display_operations({
                [&](const CallContext& caller) { return service.snapshot(caller); },
                [&](const CallContext& caller, const Json::Value& request) { return service.start(caller, request); },
                [&](const CallContext& caller, const std::string& id) { return service.status(caller, id); }});
            const auto value = api.read(admin);
            check(value["supported"] == false && value["state"] == "android" && value["watchdog"]["reason"] == "unsupported-host", "unsupported observation");
            Json::Value request; request["requestId"] = "u"; request["expected"] = value["expected"]; request["operation"]["kind"] = "stop";
            auto task = api.tasks.submit(admin, request);
            const auto until = std::chrono::steady_clock::now() + 5s;
            while (task["state"] == "queued" || task["state"] == "running") { check(std::chrono::steady_clock::now() < until, "timeout"); std::this_thread::sleep_for(1ms); task = api.tasks.find(admin, "u"); }
            check(task["errorCode"] == "UNAVAILABLE", "unsupported host rejects stop");
            tasks.shutdown();
        }
        std::cout << "{\"passed\":true}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cout << "{\"passed\":false,\"error\":\"" << error.what() << "\"}\n";
        return 1;
    }
}
