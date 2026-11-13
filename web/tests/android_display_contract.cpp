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
        {"init.svc.netd", "running"}, {"init.svc.vendor.ipacm", "running"},
        {"init.svc.bootanim", "stopped"}, {"service.bootanim.exit", "1"}, {"sys.boot_completed", "1"},
        {"init.svc_debug_pid.surfaceflinger", "100"}, {"init.svc_debug_pid.vendor.qti.hardware.display.composer", "101"},
        {"persist.sys.stability.scout.enable", "true"}, {"persist.sys.stability.nativehang.enable", "true"},
        {"persist.sys.stability.nativehangII.enable", "true"}, {"persist.sys.stability.qcom_hang_task.enable", "true"}};
    std::map<std::string, std::string> files{{"/sys/class/backlight/panel0-backlight/brightness", "379\n"}, {"/sys/class/net/wlan0/operstate", "up\n"}};
    int server_pid = 2000, server_generation = 1;
    bool server_frozen = false, dark_after_freeze = false, refuse_zygote_stop = false, panel_dark = false;
    bool refuse_server_exit = false, refuse_netd_stop = false, netd_clean = false;
    bool network_known = true, network_default = true, network_validated = true;
    uint64_t network_ready_at = 0;
    int watchdog_opens = 0, watchdog_kicks = 0, watchdog_restores = 0;
    bool reject_watchdog = false;
    bool wifi_enabled = false, wifi_prepare_fails = false, wifi_start_fails = false, wifi_started = false;
    bool rescue_enabled = false, rescue_readonly = false, rescue_skip_note = false, rescue_pending_note = false;
    int rescue_actions = 0;
    std::vector<std::string> log; // every mutation in order
    uint64_t clock = 1'000'000;
    std::string prop(const std::string& key) { std::lock_guard lock(mutex); auto it = props.find(key); return it == props.end() ? "" : it->second; }
    void set(const std::string& key, const std::string& value) {
        std::lock_guard lock(mutex);
        if (key == rescue_count && rescue_readonly) throw std::runtime_error("boot count permission denied");
        log.push_back(key + "=" + value);
        auto register_boot = [&] {
            const auto start_ms = props[rescue_start].empty() ? 0 : std::stoull(props[rescue_start]);
            int count = std::stoi(props[rescue_count]) + 1;
            if (clock - start_ms >= 600000) { count = 1; props[rescue_start] = std::to_string(clock); }
            else if (count > 1) ++rescue_actions; // pre-existing mitigation history
            props[rescue_count] = std::to_string(count);
            log.push_back("rescue-note " + std::to_string(count));
            rescue_pending_note = false;
        };
        if (key == "ctl.stop" || key == "ctl.start") {
            const bool start = key == "ctl.start";
            if (value == "zygote" && !start && refuse_zygote_stop) return;
            if (value == "zygote" && !start && !refuse_server_exit) { server_frozen = false; server_pid = 0; }
            if (value == "netd" && !start) {
                if (refuse_netd_stop) return;
                netd_clean = true;
            }
            if (value == "zygote" && start) {
                server_pid = 2000 + 10 * server_generation++; server_frozen = false;
                if (rescue_enabled && !rescue_skip_note) {
                    if (props["init.svc.system_suspend"] == "running") register_boot();
                    else rescue_pending_note = true;
                }
            }
            if (value == "system_suspend" && start && rescue_pending_note) register_boot();
            if (value == "surfaceflinger" && start) props["init.svc_debug_pid.surfaceflinger"] = std::to_string(300 + server_generation);
            props["init.svc." + value] = start ? "running" : "stopped";
            return;
        }
        props[key] = value;
    }
};
struct FakeWatchdog final : AndroidWatchdog {
    Phone& phone;
    explicit FakeWatchdog(Phone& value) : phone(value) {}
    void kick(unsigned seconds) override {
        std::lock_guard lock(phone.mutex);
        check(seconds == 120, "bounded watchdog kick");
        ++phone.watchdog_kicks;
        if (phone.reject_watchdog) throw std::runtime_error("hangdetect kick: Bad address");
    }
    void restore() override { std::lock_guard lock(phone.mutex); ++phone.watchdog_restores; }
};
struct FakeWifi final : AndroidWifiSession {
    Phone& phone;
    explicit FakeWifi(Phone& value) : phone(value) {}
    void start() override {
        std::lock_guard lock(phone.mutex);
        ::check(phone.server_pid == 0 && phone.props["init.svc.zygote"] == "stopped", "Wi-Fi takeover preceded old framework exit");
        phone.log.push_back("wifi-start"); phone.wifi_started = true;
        if (phone.wifi_start_fails) throw std::runtime_error("Wi-Fi takeover failed");
    }
    void check() override {}
    void stop() override {
        std::lock_guard lock(phone.mutex);
        phone.log.push_back("wifi-stop"); phone.wifi_started = false;
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
    std::unique_ptr<AndroidWatchdog> watchdog;
    std::unique_ptr<AndroidWifiSession> wifi;
    std::thread worker;
    FakeSentinel(Phone& device, AndroidDisplayIo hooks, AndroidDisplayPlan request, const std::string& failure = {}) : phone(device), io(std::move(hooks)), plan(std::move(request)) {
        try {
            if (!failure.empty()) throw std::runtime_error(failure);
            check(plan.daemon_pid == 4242, "daemon identity mismatch");
            watchdog = android_display_arm_watchdog(io, plan);
            AndroidRescueRestart(io, plan.rescue_adapter).verify_access();
            if (!plan.wifi.isNull()) wifi = io.prepare_wifi(plan.wifi);
            push("ready");
        } catch (const std::exception& error) { push(std::string("failed ") + error.what()); }
    }
    ~FakeSentinel() override { if (worker.joinable()) worker.join(); }
    void push(const std::string& line) { std::lock_guard lock(mutex); lines.push_back(line); ready.notify_all(); }
    void send(const std::string& line) override {
        { std::lock_guard lock(mutex); commands.push_back(line); }
        if (line == "start-wifi") {
            try { wifi->start(); push("wifi-ready"); }
            catch (const std::exception& error) { push(std::string("wifi-failed ") + error.what()); }
            return;
        }
        if (line != "restore" || restored_once) return;
        restored_once = true;
        worker = std::thread([this] {
            try {
                android_display_restore(io, plan, watchdog.get(), [this](const std::string& phase) { push("progress " + phase); }, wifi.get());
                if (watchdog) watchdog->restore();
                push("restored");
            }
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
// The service drops its handle once restored; the fixture keeps the fake
// alive so checks can still read what it was sent.
struct SentinelRef final : AndroidSentinel {
    std::shared_ptr<FakeSentinel> target;
    explicit SentinelRef(std::shared_ptr<FakeSentinel> sentinel) : target(std::move(sentinel)) {}
    void send(const std::string& line) override { target->send(line); }
    std::optional<std::string> read_line(std::chrono::milliseconds timeout) override { return target->read_line(timeout); }
    void close() override { target->close(); }
};
TaskLimits limits() { TaskLimits out; out.background_workers = 1; return out; }
struct Fixture {
    Phone phone;
    TaskService tasks{limits()};
    std::vector<std::shared_ptr<FakeSentinel>> sentinels;
    std::string watchdog_reason, sentinel_failure;
    std::string rescue_reason;
    bool watchdog_required = true;
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
        hooks.uptime_ms = hooks.wall_ms;
        hooks.default_interface = [] { return std::string("wlan0"); };
        hooks.wifi_plan = [this] {
            Json::Value plan;
            if (phone.wifi_enabled) plan["interface"] = "wlan0";
            return plan;
        };
        hooks.prepare_wifi = [this](const Json::Value&) -> std::unique_ptr<AndroidWifiSession> {
            if (phone.wifi_prepare_fails) throw std::runtime_error("unsupported Wi-Fi config");
            return std::make_unique<FakeWifi>(phone);
        };
        hooks.network_status = [this]() -> std::optional<AndroidDisplayNetwork> {
            std::lock_guard lock(phone.mutex);
            if (!phone.network_known) return std::nullopt;
            const bool ready = phone.clock >= phone.network_ready_at && (phone.server_generation == 1 || phone.netd_clean);
            return AndroidDisplayNetwork{ready && phone.network_default, ready && phone.network_validated};
        };
        hooks.watchdog_status = [this] { return AndroidWatchdogStatus{watchdog_required, watchdog_reason}; };
        hooks.rescue_status = [this] { return AndroidRescueStatus{phone.rescue_enabled ? rescue_adapter : "", rescue_reason}; };
        hooks.open_watchdog = [this] {
            ++phone.watchdog_opens;
            return std::make_unique<FakeWatchdog>(phone);
        };
        hooks.spawn_sentinel = [this](const AndroidDisplayPlan& plan) -> std::unique_ptr<AndroidSentinel> {
            auto sentinel = std::make_shared<FakeSentinel>(phone, io(), plan, sentinel_failure);
            sentinels.push_back(sentinel);
            return std::make_unique<SentinelRef>(sentinel);
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
            std::map<std::string, std::string> props;
            bool present = false, denied = false;
            int hashes = 0;
            std::string hash = "4533611de83fa462db64b2bacab2c0e497535f4acd96c0ba4444db0e44b1f193";
            const auto probe = [&] {
                return android_rescue_probe([&](const std::string&) { if (denied) throw std::runtime_error("denied"); return present; },
                    [&](const std::string&) { ++hashes; return hash; }, [&](const std::string& key) { return props[key]; });
            };
            auto status = probe();
            check(status.adapter.empty() && status.reason.empty() && hashes == 0, "absent rescue skips adapter and fingerprint");
            denied = true; check(!probe().reason.empty(), "probe errors are not absence"); denied = false;
            props["sys.rescue_boot_count"] = "1";
            check(!probe().reason.empty(), "legacy counter requires its own adapter"); props.clear();
            present = true;
            check(!probe().reason.empty(), "present module without live accounting rejected");
            props[rescue_count] = "3";
            check(probe().adapter == rescue_adapter && probe().reason.empty(), "verified module adapted");
            hash = "unknown"; check(!probe().reason.empty(), "updated module refused before mutation");
            hash = "4533611de83fa462db64b2bacab2c0e497535f4acd96c0ba4444db0e44b1f193";
            props[rescue_count] = "-1"; check(!probe().reason.empty(), "invalid count rejected");
            props[rescue_count] = "3"; props["crashrecovery.attempting_factory_reset"] = "true";
            check(!probe().reason.empty(), "pending system recovery cannot be intercepted");
        }
        for (const std::string tier : {"display", "zygote"}) {
            Fixture f; f.phone.rescue_enabled = true;
            f.phone.props[rescue_count] = "3"; f.phone.props[rescue_start] = std::to_string(f.phone.clock - 1000);
            const auto window = f.phone.props[rescue_start];
            auto api = f.api();
            for (int n = 0; n < 3; ++n) {
                auto request = f.request("rescue-stop-" + std::to_string(n), "stop", api.read(admin));
                request["operation"]["tier"] = tier;
                check(f.finish(api, request)["state"] == "succeeded", "rescue guarded takeover succeeds");
                check(f.phone.prop(rescue_count) == "3", "stop does not erase previous boot history");
                check(AndroidDisplayPlan::parse(f.sentinels.back()->plan.json()).rescue_adapter == rescue_adapter, "rescue adapter survives sentinel handoff");
                check(f.finish(api, f.request("rescue-restore-" + std::to_string(n), "restore", api.read(admin)))["state"] == "succeeded", "guarded framework restoration succeeds");
                check(f.phone.prop(rescue_count) == "3" && f.phone.prop(rescue_start) == window && f.phone.rescue_actions == 0,
                    "repeated controlled boots preserve history without mitigation");
            }
            check(f.index("ctl.stop=zygote") < f.index(std::string(rescue_count) + "=0") &&
                f.index(std::string(rescue_count) + "=0") < f.index("ctl.start=zygote"), "accounting changes only while old framework is gone");
            // An unplanned subsequent boot must still trigger the modeled observer.
            f.phone.set("ctl.start", "zygote");
            check(f.phone.prop(rescue_count) == "4" && f.phone.rescue_actions == 1, "real later restart retains normal rescue behavior");
        }
        for (const std::string mode : {"absent", "unverified", "readonly", "cancel", "extra", "expired", "timeout", "arm-denied"}) {
            Fixture f;
            f.phone.rescue_enabled = mode != "absent";
            f.phone.props[rescue_count] = "3"; f.phone.props[rescue_start] = std::to_string(f.phone.clock - 1000);
            if (mode == "unverified" || mode == "readonly") {
                f.rescue_reason = mode == "unverified" ? "unverified rescue module" : "";
                f.phone.rescue_readonly = mode == "readonly";
                auto api = f.api();
                check(f.finish(api, f.request("rescue-refuse", "stop", api.read(admin)))["state"] == "failed" && f.phone.log.empty(), "unverified/read-only rescue refuses before Android mutation");
                continue;
            }
            auto io = f.io();
            AndroidRescueRestart guard(io, f.phone.rescue_enabled ? rescue_adapter : "");
            guard.verify_access();
            if (mode == "expired") f.phone.props[rescue_start] = "0";
            if (mode == "arm-denied") f.phone.rescue_readonly = true;
            bool failed = false;
            try {
                guard.arm();
                if (mode == "cancel") guard.cancel();
                else if (mode == "absent") {
                    guard.finish(2000, "start2000");
                    check(f.phone.log.empty(), "absent adapter performs no property writes");
                } else {
                    f.phone.rescue_skip_note = mode == "timeout";
                    f.phone.set("ctl.start", "zygote");
                    if (mode == "extra") f.phone.set("ctl.start", "zygote");
                    guard.finish(2000, "start2000");
                }
            } catch (const std::exception&) { failed = true; }
            check(failed == (mode == "extra" || mode == "timeout" || mode == "arm-denied"), "accounting failure reported");
            const auto expected = mode == "extra" ? "4" : mode == "expired" ? "0" : "3";
            check(f.phone.prop(rescue_count) == expected, "cancel/extra/expired/timeout accounting preserved");
        }
        {
            Fixture f; f.phone.rescue_enabled = true;
            f.phone.props[rescue_count] = "3"; f.phone.props[rescue_start] = std::to_string(f.phone.clock - 1000);
            auto io = f.io();
            bool fail_after_write = false;
            io.set_property = [&](const std::string& key, const std::string& value) {
                f.phone.set(key, value);
                if (fail_after_write) throw std::runtime_error("ambiguous committed write");
            };
            bool failed = false;
            {
                AndroidRescueRestart guard(io, rescue_adapter);
                guard.arm(); f.phone.set("ctl.start", "zygote");
                fail_after_write = true;
                try { guard.finish(2000, "start2000"); } catch (const std::exception&) { failed = true; }
            }
            check(failed && f.phone.prop(rescue_count) == "3", "ambiguous committed reconciliation is not applied twice");
        }
        {
            Fixture f; f.phone.rescue_enabled = true;
            f.phone.props[rescue_count] = "3"; f.phone.props[rescue_start] = std::to_string(f.phone.clock - 1000);
            auto api = f.api();
            check(f.finish(api, f.request("rescue-timeout-stop", "stop", api.read(admin)))["state"] == "succeeded", "timeout fixture stopped");
            f.phone.rescue_skip_note = true;
            const auto started = f.phone.clock;
            const auto kicks = f.phone.watchdog_kicks;
            const auto result = f.finish(api, f.request("rescue-timeout-restore", "restore", api.read(admin)));
            check(result["state"] == "failed" && f.phone.clock >= started + 40000 && f.phone.watchdog_kicks > kicks + 10,
                  "accounting timeout still verifies framework with watchdog protection");
            check(f.phone.prop(rescue_count) == "3" && f.phone.prop("init.svc.system_suspend") == "running", "timeout returns history and starts dependencies");
        }
        {
            check(android_wifi_config_matches("network={\nssid=\"my-ap\"\npsk=\"secret\"\n}\n", "my-ap"), "matching persisted network");
            check(android_wifi_config_matches("network={\nssid=6d792d6170\n}\n", "my-ap"), "hexadecimal SSID");
            check(!android_wifi_config_matches("network={\nssid=\"other\"\n}\n", "my-ap"), "wrong persisted network rejected");
            check(!android_wifi_config_matches("network={\nssid=\"my-ap\"\n}\nnetwork={\nssid=\"other\"\n}\n", "my-ap"), "multiple persisted networks rejected");
            check(!android_wifi_config_matches("network={\nssid=\"my-ap\"\n", "my-ap"), "truncated config rejected");
            Json::Value plan; plan["ip"] = "192.0.2.2"; plan["mask"] = "255.255.255.0";
            plan["gateway"] = "192.0.2.1"; plan["dns"] = "192.0.2.1 192.0.2.3";
            unsigned lease = 0;
            const std::string fields = "192.0.2.2\n255.255.255.0\n192.0.2.1\n192.0.2.3 192.0.2.1\n3600\n";
            check(android_wifi_lease_matches(plan, "bound\n" + fields, lease) && lease == 3600, "matching DHCP offer accepted");
            check(android_wifi_lease_matches(plan, "renew\n" + fields, lease), "matching DHCP renewal accepted");
            check(!android_wifi_lease_matches(plan, "deconfig\n" + fields, lease), "lost lease rejected");
            plan["ip"] = "192.0.2.9";
            check(!android_wifi_lease_matches(plan, "renew\n" + fields, lease), "changed address rejected");
            plan["ip"] = "192.0.2.2"; plan["dns"] = "192.0.2.9";
            check(!android_wifi_lease_matches(plan, "renew\n" + fields, lease), "changed DNS rejected");
        }
        for (const std::string mode : {"success", "prepare-failure", "start-failure", "display"}) {
            Fixture f; f.phone.wifi_enabled = true;
            f.phone.wifi_prepare_fails = mode == "prepare-failure";
            f.phone.wifi_start_fails = mode == "start-failure";
            auto api = f.api();
            auto request = f.request("wifi", "stop", api.read(admin));
            request["operation"]["tier"] = mode == "display" ? "display" : "zygote";
            const auto task = f.finish(api, request);
            if (mode == "prepare-failure") {
                check(task["state"] == "failed" && f.phone.log.empty(), "Wi-Fi preparation failure leaves Android untouched");
            } else if (mode == "start-failure") {
                check(task["state"] == "failed", "failed Wi-Fi association cannot report stopped");
                const auto restored = f.wait_state(api, "android");
                check(restored["lastRestore"]["ok"] == true && !f.phone.wifi_started, "partial Wi-Fi start is cleaned up");
                check(f.index("wifi-stop") < f.index("ctl.start=netd"), "partial Wi-Fi stopped before framework restoration");
            } else {
                check(task["state"] == "succeeded", "Wi-Fi session stopped successfully");
                const auto plan = AndroidDisplayPlan::parse(f.sentinels[0]->plan.json());
                check(plan.wifi.isNull() == (mode == "display"), "only zygote transfers Wi-Fi plan");
                if (mode == "success") check(f.phone.wifi_started && f.index("ctl.stop=zygote") < f.index("wifi-start"), "Wi-Fi ready before success receipt");
                else check(!f.phone.wifi_started, "display tier leaves original supplicant alone");
                check(f.finish(api, f.request("wifi-restore", "restore", api.read(admin)))["state"] == "succeeded", "Wi-Fi restoration succeeded");
                if (mode == "success") check(!f.phone.wifi_started && f.index("wifi-stop") < f.index("ctl.start=zygote"), "standalone Wi-Fi stops before new framework");
            }
        }
        {
            int verified = 0;
            auto verify = [&] { ++verified; return std::string(); };
            const auto absent = android_display_probe_watchdog([](const std::string&) { return false; }, verify);
            check(!absent.required && absent.reason.empty() && verified == 0, "absent hangdetect skips build/log checks");
            for (const std::string present : {"/dev/Monitor_Hang", "/sys/class/misc/Monitor_Hang", "/sys/module/hangdetect"}) {
                const auto found = android_display_probe_watchdog([&](const std::string& path) { return path == present; }, verify);
                check(found.required && found.reason.empty(), "every hangdetect indicator selects the driver adapter");
            }
            check(verified == 3, "only present drivers are verified");
            const auto denied = android_display_probe_watchdog([](const std::string&) -> bool { throw std::runtime_error("Permission denied"); }, verify);
            check(denied.required && !denied.reason.empty(), "probe errors cannot select the absent path");
            const auto unsupported = android_display_probe_watchdog([](const std::string&) { return true; }, [] { return "unverified ABI"; });
            check(unsupported.required && !unsupported.reason.empty(), "present unverified driver is not bypassed");
        }
        for (const std::string tier : {"display", "zygote"}) {
            Fixture f; auto api = f.api();
            f.watchdog_required = false;
            f.phone.reject_watchdog = true; // any accidental driver access would fail
            const auto initial = api.read(admin);
            check(initial["watchdog"]["verified"] == true && initial["watchdog"]["kick"] == "not-required", "absent watchdog is a ready path");
            auto stop = f.request("no-watchdog-stop", "stop", initial);
            stop["operation"]["tier"] = tier;
            stop["operation"]["autoRestoreSeconds"] = 60;
            check(f.finish(api, stop)["state"] == "succeeded", "no-watchdog takeover succeeded");
            check(f.sentinels.size() == 1 && f.sentinels[0]->plan.auto_restore_seconds == 60, "absent watchdog still arms the independent sentinel and timer");
            check(!AndroidDisplayPlan::parse(f.sentinels[0]->plan.json()).watchdog_required, "absent path survives sentinel plan serialization");
            check(api.read(admin)["watchdog"]["kick"] == "not-required", "no fictitious accepted kick");
            check(f.finish(api, f.request("no-watchdog-restore", "restore", api.read(admin)))["state"] == "succeeded", "no-watchdog restoration succeeded");
            check(f.phone.watchdog_opens == 0 && f.phone.watchdog_kicks == 0 && f.phone.watchdog_restores == 0, "no driver calls anywhere on the absent path");
            check(api.read(admin)["lastRestore"]["ok"] == true, "framework and network still verified without watchdog");
        }
        {
            Fixture f;
            AndroidDisplayPlan plan; plan.watchdog_required = false;
            bool failed = false;
            try { (void)android_display_arm_watchdog(f.io(), plan); } catch (const std::runtime_error&) { failed = true; }
            check(failed && f.phone.watchdog_opens == 0, "sentinel refuses changed watchdog presence before driver access");
        }
        {
            const std::string dump = "Active default network: 100\n"
                "  NetworkAgentInfo{network{101} nc{[ Capabilities: INTERNET&VALIDATED ]}\n"
                "  NetworkAgentInfo{network{100} nc{[ Capabilities: INTERNET&NOT_VPN ]}\n";
            auto status = android_display_network(dump);
            check(status && status->default_present && !status->validated, "only the default network's validation counts");
            status = android_display_network("Active default network: 101\n" + dump.substr(dump.find('\n') + 1));
            check(status && status->validated, "validated default parsed");
            check(!android_display_network("permission denied"), "unknown dump is not offline");
            check(!android_display_network("Active default network: 100\n"), "missing default agent is unknown");
            check(!android_display_network("Active default network: none\n")->default_present, "offline default parsed");
        }
        {
            // Manual stop over the browser adapter, then restore.
            Fixture f; auto api = f.api();
            const auto initial = api.read(admin);
            check(initial["state"] == "android" && initial["supported"] == true && initial["owner"].isNull() &&
                initial["watchdog"]["verified"] == true && initial["watchdog"]["kick"] == "unproven" && initial["network"]["interface"] == "wlan0" && initial["panelLit"] == true, "initial observation");
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
            check(api.read(admin)["watchdog"]["kick"] == "accepted", "armed sentinel proves the kick");
            check(f.phone.watchdog_opens == 1 && f.phone.watchdog_kicks == 1, "driver opened and initial kick completed before takeover");
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
            check(f.phone.watchdog_kicks > 1 && f.phone.watchdog_restores == 1, "driver fed during restoration and returned to original policy");
            check(back["state"] == "android" && back["owner"].isNull() && back["lastRestore"]["ok"] == true && back["expected"]["revision"] != stopped["expected"]["revision"], "restored observation");
            check(f.index("ctl.stop=zygote") < f.index("ctl.stop=vendor.ipacm") &&
                f.index("ctl.stop=vendor.ipacm") < f.index("ctl.stop=netd") &&
                f.index("ctl.stop=netd") < f.index("ctl.start=netd") &&
                f.index("ctl.start=netd") < f.index("ctl.start=vendor.ipacm") &&
                f.index("ctl.start=vendor.ipacm") < f.index("ctl.start=zygote"), "network rebuilt before new framework");
            check(std::find(f.phone.log.begin(), f.phone.log.end(), "ctl.start=wificond") == f.phone.log.end(), "absent wificond skipped");
            const auto plan = AndroidDisplayPlan::parse(f.sentinels[0]->plan.json());
            check(plan.network_services == std::vector<std::string>{"netd", "vendor.ipacm"} && plan.network_default && plan.network_validated, "network plan survives sentinel handoff");
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
            // The driver rejects the sentinel's kick: nothing is mutated and later stops are refused up front.
            Fixture f; auto api = f.api();
            f.phone.reject_watchdog = true;
            auto task = f.finish(api, f.request("kick", "stop", api.read(admin)));
            check(task["state"] == "failed" && task["androidDisplayResult"]["stopped"] == false && f.phone.log.empty(), "rejected kick left Android untouched");
            const auto value = api.read(admin);
            check(value["watchdog"]["verified"] == false && value["watchdog"]["kick"] == "rejected" &&
                value["watchdog"]["reason"].asString().find("Bad address") != std::string::npos, "rejected kick surfaced");
            f.phone.reject_watchdog = false;
            check(f.finish(api, f.request("kick-2", "stop", value))["state"] == "failed" && f.sentinels.size() == 1 && f.phone.log.empty(), "rejected kick blocks later stops");
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
            check(!f.phone.netd_clean, "live old framework's netd is not reset");
        }
        for (const std::string mode : {"no-default", "unvalidated", "unknown", "delayed", "offline", "old-server", "netd-stop"}) {
            Fixture f; auto api = f.api();
            f.phone.props["init.svc.wificond"] = "running";
            if (mode == "offline") { f.phone.network_default = false; f.phone.network_validated = false; }
            check(f.finish(api, f.request("network-stop", "stop", api.read(admin)))["state"] == "succeeded", "network test stopped");
            if (mode == "no-default") { f.phone.network_default = false; f.phone.network_validated = false; }
            if (mode == "unvalidated") f.phone.network_validated = false;
            if (mode == "unknown") f.phone.network_known = false;
            if (mode == "delayed") f.phone.network_ready_at = f.phone.clock + 30000;
            if (mode == "old-server") f.phone.refuse_server_exit = true;
            if (mode == "netd-stop") f.phone.refuse_netd_stop = true;
            const auto result = f.finish(api, f.request("network-restore", "restore", api.read(admin)));
            const bool ok = mode == "delayed" || mode == "offline";
            check((result["state"] == "succeeded") == ok && api.read(admin)["lastRestore"]["ok"] == ok, "network restore result reflects actual readiness");
            if (mode == "old-server") check(!f.phone.netd_clean, "old server exit required before netd reset");
            if (mode == "delayed") check(f.phone.clock >= f.phone.network_ready_at, "waited for network recovery");
            if (ok) check(f.index("ctl.start=netd") < f.index("ctl.start=wificond") && f.index("ctl.start=wificond") < f.index("ctl.start=zygote"), "present wificond restored in order");
        }
        {
            // The explicit zygote tier stops the app framework after the display stack and restores it via the sentinel.
            Fixture f; auto api = f.api();
            auto request = f.request("zygote-tier", "stop", api.read(admin));
            request["operation"]["tier"] = "zygote";
            auto task = f.finish(api, request);
            check(task["state"] == "succeeded" && f.sentinels.size() == 1 && f.sentinels[0]->plan.stop_zygote, "zygote tier armed");
            check(f.index("ctl.stop=vendor.qti.hardware.display.composer") < f.index("ctl.stop=zygote_secondary") &&
                f.index("ctl.stop=zygote_secondary") < f.index("ctl.stop=zygote"), "zygote stopped after display services");
            check(api.read(admin)["state"] == "stopped", "zygote tier remains owned");
            auto restore = f.request("zygote-tier-restore", "restore", api.read(admin));
            task = f.finish(api, restore);
            check(task["state"] == "succeeded" && task["androidDisplayResult"]["restored"] == true &&
                f.index("ctl.start=zygote") > f.index("ctl.stop=zygote"), "zygote tier restored");
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
