// SPDX-License-Identifier: GPL-3.0-or-later
#include "android_display.h"
#include "common/wire.h"
#include "hugepage_processes.h"
#include <algorithm>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <mutex>
#include <sstream>
#include <thread>
#include <tuple>
#ifndef _WIN32
#include "common/fd.h"
#include <cerrno>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/klog.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __ANDROID__
#include "runtime/child.h"
#include <sys/system_properties.h>
#endif
#endif

#ifdef _WIN32
// Linux signal numbers for the portable state machine; never sent on Windows.
#ifndef SIGSTOP
#define SIGSTOP 19
#endif
#ifndef SIGCONT
#define SIGCONT 18
#endif
#endif

namespace droidvm {
namespace {
using namespace std::chrono_literals;
constexpr const char* composer = "vendor.qti.hardware.display.composer";
constexpr const char* surfaceflinger = "surfaceflinger";
constexpr const char* system_suspend = "system_suspend";
constexpr const char* wake_lock_name = "droidvm_android_display";
constexpr const char* brightness_path = "/sys/class/backlight/panel0-backlight/brightness";
constexpr const char* stability_keys[] = {"scout", "nativehang", "nativehangII", "qcom_hang_task"};
constexpr const char* network_dependencies[] = {"netd", "wificond", "vendor.ipacm"};
constexpr unsigned watchdog_kick_seconds = 120;
constexpr int auto_restore_min = 60, auto_restore_max = 86400, auto_restore_default = 1800;
constexpr auto restore_wait = 180s;

void require(bool value, ErrorCode code, const std::string& message) { if (!value) throw ServiceError(code, message); }
void access(const CallContext& caller, bool mutation) {
    require(caller.authenticated && !caller.principal.empty(), ErrorCode::unauthenticated, "Authentication required");
    require(caller.administrator && (!mutation || caller.manage_tasks), ErrorCode::permission_denied, "Administrator permission required");
}
bool token(const Json::Value& value, size_t limit = 128) {
    if (!value.isString()) return false;
    const auto text = value.asString();
    return !text.empty() && text.size() <= limit && text.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-") == std::string::npos;
}
std::string trim(std::string text) {
    while (!text.empty() && static_cast<unsigned char>(text.back()) <= 0x20) text.pop_back();
    while (!text.empty() && static_cast<unsigned char>(text.front()) <= 0x20) text.erase(0, 1);
    return text;
}
std::string svc(const std::string& name) { return "init.svc." + name; }
std::string stability_key(const char* name) { return std::string("persist.sys.stability.") + name + ".enable"; }
// ctl.start/ctl.stop, then wait for init to report the state (crosvm used 8 s).
void service(const AndroidDisplayIo& io, const std::string& name, bool start) {
    io.set_property(start ? "ctl.start" : "ctl.stop", name);
    const char* wanted = start ? "running" : "stopped";
    const auto until = io.wall_ms() + 8000;
    while (io.property(svc(name)) != wanted) {
        if (io.wall_ms() >= until) throw std::runtime_error("service " + name + " did not become " + wanted);
        io.sleep(50ms);
    }
}
void signal_server(const AndroidDisplayIo& io, const AndroidDisplayPlan& plan, int number) {
    if (io.start_ticks(plan.server_pid).value_or("") != plan.server_start) throw std::runtime_error("system_server identity changed");
    io.signal(plan.server_pid, number);
}
std::optional<int> panel_brightness(const AndroidDisplayIo& io) {
    const auto text = io.read(brightness_path);
    if (!text) return std::nullopt;
    try { return std::stoi(trim(*text)); } catch (...) { return std::nullopt; }
}
std::optional<std::string> operstate(const AndroidDisplayIo& io, const std::string& interface) {
    if (interface.empty()) return std::nullopt;
    const auto text = io.read("/sys/class/net/" + interface + "/operstate");
    return text ? std::optional(trim(*text)) : std::nullopt;
}
Json::Value network_json(const AndroidDisplayIo& io, const std::string& interface) {
    if (interface.empty()) return Json::Value();
    Json::Value out; out["interface"] = interface;
    const auto state = operstate(io, interface);
    out["operstate"] = state ? Json::Value(*state) : Json::Value();
    return out;
}
}

AndroidWatchdogStatus android_display_probe_watchdog(const std::function<bool(const std::string&)>& exists,
                                                    const std::function<std::string()>& verify_hangdetect) {
    try {
        for (const char* path : {"/dev/Monitor_Hang", "/sys/class/misc/Monitor_Hang", "/sys/module/hangdetect"})
            if (exists(path)) return {true, verify_hangdetect()};
        return {false, {}};
    } catch (const std::exception& error) {
        return {true, std::string("watchdog probe: ") + error.what()};
    }
}

std::unique_ptr<AndroidWatchdog> android_display_arm_watchdog(const AndroidDisplayIo& io, const AndroidDisplayPlan& plan) {
    const auto status = io.watchdog_status();
    if (!status.reason.empty()) throw std::runtime_error(status.reason);
    if (status.required != plan.watchdog_required) throw std::runtime_error("watchdog presence changed before sentinel startup");
    if (!status.required) return {};
    auto watchdog = io.open_watchdog();
    if (!watchdog) throw std::runtime_error("watchdog adapter unavailable");
    watchdog->kick(watchdog_kick_seconds);
    return watchdog;
}

std::optional<AndroidDisplayNetwork> android_display_network(const std::string& dump) {
    std::istringstream lines(dump);
    std::string id;
    for (std::string line; std::getline(lines, line);) {
        line = trim(line);
        constexpr std::string_view prefix = "Active default network: ";
        if (line.starts_with(prefix)) { id = trim(line.substr(prefix.size())); break; }
    }
    if (id == "none") return AndroidDisplayNetwork{};
    if (id.empty() || id.find_first_not_of("0123456789") != std::string::npos) return std::nullopt;
    lines.clear(); lines.seekg(0);
    for (std::string line; std::getline(lines, line);) {
        line = trim(line);
        if (!line.starts_with("NetworkAgentInfo{network{" + id + "}")) continue;
        const auto begin = line.find("Capabilities: ");
        if (begin == std::string::npos) return std::nullopt;
        const auto caps = line.substr(begin + 14, line.find(' ', begin + 14) - (begin + 14));
        return AndroidDisplayNetwork{true, ("&" + caps + "&").find("&VALIDATED&") != std::string::npos};
    }
    return std::nullopt;
}

Json::Value AndroidDisplayPlan::json() const {
    Json::Value out;
    out["daemon_pid"] = daemon_pid; out["daemon_start"] = daemon_start;
    out["server_pid"] = server_pid; out["server_start"] = server_start;
    out["suspend_running"] = suspend_running; out["secondary_running"] = secondary_running;
    out["zygote_running"] = zygote_running; out["stop_zygote"] = stop_zygote;
    out["watchdog_required"] = watchdog_required;
    out["rescue_adapter"] = rescue_adapter;
    out["network_services"] = Json::Value(Json::arrayValue);
    for (const auto& name : network_services) out["network_services"].append(name);
    out["network_default"] = network_default; out["network_validated"] = network_validated;
    out["wifi"] = wifi;
    out["stability"] = Json::Value(Json::arrayValue);
    for (const auto& [key, value] : stability) { Json::Value row; row.append(key); row.append(value); out["stability"].append(row); }
    out["lock_directory"] = lock_directory; out["network_interface"] = network_interface;
    out["auto_restore_seconds"] = auto_restore_seconds; out["restore_on_network_loss"] = restore_on_network_loss;
    return out;
}
AndroidDisplayPlan AndroidDisplayPlan::parse(const Json::Value& value) {
    if (!value.isObject() || !value["daemon_pid"].isInt() || !value["server_pid"].isInt() || !value["stability"].isArray())
        throw std::runtime_error("invalid display plan");
    AndroidDisplayPlan plan;
    plan.daemon_pid = value["daemon_pid"].asInt(); plan.daemon_start = value["daemon_start"].asString();
    plan.server_pid = value["server_pid"].asInt(); plan.server_start = value["server_start"].asString();
    plan.suspend_running = value["suspend_running"].asBool(); plan.secondary_running = value["secondary_running"].asBool();
    plan.zygote_running = value.get("zygote_running", true).asBool(); plan.stop_zygote = value.get("stop_zygote", false).asBool();
    plan.watchdog_required = value.get("watchdog_required", true).asBool();
    plan.rescue_adapter = value.get("rescue_adapter", "").asString();
    for (const auto& name : value["network_services"]) {
        if (!name.isString() || std::find(std::begin(network_dependencies), std::end(network_dependencies), name.asString()) == std::end(network_dependencies))
            throw std::runtime_error("invalid network service in display plan");
        plan.network_services.push_back(name.asString());
    }
    plan.network_default = value.get("network_default", false).asBool();
    plan.network_validated = value.get("network_validated", false).asBool();
    plan.wifi = value["wifi"];
    for (const auto& row : value["stability"]) {
        if (!row.isArray() || row.size() != 2) throw std::runtime_error("invalid display plan");
        plan.stability.emplace_back(row[0].asString(), row[1].asString());
    }
    plan.lock_directory = value["lock_directory"].asString(); plan.network_interface = value["network_interface"].asString();
    plan.auto_restore_seconds = value["auto_restore_seconds"].asInt(); plan.restore_on_network_loss = value["restore_on_network_loss"].asBool();
    return plan;
}

void android_display_restore(const AndroidDisplayIo& io, const AndroidDisplayPlan& plan, AndroidWatchdog* watchdog,
                             const std::function<void(const std::string&)>& progress, AndroidWifiSession* wifi) {
    AndroidRescueRestart rescue(io, plan.rescue_adapter);
    // A second supplicant must never compete for the interface during boot.
    if (wifi) { progress("stop independent Wi-Fi"); wifi->stop(); }
    std::vector<std::string> failures;
    auto attempt = [&](const char* label, const std::function<void()>& work) {
        progress(label);
        if (watchdog) {
            try { watchdog->kick(watchdog_kick_seconds); }
            catch (const std::exception& error) { failures.push_back(std::string("watchdog: ") + error.what()); }
        }
        try { work(); } catch (const std::exception& error) { failures.push_back(std::string(label) + ": " + error.what()); }
    };
    // SurfaceFlinger cannot reuse the frozen framework's layer handles (it
    // crashed in a vendor library when it tried): rebuild Android userspace.
    if (plan.secondary_running) attempt("stop zygote_secondary", [&] { service(io, "zygote_secondary", false); });
    bool stopped = true;
    attempt("stop zygote", [&] {
        try { service(io, "zygote", false); }
        catch (...) {
            // init refused: do not leave the old framework frozen.
            stopped = false;
            try { signal_server(io, plan, SIGCONT); } catch (...) {}
            throw;
        }
    });
    bool framework_exited = false;
    if (stopped) attempt("old framework exit", [&] {
        const auto until = io.wall_ms() + 8000;
        while (io.start_ticks(plan.server_pid).value_or("") == plan.server_start) {
            if (io.wall_ms() >= until) throw std::runtime_error("old system_server did not exit");
            io.sleep(50ms);
        }
        framework_exited = true;
    });
    // ctl.stop/start does not run zygote's onrestart dependency actions.
    // Reset netd's old network IDs before the new ConnectivityService starts.
    // Never ctl.restart netd: its onrestart would restart zygote in turn.
    if (framework_exited) {
        for (auto it = plan.network_services.rbegin(); it != plan.network_services.rend(); ++it)
            attempt(("stop " + *it).c_str(), [&] { service(io, *it, false); });
        for (const auto& name : plan.network_services)
            attempt(("start " + name).c_str(), [&] { service(io, name, true); });
    }
    attempt("start composer", [&] { service(io, composer, true); });
    attempt("start surfaceflinger", [&] { service(io, surfaceflinger, true); });
    if (plan.zygote_running) attempt("start zygote", [&] {
        // Never alter boot accounting while the old framework may still write it.
        if (framework_exited) rescue.arm();
        try { service(io, "zygote", true); }
        catch (...) { rescue.cancel(); throw; }
    });
    if (plan.secondary_running) attempt("start zygote_secondary", [&] { service(io, "zygote_secondary", true); });
    attempt("wake unlock", [&] { io.write("/sys/power/wake_unlock", wake_lock_name); });
    if (plan.suspend_running) attempt("start system_suspend", [&] { service(io, system_suspend, true); });
    for (const auto& [key, value] : plan.stability) attempt(key.c_str(), [&] { io.set_property(key, value); });
    // SystemServer startup itself needs suspend/secondary services. Waiting for
    // noteBoot before restoring those dependencies would stall its registration.
    attempt("verify controlled framework restart", [&] { rescue.finish(plan.server_pid, plan.server_start); });
    // "running" only means init forked a process: require the compositor boot
    // handshake and ten seconds without a display/framework restart.
    // Even if accounting or another step reported an error, keep feeding the
    // hardware watchdog while the restored framework boots. Earlier failures
    // still fail the receipt; they must not skip recovery/readiness work.
    attempt("verify framework", [&] {
        const auto sf_pid = io.property("init.svc_debug_pid." + std::string(surfaceflinger));
        const auto composer_pid = io.property("init.svc_debug_pid." + std::string(composer));
        if (sf_pid.empty() || composer_pid.empty()) throw std::runtime_error("missing restored service PID");
        const auto deadline = io.wall_ms() + 90000;
        std::optional<std::tuple<int, std::string, uint64_t>> stable;
        bool network_ready = false;
        for (;;) {
            if (watchdog) watchdog->kick(watchdog_kick_seconds);
            if (io.property(svc(surfaceflinger)) != "running" || io.property(svc(composer)) != "running" ||
                io.property("init.svc_debug_pid." + std::string(surfaceflinger)) != sf_pid ||
                io.property("init.svc_debug_pid." + std::string(composer)) != composer_pid)
                throw std::runtime_error("Android display service died during restoration");
            std::optional<std::pair<int, std::string>> server;
            for (const int pid : io.processes("system_server"))
                if (const auto start = io.start_ticks(pid)) server = std::pair{pid, *start};
            const bool ready = io.property("service.bootanim.exit") == "1" && io.property(svc("bootanim")) == "stopped" &&
                io.property("sys.boot_completed") == "1";
            if (server) {
                if (server->first == plan.server_pid && server->second == plan.server_start)
                    throw std::runtime_error("old system_server survived framework restart");
                if (stable) {
                    const auto& [pid, start, since] = *stable;
                    if (pid != server->first || start != server->second || !ready) throw std::runtime_error("Android framework became unstable after boot");
                    if (io.wall_ms() - since >= 10000) {
                        progress("verify network");
                        std::optional<AndroidDisplayNetwork> network;
                        try { network = io.network_status(); } catch (const std::exception&) {}
                        network_ready = network && (!plan.network_default || network->default_present) &&
                            (!plan.network_validated || network->validated);
                        if (network_ready) return;
                    }
                } else if (ready) stable = std::tuple{server->first, server->second, io.wall_ms()};
            } else if (stable) throw std::runtime_error("Android framework exited after boot");
            if (io.wall_ms() >= deadline) throw std::runtime_error(stable && !network_ready ?
                "Android default network/validation did not recover within 90 seconds" : "Android framework boot did not complete within 90 seconds");
            io.sleep(1s);
        }
    });
    if (!failures.empty()) {
        std::string joined;
        for (const auto& failure : failures) joined += (joined.empty() ? "" : "; ") + failure;
        throw std::runtime_error("restoration failed: " + joined);
    }
}

struct AndroidDisplayService::Impl : std::enable_shared_from_this<Impl> {
    enum class Phase { idle, stopping, stopped, restoring };
    TaskService& tasks;
    AndroidDisplayIo io;
    std::mutex mutex;
    std::condition_variable changed;
    Phase phase = Phase::idle;
    std::string owner_kind, owner_vm, owner_name, progress, network_interface;
    uint64_t revision = 1, since = 0, restore_at = 0;
    bool restore_on_network_loss = false;
    Json::Value last_restore;
    std::shared_ptr<AndroidSentinel> sentinel;
    std::thread reader;
    std::optional<std::pair<uint64_t, AndroidWatchdogStatus>> watchdog_cache; // observed at, status
    // The ABI check cannot see the driver's caller check; only the sentinel's
    // first kick, made before any mutation, proves this daemon may feed it.
    std::string watchdog_kick = "unproven", kick_rejection;
    Impl(TaskService& service, AndroidDisplayIo options) : tasks(service), io(std::move(options)) {
        if (io.android) require(io.property && io.set_property && io.read && io.write && io.processes && io.self_pid && io.start_ticks &&
            io.stopped && io.signal && io.sleep && io.wall_ms && io.uptime_ms && io.default_interface && io.network_status && io.wifi_plan && io.prepare_wifi && io.watchdog_status && io.rescue_status && io.open_watchdog && io.spawn_sentinel,
            ErrorCode::unavailable, "Android display IO is incomplete");
        if (!io.wall_ms) io.wall_ms = [] {
            return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        };
    }
    ~Impl() {
        // The reader thread may hold the last reference and destroy this Impl itself.
        if (!reader.joinable()) return;
        if (reader.get_id() == std::this_thread::get_id()) reader.detach();
        else reader.join();
    }
    static const char* phase_name(Phase phase) {
        switch (phase) {
            case Phase::stopping: return "stopping";
            case Phase::stopped: return "stopped";
            case Phase::restoring: return "restoring";
            default: return "android";
        }
    }
    AndroidWatchdogStatus watchdog_status_cached() {
        const auto now = io.wall_ms();
        if (!watchdog_cache || now - watchdog_cache->first > 30000) {
            const auto status = io.watchdog_status();
            if (watchdog_cache && watchdog_cache->second.required != status.required) watchdog_kick = "unproven";
            watchdog_cache = std::pair{now, status};
        }
        return watchdog_cache->second;
    }
    AndroidWatchdogStatus watchdog_status() {
        if (watchdog_kick == "rejected") return {true, "hangdetect rejected DroidVM's kick: " + kick_rejection};
        return watchdog_status_cached();
    }
    void join_reader_locked() { if (reader.joinable() && phase == Phase::idle) reader.join(); }
    Json::Value snapshot_locked() {
        Json::Value out;
        out["capability"] = AndroidDisplayService::capability;
        out["supported"] = io.android;
        out["expected"]["revision"] = std::to_string(revision);
        out["state"] = phase_name(phase);
        if (owner_kind.empty()) out["owner"] = Json::Value();
        else {
            out["owner"]["kind"] = owner_kind;
            out["owner"]["vmId"] = owner_vm.empty() ? Json::Value() : Json::Value(owner_vm);
            out["owner"]["vmName"] = owner_name.empty() ? Json::Value() : Json::Value(owner_name);
        }
        out["sinceMs"] = since ? Json::Value(std::to_string(since)) : Json::Value();
        out["autoRestoreAtMs"] = restore_at ? Json::Value(std::to_string(restore_at)) : Json::Value();
        out["restoreOnNetworkLoss"] = restore_on_network_loss;
        out["progress"] = progress;
        out["lastRestore"] = last_restore;
        if (!io.android) {
            out["network"] = Json::Value(); out["panelLit"] = Json::Value();
            out["watchdog"]["verified"] = false; out["watchdog"]["reason"] = "unsupported-host"; out["watchdog"]["kick"] = "unproven";
            out["services"]["surfaceflinger"] = ""; out["services"]["composer"] = "";
            return out;
        }
        out["network"] = network_json(io, phase == Phase::idle ? io.default_interface() : network_interface);
        const auto brightness = panel_brightness(io);
        out["panelLit"] = brightness ? Json::Value(*brightness > 0) : Json::Value();
        const auto watchdog = phase == Phase::idle ? watchdog_status() : AndroidWatchdogStatus{watchdog_kick != "not-required", {}};
        out["watchdog"]["verified"] = watchdog.reason.empty();
        out["watchdog"]["reason"] = watchdog.reason.empty() ? Json::Value() : Json::Value(watchdog.reason);
        out["watchdog"]["kick"] = watchdog.required ? watchdog_kick : "not-required";
        out["services"]["surfaceflinger"] = io.property(svc(surfaceflinger));
        out["services"]["composer"] = io.property(svc(composer));
        return out;
    }
    void set_progress(const std::string& text) { std::lock_guard lock(mutex); progress = text; }
    // Reader thread: the sentinel reports progress and the final outcome.
    void watch_sentinel(std::shared_ptr<AndroidSentinel> handle) {
        std::string outcome = "failed sentinel exited without a result";
        for (;;) {
            const auto line = handle->read_line(1s);
            if (!line) continue;
            if (line->empty()) break;
            if (line->starts_with("progress ")) { set_progress(line->substr(9)); continue; }
            if (*line == "restored" || line->starts_with("failed ")) { outcome = *line; break; }
        }
        std::lock_guard lock(mutex);
        Json::Value result;
        result["ok"] = outcome == "restored";
        result["uncertain"] = outcome.starts_with("failed sentinel");
        result["message"] = outcome == "restored" ? Json::Value() : Json::Value(outcome.substr(7));
        result["atMs"] = std::to_string(io.wall_ms());
        last_restore = result;
        phase = Phase::idle; owner_kind.clear(); owner_vm.clear(); owner_name.clear(); progress.clear();
        since = 0; restore_at = 0; network_interface.clear();
        sentinel.reset();
        ++revision;
        changed.notify_all();
    }
    // The stop sequence. Restoration is armed (sentinel ready) before the first
    // mutation; a partial failure hands the partial state to the sentinel.
    void begin(const std::string& kind, const std::string& vm_id, const std::string& vm_name, int auto_restore, bool network_loss, bool stop_zygote = false) {
        AndroidDisplayPlan plan;
        std::shared_ptr<AndroidSentinel> handle;
        {
            std::unique_lock lock(mutex);
            require(io.android, ErrorCode::unavailable, "Android display takeover is not available on this host");
            require(phase == Phase::idle, ErrorCode::conflict, "Android display is already stopped or being restored");
            join_reader_locked();
            require(io.property(svc(surfaceflinger)) == "running", ErrorCode::unavailable, "SurfaceFlinger is not running");
            require(io.property(svc(composer)) == "running", ErrorCode::unavailable, "display composer is not running");
            const auto servers = io.processes("system_server");
            require(servers.size() == 1, ErrorCode::unavailable, "expected exactly one system_server");
            require(!io.stopped(servers[0]), ErrorCode::unavailable, "system_server is already frozen");
            const auto brightness = panel_brightness(io);
            require(brightness && *brightness > 0, ErrorCode::unavailable, "the Android panel is dark; wake the screen first");
            const auto watchdog = watchdog_status();
            require(watchdog.reason.empty(), ErrorCode::unavailable, "Android watchdog unavailable: " + watchdog.reason);
            plan.watchdog_required = watchdog.required;
            const auto rescue = io.rescue_status();
            require(rescue.reason.empty(), ErrorCode::unavailable, rescue.reason);
            plan.rescue_adapter = rescue.adapter;
            plan.daemon_pid = io.self_pid();
            plan.daemon_start = io.start_ticks(plan.daemon_pid).value_or("");
            plan.server_pid = servers[0];
            plan.server_start = io.start_ticks(servers[0]).value_or("");
            require(!plan.server_start.empty(), ErrorCode::unavailable, "system_server identity unavailable");
            plan.suspend_running = io.property(svc(system_suspend)) == "running";
            plan.secondary_running = io.property(svc("zygote_secondary")) == "running";
            plan.zygote_running = io.property(svc("zygote")) == "running";
            require(plan.zygote_running, ErrorCode::unavailable, "zygote is not running");
            plan.stop_zygote = stop_zygote;
            for (const char* name : network_dependencies)
                if (io.property(svc(name)) == "running") plan.network_services.emplace_back(name);
            const auto network = io.network_status();
            require(network.has_value(), ErrorCode::unavailable, "Android default network status unavailable");
            plan.network_default = network->default_present; plan.network_validated = network->validated;
            for (const char* name : stability_keys) plan.stability.emplace_back(stability_key(name), io.property(stability_key(name)));
            plan.network_interface = io.default_interface();
            if (plan.stop_zygote) {
                plan.wifi = io.wifi_plan();
                if (!plan.wifi.isNull()) plan.network_interface = plan.wifi["interface"].asString();
            }
            plan.auto_restore_seconds = auto_restore;
            plan.restore_on_network_loss = network_loss && !plan.network_interface.empty();
            phase = Phase::stopping; owner_kind = kind; owner_vm = vm_id; owner_name = vm_name;
            progress = "arming"; network_interface = plan.network_interface;
            restore_on_network_loss = plan.restore_on_network_loss;
            ++revision;
        }
        auto fail = [&](const std::string& message, bool armed) {
            std::lock_guard lock(mutex);
            if (armed) {
                phase = Phase::restoring; progress = "restoring";
                handle->send("restore");
                sentinel = handle;
                if (reader.joinable()) reader.join();
                reader = std::thread([self = shared_from_this(), handle] { self->watch_sentinel(handle); });
            } else {
                phase = Phase::idle; owner_kind.clear(); owner_vm.clear(); owner_name.clear(); progress.clear();
                network_interface.clear(); ++revision;
            }
            changed.notify_all();
            throw ServiceError(ErrorCode::unavailable, message);
        };
        try {
            handle = io.spawn_sentinel(plan);
            const auto ready = handle->read_line(10s);
            if (!ready || *ready != "ready") {
                std::string reason = ready && ready->starts_with("failed ") ? ready->substr(7) : "sentinel did not become ready";
                handle->close();
                if (reason.starts_with("hangdetect kick: ")) {
                    std::lock_guard lock(mutex);
                    watchdog_kick = "rejected"; kick_rejection = reason.substr(17);
                }
                fail("Android display sentinel: " + reason, false);
            }
            std::lock_guard lock(mutex);
            watchdog_kick = plan.watchdog_required ? "accepted" : "not-required";
        } catch (const ServiceError&) { throw; }
        catch (const std::exception& error) { fail(std::string("Android display sentinel: ") + error.what(), false); }
        try {
            set_progress("wake lock");
            io.write("/sys/power/wake_lock", wake_lock_name);
            if (plan.suspend_running) { set_progress("stop system_suspend"); service(io, system_suspend, false); }
            for (const auto& [key, value] : plan.stability) io.set_property(key, "false");
            set_progress("freeze system_server");
            signal_server(io, plan, SIGSTOP);
            // The panel may have blanked while the framework was still alive.
            const auto brightness = panel_brightness(io);
            if (!brightness || *brightness <= 0) throw std::runtime_error("the Android panel went dark before the display stack was stopped");
            set_progress("stop surfaceflinger");
            service(io, surfaceflinger, false);
            // Stopping SF makes init restart the HAL once; let that settle first.
            io.sleep(2s);
            set_progress("stop composer");
            service(io, composer, false);
            if (plan.stop_zygote) {
                set_progress("stop zygote_secondary");
                if (plan.secondary_running) service(io, "zygote_secondary", false);
                set_progress("stop zygote");
                service(io, "zygote", false);
                const auto until = io.wall_ms() + 8000;
                while (io.start_ticks(plan.server_pid).value_or("") == plan.server_start) {
                    if (io.wall_ms() >= until) throw std::runtime_error("system_server did not exit after stopping zygote");
                    io.sleep(50ms);
                }
                if (!plan.wifi.isNull()) {
                    set_progress("connect independent Wi-Fi");
                    handle->send("start-wifi");
                    const auto ready = handle->read_line(65s);
                    if (!ready || *ready != "wifi-ready") throw std::runtime_error(
                        ready && ready->starts_with("wifi-failed ") ? ready->substr(12) : "independent Wi-Fi did not become ready");
                }
            }
        } catch (const std::exception& error) { fail(std::string("Android display stop failed, restoring: ") + error.what(), true); }
        std::lock_guard lock(mutex);
        phase = Phase::stopped; progress = "stopped";
        since = io.wall_ms();
        restore_at = auto_restore > 0 ? since + static_cast<uint64_t>(auto_restore) * 1000 : 0;
        sentinel = handle;
        if (reader.joinable()) reader.join();
        reader = std::thread([self = shared_from_this(), handle] { self->watch_sentinel(handle); });
        changed.notify_all();
    }
    bool release_locked() {
        if (phase != Phase::stopped || !sentinel) return false;
        phase = Phase::restoring; progress = "restoring";
        sentinel->send("restore");
        changed.notify_all();
        return true;
    }
    Json::Value receipt(const Json::Value& expected, const std::string& kind) {
        Json::Value out;
        out["expected"] = expected; out["kind"] = kind;
        out["state"] = phase_name(phase); out["stopped"] = false; out["restored"] = false; out["uncertain"] = false;
        out["revision"] = Json::Value(); out["network"] = Json::Value(); out["message"] = Json::Value();
        return out;
    }
    TaskCompletion execute(const Json::Value& request, TaskControl& control) {
        const auto& operation = request["operation"];
        const auto kind = operation["kind"].asString();
        Json::Value result;
        { std::lock_guard lock(mutex); result = receipt(request["expected"], kind); }
        try {
            {
                std::lock_guard lock(mutex);
                require(request["expected"]["revision"] == std::to_string(revision), ErrorCode::conflict, "Android display state changed; refresh before retrying");
                if (kind == "restore") {
                    require(phase == Phase::stopped || phase == Phase::restoring, ErrorCode::conflict, "Android display is not stopped");
                    require(owner_kind == "manual", ErrorCode::conflict, "The display is owned by a running VM; stop that VM instead");
                }
            }
            if (!control.enter_commit()) return TaskCompletion::cancelled(result);
            if (kind == "stop") {
                const int auto_restore = operation.get("autoRestoreSeconds", auto_restore_default).asInt();
                begin("manual", "", "", auto_restore, operation.get("restoreOnNetworkLoss", true).asBool(), operation.get("tier", "display") == "zygote");
                std::lock_guard lock(mutex);
                result["state"] = phase_name(phase); result["stopped"] = true;
                result["revision"] = std::to_string(revision); result["network"] = network_json(io, network_interface);
                return TaskCompletion::success(result);
            }
            std::unique_lock lock(mutex);
            release_locked();
            const bool done = changed.wait_for(lock, restore_wait, [&] { return phase == Phase::idle; });
            result["state"] = phase_name(phase);
            result["revision"] = std::to_string(revision);
            if (!done) {
                result["uncertain"] = true; result["message"] = "restoration still running";
                return TaskCompletion::failure(ErrorCode::commit_uncertain, "Android restoration did not finish in time; keep watching the state", result);
            }
            result["restored"] = last_restore["ok"].asBool(); result["uncertain"] = last_restore["uncertain"].asBool();
            result["message"] = last_restore["message"]; result["network"] = network_json(io, io.default_interface());
            if (!result["restored"].asBool())
                return TaskCompletion::failure(result["uncertain"].asBool() ? ErrorCode::commit_uncertain : ErrorCode::unavailable,
                    "Android restoration reported a failure", result);
            return TaskCompletion::success(result);
        } catch (const ServiceError& error) {
            std::lock_guard lock(mutex);
            result["state"] = phase_name(phase); result["message"] = error.what();
            return TaskCompletion::failure(error.code(), error.what(), result);
        } catch (const std::exception& error) {
            std::lock_guard lock(mutex);
            result["state"] = phase_name(phase); result["message"] = error.what();
            return TaskCompletion::failure(ErrorCode::internal, error.what(), result);
        }
    }
};

namespace {
struct Lease final : vm::AndroidDisplayLease {
    std::shared_ptr<AndroidDisplayService::Impl> impl;
    explicit Lease(std::shared_ptr<AndroidDisplayService::Impl> owner) : impl(std::move(owner)) {}
    void watch(int pid) override {
        std::lock_guard lock(impl->mutex);
        if (impl->sentinel && impl->phase == AndroidDisplayService::Impl::Phase::stopped) impl->sentinel->send("watch " + std::to_string(pid));
    }
    ~Lease() override {
        std::lock_guard lock(impl->mutex);
        impl->release_locked();
    }
};
void validate(const Json::Value& request) {
    require(request.isObject() && request.size() == 3 && token(request["requestId"]), ErrorCode::invalid_argument, "Invalid Android display request");
    require(request["expected"].isObject() && request["expected"].size() == 1 && token(request["expected"]["revision"]), ErrorCode::invalid_argument, "Expected revision required");
    const auto& operation = request["operation"];
    require(operation.isObject() && operation["kind"].isString(), ErrorCode::invalid_argument, "Expected Android display operation");
    const auto kind = operation["kind"].asString();
    if (kind == "stop") {
        for (const auto& key : operation.getMemberNames())
            require(key == "kind" || key == "tier" || key == "autoRestoreSeconds" || key == "restoreOnNetworkLoss", ErrorCode::invalid_argument, "Unexpected stop field");
        if (operation.isMember("tier"))
            require(operation["tier"].isString() && (operation["tier"] == "display" || operation["tier"] == "zygote"),
                ErrorCode::invalid_argument, "tier must be display or zygote");
        if (operation.isMember("autoRestoreSeconds"))
            require(operation["autoRestoreSeconds"].isInt() && operation["autoRestoreSeconds"].asInt() >= auto_restore_min &&
                operation["autoRestoreSeconds"].asInt() <= auto_restore_max, ErrorCode::invalid_argument, "autoRestoreSeconds must be 60 to 86400");
        if (operation.isMember("restoreOnNetworkLoss")) require(operation["restoreOnNetworkLoss"].isBool(), ErrorCode::invalid_argument, "restoreOnNetworkLoss must be boolean");
    } else require(kind == "restore" && operation.size() == 1, ErrorCode::invalid_argument, "Unsupported Android display operation");
}
}

AndroidDisplayService::AndroidDisplayService(TaskService& tasks, AndroidDisplayIo io) : impl_(std::make_shared<Impl>(tasks, std::move(io))) {}
AndroidDisplayService::~AndroidDisplayService() {
    std::shared_ptr<AndroidSentinel> handle;
    {
        std::lock_guard lock(impl_->mutex);
        // A stopped manual session must not outlive the daemon unrestored.
        impl_->release_locked();
        handle = impl_->sentinel;
    }
    if (handle) handle->close(); // the detached sentinel finishes on its own
}
Json::Value AndroidDisplayService::snapshot(const CallContext& caller) {
    access(caller, false);
    std::lock_guard lock(impl_->mutex);
    impl_->join_reader_locked();
    return impl_->snapshot_locked();
}
TaskView AndroidDisplayService::start(const CallContext& caller, const Json::Value& request) {
    access(caller, true);
    validate(request);
    TaskSpec spec; spec.kind = "android_display"; spec.resource = "android-display";
    spec.request_id = request["requestId"].asString(); spec.request_signature = wire::stringify(request);
    spec.result_bytes = 8192; spec.background = true;
    const auto ref = impl_->tasks.submit(caller, std::move(spec), [impl = impl_, request](TaskControl& control) { return impl->execute(request, control); });
    return impl_->tasks.get(caller, ref);
}
TaskView AndroidDisplayService::status(const CallContext& caller, const std::string& request_id) {
    access(caller, true);
    require(token(Json::Value(request_id)), ErrorCode::invalid_argument, "Invalid request id");
    const auto found = impl_->tasks.find_request(caller, request_id);
    require(found.has_value(), ErrorCode::task_not_found, "Unknown Android display request");
    return *found;
}
std::unique_ptr<vm::AndroidDisplayLease> AndroidDisplayService::acquire(const std::string& vm_id, const std::string& vm_name, bool stop_zygote) {
    try { impl_->begin("vm", vm_id, vm_name, 0, false, stop_zygote); }
    catch (const ServiceError& error) { throw std::runtime_error(error.what()); }
    return std::make_unique<Lease>(impl_);
}
bool AndroidDisplayService::drain(std::chrono::milliseconds timeout) {
    std::unique_lock lock(impl_->mutex);
    return impl_->changed.wait_for(lock, timeout, [&] { return impl_->phase == Impl::Phase::idle; });
}

#ifndef _WIN32
namespace {
std::optional<std::string> read_small(const std::string& path) {
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return std::nullopt;
    std::string bytes; char buffer[4096];
    for (;;) {
        const auto count = read(fd, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0 || bytes.size() > 65536) break;
        bytes.append(buffer, static_cast<size_t>(count));
    }
    close(fd);
    return bytes;
}
void write_small(const std::string& path, const std::string& value) {
    const int fd = open(path.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) throw std::runtime_error("open " + path + ": " + std::strerror(errno));
    const auto count = write(fd, value.data(), value.size());
    const int saved = errno;
    close(fd);
    if (count < 0 || static_cast<size_t>(count) != value.size()) throw std::runtime_error("write " + path + ": " + std::strerror(saved));
}
std::string property_get(const std::string& key) {
#ifdef __ANDROID__
    char value[PROP_VALUE_MAX] = {};
    const int n = __system_property_get(key.c_str(), value);
    return n > 0 ? std::string(value, static_cast<size_t>(n)) : std::string();
#else
    (void)key; return {};
#endif
}
void property_set(const std::string& key, const std::string& value) {
#ifdef __ANDROID__
    if (__system_property_set(key.c_str(), value.c_str()) != 0) throw std::runtime_error("setting property " + key + " failed");
#else
    throw std::runtime_error("property " + key + "=" + value + " unavailable off Android");
#endif
}
std::vector<int> processes_by_comm(const std::string& comm) {
    std::vector<int> out;
    DIR* dir = opendir("/proc");
    if (!dir) return out;
    while (auto* entry = readdir(dir)) {
        char* end = nullptr;
        const long pid = std::strtol(entry->d_name, &end, 10);
        if (!end || *end || pid <= 0) continue;
        const auto name = read_small("/proc/" + std::string(entry->d_name) + "/comm");
        if (name && trim(*name) == comm) out.push_back(static_cast<int>(pid));
    }
    closedir(dir);
    std::sort(out.begin(), out.end());
    return out;
}
bool process_stopped(int pid) {
    const auto status = read_small("/proc/" + std::to_string(pid) + "/status");
    if (!status) return false;
    std::istringstream lines(*status);
    for (std::string line; std::getline(lines, line);)
        if (line.starts_with("State:")) return line.find("T (") != std::string::npos || line.find("t (") != std::string::npos;
    return false;
}
std::string default_route_interface() {
    const auto table = read_small("/proc/net/route");
    if (!table) return {};
    std::istringstream lines(*table);
    std::string header; std::getline(lines, header);
    for (std::string line; std::getline(lines, line);) {
        std::istringstream fields(line);
        std::string iface, destination;
        if (fields >> iface >> destination && destination == "00000000") return iface;
    }
    return {};
}
// Verified against warsaw OS4.0.0.7's hangdetect.ko: HANG_KICK takes a scalar
// timeout in seconds despite its _IOR encoding. Other builds fail closed.
constexpr unsigned long hang_kick = 0x8004700a;
constexpr const char* verified_build = "OS4.0.0.7.XHPCNXM";
struct HangdetectState { double timestamp = 0; unsigned remaining = 0, total = 0; bool armed = false; };
std::string hangdetect_status(HangdetectState* state) {
    if (property_get("ro.build.version.incremental") != verified_build) return "hangdetect ABI unverified on this Android build";
    std::vector<char> log(4u << 20);
    const int n = klogctl(3, log.data(), static_cast<int>(log.size()));
    if (n < 0) return std::string("read kernel log: ") + std::strerror(errno);
    std::string text(log.data(), static_cast<size_t>(n));
    const auto at = text.rfind("hang_detect thread counts down ");
    if (at == std::string::npos) return "no hangdetect status in the kernel log";
    const auto line_start = text.rfind('\n', at);
    const auto line_end = text.find('\n', at);
    const auto line = text.substr(line_start == std::string::npos ? 0 : line_start + 1, line_end == std::string::npos ? std::string::npos : line_end - (line_start == std::string::npos ? 0 : line_start + 1));
    const auto open = line.find('['), close = line.find(']');
    if (open == std::string::npos || close == std::string::npos || close < open) return "kernel timestamp missing";
    double timestamp = 0;
    try { timestamp = std::stod(trim(line.substr(open + 1, close - open - 1))); } catch (...) { return "kernel timestamp invalid"; }
    // printk timestamps exclude suspend; CLOCK_MONOTONIC matches them.
    timespec now{};
    clock_gettime(CLOCK_MONOTONIC, &now);
    const double uptime = static_cast<double>(now.tv_sec) + static_cast<double>(now.tv_nsec) / 1e9;
    if (uptime - timestamp < 0 || uptime - timestamp > 45) return "stale hangdetect status";
    const auto counts = line.substr(line.find("counts down ") + 12);
    const auto comma = counts.find(", status ");
    if (comma == std::string::npos) return "hangdetect state missing";
    const auto pair = counts.substr(0, comma), status = counts.substr(comma + 9);
    const auto colon = pair.find(':');
    if (colon == std::string::npos) return "hangdetect timeout missing";
    unsigned remaining = 0, total = 0;
    try { remaining = static_cast<unsigned>(std::stoul(pair.substr(0, colon))); total = static_cast<unsigned>(std::stoul(trim(pair.substr(colon + 1)))); }
    catch (...) { return "hangdetect counter invalid"; }
    const bool armed = !status.starts_with("0.");
    if (armed && !(status.starts_with("1.") && remaining >= 3 && total >= 3 && total <= 120)) return "unsafe or unsupported hangdetect counter: " + status;
    if (state) *state = {timestamp, remaining, total, armed};
    return {};
}
class Hangdetect final : public AndroidWatchdog {
public:
    Hangdetect() {
        HangdetectState state;
        const auto status = hangdetect_status(&state);
        if (!status.empty()) throw std::runtime_error(status);
        device_ = Fd(open("/dev/Monitor_Hang", O_RDWR | O_CLOEXEC));
        if (device_.get() < 0) throw std::runtime_error(std::string("open /dev/Monitor_Hang: ") + std::strerror(errno));
        restore_seconds_ = state.armed ? state.total * 30 : 0;
    }
    ~Hangdetect() override { try { restore(); } catch (...) {} }
    void kick(unsigned seconds) override {
        // The verified ioctl takes a scalar, not a pointer; only bounded values.
        if (ioctl(device_.get(), hang_kick, static_cast<unsigned long>(seconds)) != 0)
            throw std::runtime_error(std::string("hangdetect kick: ") + std::strerror(errno));
    }
    void restore() override {
        if (!restore_seconds_) return;
        kick(*restore_seconds_);
        restore_seconds_.reset();
    }
private:
    Fd device_;
    std::optional<unsigned> restore_seconds_;
};
// Double-forked so the sentinel is reparented to init and survives this
// daemon; the pipes are its only link. Nothing here ever kills it.
class RealSentinel final : public AndroidSentinel {
public:
    RealSentinel(const std::string& executable, const AndroidDisplayPlan& plan) {
        int in[2], out[2];
        if (pipe2(in, O_CLOEXEC) != 0) throw std::runtime_error(std::string("pipe: ") + std::strerror(errno));
        if (pipe2(out, O_CLOEXEC) != 0) { ::close(in[0]); ::close(in[1]); throw std::runtime_error(std::string("pipe: ") + std::strerror(errno)); }
        const pid_t child = fork();
        if (child < 0) { ::close(in[0]); ::close(in[1]); ::close(out[0]); ::close(out[1]); throw std::runtime_error(std::string("fork: ") + std::strerror(errno)); }
        if (child == 0) {
            const pid_t grandchild = fork();
            if (grandchild != 0) _exit(grandchild < 0 ? 1 : 0);
            setsid();
            dup2(in[0], 0); dup2(out[1], 1);
            const int null = open("/dev/null", O_WRONLY);
            if (null >= 0) dup2(null, 2);
            signal(SIGPIPE, SIG_IGN);
            // The verified hangdetect driver authorizes kicks by the cmdline
            // system-path prefix. Only the sentinel uses this argv[0]; exec
            // still loads the actual DroidVM executable supplied above.
            execl(executable.c_str(), plan.watchdog_required ? "/system/bin/droidvmd-android-sentinel" : "droidvmd-android-sentinel",
                  "--android-display-sentinel", static_cast<char*>(nullptr));
            _exit(127);
        }
        ::close(in[0]); ::close(out[1]);
        int status = 0;
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
        input_ = Fd(in[1]); output_ = Fd(out[0]);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) throw std::runtime_error("sentinel fork failed");
        send_raw(wire::stringify(plan.json()) + "\n");
    }
    void send(const std::string& line) override { send_raw(line + "\n"); }
    std::optional<std::string> read_line(std::chrono::milliseconds timeout) override {
        std::lock_guard lock(mutex_);
        for (;;) {
            const auto newline = buffer_.find('\n');
            if (newline != std::string::npos) { auto line = buffer_.substr(0, newline); buffer_.erase(0, newline + 1); return line; }
            if (output_.get() < 0) return std::string();
            pollfd event{output_.get(), POLLIN, 0};
            const int ready = poll(&event, 1, static_cast<int>(timeout.count()));
            if (ready < 0 && errno == EINTR) continue;
            if (ready == 0) return std::nullopt;
            char chunk[1024];
            const auto count = read(output_.get(), chunk, sizeof(chunk));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) { output_ = Fd(); return std::string(); }
            buffer_.append(chunk, static_cast<size_t>(count));
        }
    }
    void close() override { std::lock_guard lock(mutex_); input_ = Fd(); output_ = Fd(); }
private:
    std::mutex mutex_;
    Fd input_, output_;
    std::string buffer_;
    void send_raw(const std::string& bytes) {
        if (input_.get() < 0) return;
        size_t offset = 0;
        while (offset < bytes.size()) {
            const auto count = write(input_.get(), bytes.data() + offset, bytes.size() - offset);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) return; // the sentinel is gone; its own watchdog restores
            offset += static_cast<size_t>(count);
        }
    }
};
}

AndroidDisplayIo android_display_real_io(std::string executable, std::string lock_directory) {
    AndroidDisplayIo io;
#ifdef __ANDROID__
    io.android = true;
#endif
    io.property = property_get;
    io.set_property = property_set;
    io.read = read_small;
    io.write = write_small;
    io.processes = processes_by_comm;
    io.self_pid = [] { return static_cast<int>(getpid()); };
    io.start_ticks = [](int pid) { return hugepage_process_start_ticks(pid); };
    io.stopped = process_stopped;
    io.signal = [](int pid, int number) { if (kill(pid, number) != 0) throw std::runtime_error(std::string("kill: ") + std::strerror(errno)); };
    io.sleep = [](std::chrono::milliseconds duration) { std::this_thread::sleep_for(duration); };
    io.wall_ms = [] { return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()); };
    io.uptime_ms = [] {
        timespec now{};
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) throw std::runtime_error("cannot read Android uptime");
        return static_cast<uint64_t>(now.tv_sec) * 1000 + static_cast<uint64_t>(now.tv_nsec) / 1000000;
    };
    io.default_interface = default_route_interface;
    io.wifi_plan = android_wifi_plan;
    io.prepare_wifi = android_wifi_prepare;
    io.network_status = []() -> std::optional<AndroidDisplayNetwork> {
#ifdef __ANDROID__
        ChildOptions options; options.argv = {"/system/bin/dumpsys", "-t", "2", "connectivity"};
        Child child(options);
        const auto result = child.communicate({}, 3s, 1u << 20);
        if (result.exit_code != 0 || result.timed_out || result.truncated) return std::nullopt;
        return android_display_network(result.output);
#else
        return std::nullopt;
#endif
    };
    io.watchdog_status = [] {
        return android_display_probe_watchdog([](const std::string& path) {
            struct stat info{};
            if (lstat(path.c_str(), &info) == 0) return true;
            if (errno == ENOENT) return false;
            throw std::runtime_error("inspect " + path + ": " + std::strerror(errno));
        }, [] { return hangdetect_status(nullptr); });
    };
    io.open_watchdog = [] { return std::make_unique<Hangdetect>(); };
    io.rescue_status = []() -> AndroidRescueStatus {
#ifdef __ANDROID__
        return android_rescue_probe([](const std::string& path) {
            struct stat info{};
            if (stat(path.c_str(), &info) == 0) return true;
            if (errno == ENOENT) return false;
            throw std::runtime_error("cannot inspect crash recovery module");
        }, [](const std::string& path) {
            ChildOptions options; options.argv = {"/system/bin/sha256sum", path};
            Child child(options);
            const auto result = child.communicate({}, 3s, 1024);
            if (result.exit_code != 0 || result.timed_out || result.truncated) throw std::runtime_error("cannot verify crash recovery module fingerprint");
            return result.output.substr(0, result.output.find(' '));
        }, property_get);
#else
        return {};
#endif
    };
    io.spawn_sentinel = [executable, lock_directory](const AndroidDisplayPlan& plan) -> std::unique_ptr<AndroidSentinel> {
        auto copy = plan;
        if (copy.lock_directory.empty()) copy.lock_directory = lock_directory;
        return std::make_unique<RealSentinel>(executable, copy);
    };
    return io;
}

int android_display_sentinel_main() {
    signal(SIGPIPE, SIG_IGN);
    auto say = [](const std::string& line) { const auto text = line + "\n"; (void)!write(1, text.data(), text.size()); };
    auto fail = [&](const std::string& message) { say("failed " + message); return 1; };
    std::string line;
    for (char c; read(0, &c, 1) == 1 && c != '\n';) line.push_back(c);
    AndroidDisplayPlan plan;
    try { plan = AndroidDisplayPlan::parse(wire::parse(line)); } catch (const std::exception& error) { return fail(error.what()); }
    const auto io = android_display_real_io("/proc/self/exe", plan.lock_directory);
    // Never let two sentinels restore over each other, including a standalone
    // crosvm takeover=display session, which holds the second lock file.
    std::vector<Fd> locks;
    for (const auto& path : {plan.lock_directory + "/android-display.lock", std::string("/data/local/tmp/crosvm-kms.lock")}) {
        Fd lock(open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600));
        if (lock.get() < 0) return fail("open " + path + ": " + std::strerror(errno));
        if (flock(lock.get(), LOCK_EX | LOCK_NB) != 0) return fail("another display session owns the panel (" + path + ")");
        locks.push_back(std::move(lock));
    }
    if (io.start_ticks(plan.daemon_pid).value_or("") != plan.daemon_start) return fail("daemon identity mismatch");
    Fd daemon(static_cast<int>(syscall(SYS_pidfd_open, plan.daemon_pid, 0)));
    if (daemon.get() < 0) return fail(std::string("pidfd_open: ") + std::strerror(errno));
    std::unique_ptr<AndroidWatchdog> watchdog;
    std::unique_ptr<AndroidWifiSession> wifi;
    try {
        watchdog = android_display_arm_watchdog(io, plan);
        AndroidRescueRestart(io, plan.rescue_adapter).verify_access();
        if (!plan.wifi.isNull()) wifi = io.prepare_wifi(plan.wifi);
    }
    catch (const std::exception& error) { return fail(error.what()); }
    say("ready");
    Fd watched;
    std::string reason, input;
    const auto started = std::chrono::steady_clock::now();
    unsigned link_down = 0;
    bool wifi_started = false;
    while (reason.empty()) {
        pollfd events[3] = {{daemon.get(), POLLIN, 0}, {0, POLLIN, 0}, {watched.get(), POLLIN, 0}};
        const int count = poll(events, watched.get() >= 0 ? 3 : 2, 10000);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { reason = std::string("poll: ") + std::strerror(errno); break; }
        if (count == 0) {
            try { if (watchdog) watchdog->kick(watchdog_kick_seconds); }
            catch (const std::exception& error) { reason = std::string("watchdog: ") + error.what(); break; }
            try { if (wifi_started) wifi->check(); }
            catch (const std::exception& error) { reason = error.what(); break; }
            if (plan.auto_restore_seconds > 0 && std::chrono::steady_clock::now() - started >= std::chrono::seconds(plan.auto_restore_seconds)) { reason = "auto-restore deadline"; break; }
            if (plan.restore_on_network_loss) {
                const auto state = operstate(io, plan.network_interface);
                link_down = state && *state == "up" ? 0 : link_down + 1;
                if (link_down >= 3) { reason = "network link lost"; break; }
            }
            continue;
        }
        if (events[0].revents) { reason = "daemon exited"; break; }
        if (watched.get() >= 0 && events[2].revents) { watched = Fd(); say("progress vm-exited"); }
        if (events[1].revents) {
            char chunk[256];
            const auto n = read(0, chunk, sizeof(chunk));
            if (n <= 0) { reason = "daemon closed"; break; }
            input.append(chunk, static_cast<size_t>(n));
            for (auto newline = input.find('\n'); newline != std::string::npos && reason.empty(); newline = input.find('\n')) {
                const auto command = input.substr(0, newline);
                input.erase(0, newline + 1);
                if (command == "restore") reason = "requested";
                else if (command == "start-wifi") {
                    try {
                        if (!wifi || wifi_started) throw std::runtime_error("invalid Wi-Fi handoff request");
                        if (watchdog) watchdog->kick(watchdog_kick_seconds);
                        wifi->start(); wifi_started = true; say("wifi-ready");
                    } catch (const std::exception& error) {
                        say(std::string("wifi-failed ") + error.what()); reason = "Wi-Fi handoff failed";
                    }
                }
                else if (command == "unwatch") watched = Fd();
                else if (command.starts_with("watch ")) {
                    try { watched = Fd(static_cast<int>(syscall(SYS_pidfd_open, std::stoi(command.substr(6)), 0))); } catch (...) { watched = Fd(); }
                }
            }
        }
    }
    say("progress " + reason);
    if (watched.get() >= 0) {
        // crosvm holds DRM master; the HAL cannot come back while it lives.
        say("progress kill-vm");
        syscall(SYS_pidfd_send_signal, watched.get(), SIGKILL, nullptr, 0);
        pollfd exit_event{watched.get(), POLLIN, 0};
        while (poll(&exit_event, 1, 10000) < 0 && errno == EINTR) {}
        watched = Fd();
    }
    int status = 0;
    try { android_display_restore(io, plan, watchdog.get(), [&](const std::string& phase) { say("progress " + phase); }, wifi.get()); }
    catch (const std::exception& error) { say(std::string("failed ") + error.what()); status = 1; }
    try { if (watchdog) watchdog->restore(); } catch (const std::exception& error) { if (status == 0) { say(std::string("failed hangdetect restore: ") + error.what()); status = 1; } }
    if (status == 0) say("restored");
    return status;
}
#else
AndroidDisplayIo android_display_real_io(std::string, std::string) { return {}; }
int android_display_sentinel_main() { return 1; }
#endif
}
