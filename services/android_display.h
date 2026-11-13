// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "tasks.h"
#include "android_wifi.h"
#include "android_rescue.h"
#include "vm/android_display_control.h"
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace droidvm {
struct AndroidDisplayNetwork {
    bool default_present = false;
    bool validated = false;
};
struct AndroidWatchdogStatus {
    bool required = true;
    std::string reason; // empty when this path is ready; probe failures never mean absent
};
AndroidWatchdogStatus android_display_probe_watchdog(const std::function<bool(const std::string&)>& exists,
                                                    const std::function<std::string()>& verify_hangdetect);
// Unknown dump formats must not be mistaken for a working or offline network.
std::optional<AndroidDisplayNetwork> android_display_network(const std::string& dump);
// Android display ownership: stop SurfaceFlinger and the display HAL (and
// freeze system_server, which hosts MIUI Scout) so a VM can hold DRM master, or
// so a browser user can idle the phone while keeping its Wi-Fi up. An optional
// zygote tier also stops the Android app framework to reclaim its memory.
// Restoration is executed by a detached sentinel so it also happens on daemon death.
//
// Everything the sentinel needs to put Android back, captured before the first
// mutation and handed over once.
struct AndroidDisplayPlan {
    int daemon_pid = 0;
    std::string daemon_start; // /proc start ticks: PID reuse must not look like a live daemon
    int server_pid = 0;
    std::string server_start;
    bool suspend_running = false, secondary_running = false;
    bool zygote_running = true;
    bool stop_zygote = false;
    bool watchdog_required = true;
    std::string rescue_adapter;
    std::vector<std::string> network_services; // running init dependencies, in start order
    bool network_default = false, network_validated = false;
    Json::Value wifi; // credential-free independent Wi-Fi takeover plan
    std::vector<std::pair<std::string, std::string>> stability; // persist.sys.stability.* originals
    std::string lock_directory;
    std::string network_interface; // "" = no link watch
    int auto_restore_seconds = 0; // 0 = only on request, daemon death or link loss
    bool restore_on_network_loss = false;
    Json::Value json() const;
    static AndroidDisplayPlan parse(const Json::Value& value);
};
// One sentinel process, or a fixture standing in for it. Lines are newline
// terminated. To the sentinel: "watch <pid>", "unwatch", "restore". From it:
// "ready", "progress <phase>", "restored", "failed <message>".
class AndroidSentinel {
public:
    virtual ~AndroidSentinel() = default;
    virtual void send(const std::string& line) = 0;
    // nullopt on timeout; "" once the sentinel has gone away.
    virtual std::optional<std::string> read_line(std::chrono::milliseconds timeout) = 0;
    // Drop the pipes; a later read_line returns "". Never kills the sentinel.
    virtual void close() = 0;
};
class AndroidWatchdog {
public:
    virtual ~AndroidWatchdog() = default;
    virtual void kick(unsigned seconds) = 0;
    virtual void restore() = 0;
};
struct AndroidDisplayIo {
    bool android = false; // this host can hand its panel over at all
    std::function<std::string(const std::string&)> property; // "" when unset
    std::function<void(const std::string&, const std::string&)> set_property; // throws std::runtime_error
    std::function<std::optional<std::string>(const std::string&)> read; // small file; nullopt when unreadable
    std::function<void(const std::string&, const std::string&)> write; // throws
    std::function<std::vector<int>(const std::string& comm)> processes;
    std::function<int()> self_pid;
    std::function<std::optional<std::string>(int)> start_ticks;
    std::function<bool(int)> stopped; // /proc state T (SIGSTOP)
    std::function<void(int pid, int number)> signal; // throws
    std::function<void(std::chrono::milliseconds)> sleep;
    std::function<uint64_t()> wall_ms;
    std::function<uint64_t()> uptime_ms; // CLOCK_MONOTONIC, Android uptimeMillis
    std::function<std::string()> default_interface; // default-route device, "" when unknown
    std::function<std::optional<AndroidDisplayNetwork>()> network_status;
    std::function<Json::Value()> wifi_plan;
    std::function<std::unique_ptr<AndroidWifiSession>(const Json::Value&)> prepare_wifi;
    std::function<AndroidWatchdogStatus()> watchdog_status;
    std::function<AndroidRescueStatus()> rescue_status;
    std::function<std::unique_ptr<AndroidWatchdog>()> open_watchdog;
    std::function<std::unique_ptr<AndroidSentinel>(const AndroidDisplayPlan&)> spawn_sentinel;
};
// Real Android/Linux implementation. executable is re-exec'd as the sentinel.
AndroidDisplayIo android_display_real_io(std::string executable, std::string lock_directory);
// Recheck the selected path in the sentinel. No driver is opened on the absent path.
std::unique_ptr<AndroidWatchdog> android_display_arm_watchdog(const AndroidDisplayIo&, const AndroidDisplayPlan&);
// Rebuild the Android framework. Shared by the sentinel and by fixtures; every
// step is attempted and the joined failures are thrown afterwards.
void android_display_restore(const AndroidDisplayIo& io, const AndroidDisplayPlan& plan, AndroidWatchdog* watchdog,
                             const std::function<void(const std::string&)>& progress, AndroidWifiSession* wifi = nullptr);
// droidvmd --android-display-sentinel: reads the plan from stdin. Linux only.
int android_display_sentinel_main();

class AndroidDisplayService : public vm::AndroidDisplayControl {
public:
    static constexpr const char* capability = "android-display-v1";
    AndroidDisplayService(TaskService&, AndroidDisplayIo);
    ~AndroidDisplayService() override;
    Json::Value snapshot(const CallContext&);
    TaskView start(const CallContext&, const Json::Value& request);
    TaskView status(const CallContext&, const std::string& request_id);
    std::unique_ptr<vm::AndroidDisplayLease> acquire(const std::string& vm_id, const std::string& vm_name, bool stop_zygote = false) override;
    // Wait for an in-flight restoration (daemon shutdown); false on timeout.
    bool drain(std::chrono::milliseconds timeout);
    struct Impl; // shared with the VM lease; not part of any transport surface
private:
    std::shared_ptr<Impl> impl_;
};
}
