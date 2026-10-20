// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "tasks.h"
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
// Android display ownership: stop SurfaceFlinger and the display HAL (and
// freeze system_server, which hosts MIUI Scout) so a VM can hold DRM master, or
// so a browser user can idle the phone while keeping its Wi-Fi up. Restoration
// rebuilds the Android framework; it is executed by a detached sentinel process
// so it also happens when this daemon dies. The display tier only: zygote stays
// up, so netd/wpa_supplicant and the daemon's own network keep working.
//
// Everything the sentinel needs to put Android back, captured before the first
// mutation and handed over once.
struct AndroidDisplayPlan {
    int daemon_pid = 0;
    std::string daemon_start; // /proc start ticks: PID reuse must not look like a live daemon
    int server_pid = 0;
    std::string server_start;
    bool suspend_running = false, secondary_running = false;
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
    std::function<std::string()> default_interface; // default-route device, "" when unknown
    std::function<std::string()> watchdog_status; // "" when the hangdetect ABI is verified, else why not
    std::function<std::unique_ptr<AndroidSentinel>(const AndroidDisplayPlan&)> spawn_sentinel;
};
// Real Android/Linux implementation. executable is re-exec'd as the sentinel.
AndroidDisplayIo android_display_real_io(std::string executable, std::string lock_directory);
// Rebuild the Android framework. Shared by the sentinel and by fixtures; every
// step is attempted and the joined failures are thrown afterwards.
void android_display_restore(const AndroidDisplayIo& io, const AndroidDisplayPlan& plan, AndroidWatchdog* watchdog,
                             const std::function<void(const std::string&)>& progress);
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
    std::unique_ptr<vm::AndroidDisplayLease> acquire(const std::string& vm_id, const std::string& vm_name) override;
    // Wait for an in-flight restoration (daemon shutdown); false on timeout.
    bool drain(std::chrono::milliseconds timeout);
    struct Impl; // shared with the VM lease; not part of any transport surface
private:
    std::shared_ptr<Impl> impl_;
};
}
