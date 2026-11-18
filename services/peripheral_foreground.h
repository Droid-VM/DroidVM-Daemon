// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "vm/runtime.h"
#include <json/json.h>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

// Keeps the app's PeripheralForegroundService in step with the VMs this daemon
// runs (the job of the Java daemon's PeripheralForegroundControl).
//
// crosvm runs under the app's uid but outside ActivityManager, so host APIs
// gated on a foreground uid (the camera's AppOp) only work while some process
// ActivityManager manages holds the uid foreground. A foreground service in
// the app does that, and only a root caller may start one while the app is in
// the background, which is why the daemon raises it: as root, through
//   am start-foreground-service --user <u> -n <pkg>/<service> --ei types <mask> [--ei gnss_sources <bits>] [--ez keep_screen_on true]
// and `am stopservice` once no running VM needs it.
//
// The rule is one pure function, foreground_request(): a VM that is not
// STOPPED is a VM whose devices exist (STARTING counts: the request goes out
// before crosvm is spawned, and the guest opens a camera seconds into its
// boot), and only rows the backend really attaches count.
namespace droidvm {
// android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_*
inline constexpr int foreground_type_location = 0x08;
inline constexpr int foreground_type_camera = 0x40;
// What a launch would attach, as far as the foreground rule needs to know.
struct ForegroundFacts {
    bool crosvm_uvc_camera = false; // HostFacts::crosvm_uvc_camera
    bool crosvm_serial_name = false; // HostFacts::crosvm_serial_name: the GNSS port exists
    bool host_gps_receiver = false; // vm::host_has_gps_receiver(), what AUTO resolves on
    // What a VIRTIO_CAMERA row needs (vm::virtio_camera_attached): the
    // virtio-media camera in crosvm, a Gunyah VM, the app uid crosvm runs it as.
    bool crosvm_media_camera = false; // HostFacts::crosvm_media_camera
    bool has_kvm = false, has_gunyah = false; // how an AUTO hypervisor resolves
    int app_uid = -1;
};
// One request to the service: the intent extras it reads.
struct ForegroundRequest {
    int types = 0; // EXTRA_TYPES; 0 stops the service
    // EXTRA_GNSS_SOURCES ("gnss_sources", vm::gnss_source_* bits): which of the
    // phone's sources the running VMs' GNSS receivers want, for the feeder the
    // service runs while it carries foreground_type_location.
    int gnss_sources = 0;
    // EXTRA_KEEP_SCREEN_ON ("keep_screen_on"): a VM raising the camera type
    // whose camera_keep_screen_on (default on) holds the display awake. The
    // CAMERA app op is granted in foreground mode and a sleeping screen makes
    // the app TOP_SLEEPING, which revokes a capture already streaming; the
    // service holds a screen wake lock while this is set. Only with
    // foreground_type_camera in types, so no VM holds the display without a
    // camera and none opens a camera and lets the display go.
    bool keep_screen_on = false;
    bool operator==(const ForegroundRequest&) const = default;
};
// The request one VM in [state] with [config] (migrated VM JSON) makes.
ForegroundRequest foreground_request(vm::State state, const Json::Value& config, const ForegroundFacts& facts);
// The union over every VM.
ForegroundRequest foreground_union(const std::vector<ForegroundRequest>& requests);
// The `am` command line for [request]: a start for a non-zero mask, a stop for zero.
std::vector<std::string> foreground_command(const ForegroundRequest& request, const std::string& package, int user);
// Whether `am` took the request. A start refused by ActivityManager prints
// "Error: ..." (no service, permission, background start); a stop of a service
// that is not running is fine.
bool foreground_accepted(const ForegroundRequest& request, int exit_code, const std::string& output);
inline constexpr const char* peripheral_foreground_service = "cn.classfun.droidvm.lib.peripheral.PeripheralForegroundService";

class PeripheralForeground {
public:
    struct VmView { vm::State state = vm::State::stopped; Json::Value config; };
    struct Hooks {
        std::function<std::vector<VmView>()> snapshot; // every VM this daemon runs
        std::function<ForegroundFacts()> facts;
        // Runs argv; returns exit code (negative: could not run), output in [output].
        std::function<int(const std::vector<std::string>& argv, std::string& output)> run;
        std::function<void(const char* level, const std::string& text)> log;
        std::string package;
        int user = 0;
        // A refused request is not remembered: it is retried after these
        // delays (the last repeats) while it is still wanted, and on the next
        // state change.
        std::vector<std::chrono::milliseconds> retry = {std::chrono::seconds(2), std::chrono::seconds(10), std::chrono::seconds(60)};
    };
    explicit PeripheralForeground(Hooks hooks);
    // Stops the service if it was raised, then joins the worker.
    ~PeripheralForeground();
    PeripheralForeground(const PeripheralForeground&) = delete;
    PeripheralForeground& operator=(const PeripheralForeground&) = delete;
    // Any VM changed state. Never blocks: `am` takes a second and the caller
    // is the VM's own state transition.
    void changed();
    // The service may be gone although it was raised (the GNSS feeder fell
    // silent: the app's process was killed or replaced). Forgets what was
    // applied, so the whole request goes out again. Never blocks.
    void reraise();
    // Waits until the worker has nothing pending (tests).
    void settle();
private:
    void work();
    bool apply(const ForegroundRequest& wanted);
    Hooks hooks_;
    std::mutex mutex_;
    std::condition_variable wake_, idle_;
    bool dirty_ = false, closing_ = false, busy_ = false, forget_ = false;
    // What the service was last given; empty after a refusal, so the next
    // pass asks again even for the same request.
    std::optional<ForegroundRequest> applied_ = ForegroundRequest{};
    size_t failures_ = 0;
    std::thread worker_;
};
}
