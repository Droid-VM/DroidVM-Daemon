// SPDX-License-Identifier: GPL-3.0-or-later
#include "services/peripheral_foreground.h"
#include "vm/command_common.h"
#include "store/vm_config.h"
#include "vm/gnss_port.h"
#include "vm/crosvm_command.h"
#include <algorithm>

namespace droidvm {
namespace {
using namespace vm::command;
std::string hex(int value) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    auto bits = static_cast<unsigned>(value);
    do { out.insert(out.begin(), digits[bits & 15]); bits >>= 4; } while (bits);
    return "0x" + out;
}
}
ForegroundRequest foreground_request(vm::State state, const Json::Value& config, const ForegroundFacts& facts) {
    ForegroundRequest request;
    if (state == vm::State::stopped || !config.isObject()) return request;
    // Only crosvm attaches these devices; QEMU ignores the rows.
    if (config::java_enum(config, "backend", "CROSVM", {"CROSVM", "QEMU"}) != "CROSVM") return request;
    const auto& rows = member(config, "peripherals");
    if (!rows.isArray()) return request;
    vm::HostFacts camera_host;
    camera_host.crosvm_media_camera = facts.crosvm_media_camera;
    camera_host.has_kvm = facts.has_kvm;
    camera_host.has_gunyah = facts.has_gunyah;
    camera_host.app_uid = facts.app_uid;
    for (const auto& row : rows) {
        const auto type = java_enum(row, "type", "VIRTIO_SOUND", peripheral_types);
        // A USB camera row is a camera only when crosvm takes --uvc-camera
        // (the same test the command builder makes); one listed on a crosvm
        // without it never opens, and raising the camera type for it would
        // show a privacy indicator for a camera nothing uses.
        if (type == "USB_CAMERA" && facts.crosvm_uvc_camera) request.types |= foreground_type_camera;
        // A virtio-media camera row only on a VM that really attaches it: the
        // VPU switch on, Gunyah, the uid known -- the command builder's rule.
        if (type == "VIRTIO_CAMERA" && vm::virtio_camera_attached(config, camera_host)) request.types |= foreground_type_camera;
        // virtio-snd plays through an app-uid helper that ActivityManager does
        // not manage, and Android 17 mutes background playback from a uid that
        // does not hold the foreground-audio capability. mediaPlayback is the
        // type that grants it; measured on Android 17, playback survives
        // backgrounding while the service carries it.
        if (type == "VIRTIO_SOUND") request.types |= foreground_type_media_playback;
    }
    // The bit comes from the mask itself: a VM that raises the camera type
    // and has not switched the display hold off.
    request.keep_screen_on = (request.types & foreground_type_camera) != 0 && boolean(config, "camera_keep_screen_on", true);
    // The GNSS receiver (the first row; the VM has one) reads the phone's
    // location through the app's uid, which needs the location type, and the
    // feeder needs to know which sources: AUTO resolved against this phone the
    // way the launcher resolves it. Only when crosvm can name the port.
    if (const auto* row = vm::gnss_row(config); row && facts.crosvm_serial_name) {
        request.types |= foreground_type_location;
        request.gnss_sources |= vm::gnss_source_bits(vm::resolve_gnss_source(vm::gnss_source(*row), facts.host_gps_receiver));
    }
    return request;
}
ForegroundRequest foreground_union(const std::vector<ForegroundRequest>& requests) {
    ForegroundRequest out;
    for (const auto& request : requests) {
        out.types |= request.types;
        out.gnss_sources |= request.gnss_sources;
        out.keep_screen_on = out.keep_screen_on || request.keep_screen_on;
    }
    return out;
}
std::vector<std::string> foreground_command(const ForegroundRequest& request, const std::string& package, int user) {
    const auto component = package + "/" + peripheral_foreground_service;
    if (request.types == 0) return {"/system/bin/am", "stopservice", "--user", std::to_string(user), "-n", component};
    std::vector<std::string> argv{"/system/bin/am", "start-foreground-service", "--user", std::to_string(user), "-n", component,
                                  "--ei", "types", std::to_string(request.types)};
    if (request.gnss_sources != 0) {
        argv.insert(argv.end(), {"--ei", "gnss_sources", std::to_string(request.gnss_sources)});
    }
    // Absent reads as false in the service, which releases the lock.
    if (request.keep_screen_on && (request.types & foreground_type_camera) != 0)
        argv.insert(argv.end(), {"--ez", "keep_screen_on", "true"});
    return argv;
}
bool foreground_accepted(const ForegroundRequest& request, int exit_code, const std::string& output) {
    if (request.types == 0) {
        // "Service not stopped: Unable to find service" is a service that is
        // already gone, which is what was asked for.
        return exit_code == 0 || output.find("Unable to find service") != std::string::npos;
    }
    return exit_code == 0 && output.find("Error") == std::string::npos;
}

PeripheralForeground::PeripheralForeground(Hooks hooks) : hooks_(std::move(hooks)) {
    if (hooks_.retry.empty()) hooks_.retry.push_back(std::chrono::seconds(60));
    worker_ = std::thread(&PeripheralForeground::work, this);
}
PeripheralForeground::~PeripheralForeground() {
    {
        std::lock_guard lock(mutex_);
        closing_ = true;
    }
    wake_.notify_all();
    if (worker_.joinable()) worker_.join();
    // The daemon is going away and its VMs with it: nothing may keep the app
    // in the foreground on their behalf.
    if (!applied_ || applied_->types != 0) {
        try { apply({}); } catch (...) {}
    }
}
void PeripheralForeground::changed() {
    {
        std::lock_guard lock(mutex_);
        dirty_ = true;
    }
    wake_.notify_all();
}
void PeripheralForeground::reraise() {
    {
        std::lock_guard lock(mutex_);
        forget_ = true;
        dirty_ = true;
    }
    wake_.notify_all();
}
void PeripheralForeground::settle() {
    std::unique_lock lock(mutex_);
    idle_.wait(lock, [this] { return closing_ || (!dirty_ && !busy_); });
}
bool PeripheralForeground::apply(const ForegroundRequest& wanted) {
    const auto argv = foreground_command(wanted, hooks_.package, hooks_.user);
    std::string output;
    const int code = hooks_.run ? hooks_.run(argv, output) : -1;
    const bool ok = foreground_accepted(wanted, code, output);
    if (hooks_.log) {
        if (ok) hooks_.log("INFO", "peripheral foreground service types " + hex(wanted.types));
        else hooks_.log("WARN", "peripheral foreground service types " + hex(wanted.types) + " refused (exit " +
                        std::to_string(code) + "): " + output + "; will retry");
    }
    return ok;
}
void PeripheralForeground::work() {
    std::unique_lock lock(mutex_);
    for (;;) {
        if (failures_ == 0) wake_.wait(lock, [this] { return closing_ || dirty_; });
        else {
            const auto delay = hooks_.retry[std::min(failures_ - 1, hooks_.retry.size() - 1)];
            wake_.wait_for(lock, delay, [this] { return closing_ || dirty_; });
        }
        if (closing_) break;
        dirty_ = false;
        // applied_ belongs to this thread; reraise() only asks for it to go.
        if (forget_) { applied_.reset(); forget_ = false; }
        busy_ = true;
        lock.unlock();
        bool failed = false;
        try {
            std::vector<ForegroundRequest> requests;
            const auto facts = hooks_.facts ? hooks_.facts() : ForegroundFacts{};
            if (hooks_.snapshot)
                for (const auto& view : hooks_.snapshot()) requests.push_back(foreground_request(view.state, view.config, facts));
            const auto wanted = foreground_union(requests);
            // An unchanged request is not re-applied on every event; a
            // refused one was forgotten, so it never compares equal here.
            if (applied_ != wanted) {
                const bool ok = apply(wanted);
                applied_ = ok ? std::optional(wanted) : std::nullopt;
                failed = !ok;
            }
        } catch (const std::exception& error) {
            if (hooks_.log) hooks_.log("WARN", std::string("peripheral foreground service not updated: ") + error.what());
            failed = true;
        }
        lock.lock();
        failures_ = failed ? failures_ + 1 : 0;
        busy_ = false;
        if (!dirty_) idle_.notify_all();
    }
    busy_ = false;
    idle_.notify_all();
}
}
