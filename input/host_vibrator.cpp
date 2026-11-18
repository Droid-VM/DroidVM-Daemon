// SPDX-License-Identifier: GPL-3.0-or-later
// Port of the hackintosh daemon's input/HostVibrator.java, playing on the
// vibrator HAL (or VibratorManagerService through the shell) instead of the
// Java Vibrator the native daemon cannot reach.
#include "input/host_vibrator.h"
#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <android/binder_status.h>
#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#include <type_traits>

namespace droidvm::input {
namespace {
constexpr uint16_t ev_ff = 0x15, ff_rumble = 0x50;
constexpr size_t record_bytes = 8;
// The trackpad's haptic waveforms: the HID Haptics page's (0x0e) usages
// 0x1002..0x1007 by their low byte, as crosvm declares them.
constexpr uint16_t haptic_stop = 0x02, haptic_click = 0x03, haptic_buzz = 0x04, haptic_rumble = 0x05,
    haptic_press = 0x06, haptic_release = 0x07;
constexpr const char* trackpad_key = "/trackpad"; // a VM's trackpad beside its vibrator
constexpr int click_ms = 12; // about what one of the platform's click primitives lasts
constexpr int max_repeats = 20, default_period_ms = 100, max_period_ms = 1000;

// android.hardware.vibrator.IVibrator (stable AIDL): the transaction codes are
// FIRST_CALL_TRANSACTION plus the method's position in the frozen interface.
constexpr const char* hal_descriptor = "android.hardware.vibrator.IVibrator";
constexpr const char* hal_instance = "android.hardware.vibrator.IVibrator/default";
constexpr transaction_code_t hal_get_capabilities = FIRST_CALL_TRANSACTION + 0;
constexpr transaction_code_t hal_off = FIRST_CALL_TRANSACTION + 1;
constexpr transaction_code_t hal_on = FIRST_CALL_TRANSACTION + 2; // on(int timeoutMs, IVibratorCallback)
constexpr transaction_code_t hal_set_amplitude = FIRST_CALL_TRANSACTION + 5; // setAmplitude(float)
constexpr int32_t cap_amplitude_control = 1 << 2;

class HalMotor final : public VibratorMotor {
public:
    HalMotor(void* library, AIBinder* binder) : library_(library), binder_(binder) {}
    ~HalMotor() override {
        AIBinder_decStrong(binder_);
        if (library_) dlclose(library_);
    }
    // getCapabilities; false when the service does not answer as an IVibrator.
    bool probe() {
        return call(hal_get_capabilities, nullptr, [this](const AParcel* out) {
            return AParcel_readInt32(out, &capabilities_) == STATUS_OK;
        });
    }
    bool amplitude_control() const override { return capabilities_ & cap_amplitude_control; }
    bool play(int ms, int amplitude) override {
        // As the platform's VibratorController does: on, then the amplitude.
        const bool on = call(hal_on, [ms](AParcel* in) {
            return AParcel_writeInt32(in, ms) == STATUS_OK && AParcel_writeStrongBinder(in, nullptr) == STATUS_OK;
        }, nullptr);
        if (!on || !amplitude_control()) return on;
        const float level = std::clamp(amplitude, 1, 255) / 255.0f;
        return call(hal_set_amplitude, [level](AParcel* in) { return AParcel_writeFloat(in, level) == STATUS_OK; }, nullptr);
    }
    bool stop() override { return call(hal_off, nullptr, nullptr); }
    const char* name() const override { return "the vibrator HAL"; }
private:
    template<class Write, class Read>
    bool call(transaction_code_t code, Write write, Read read) {
        AParcel* in = nullptr;
        if (AIBinder_prepareTransaction(binder_, &in) != STATUS_OK) return false;
        if constexpr (!std::is_same_v<Write, std::nullptr_t>) {
            if (!write(in)) { AParcel_delete(in); return false; }
        }
        AParcel* out = nullptr;
        // Consumes [in] whatever the outcome.
        if (AIBinder_transact(binder_, code, &in, &out, 0) != STATUS_OK) {
            if (out) AParcel_delete(out);
            return false;
        }
        AStatus* status = nullptr;
        bool ok = AParcel_readStatusHeader(out, &status) == STATUS_OK && status && AStatus_isOk(status);
        if (status) AStatus_delete(status);
        if constexpr (!std::is_same_v<Read, std::nullptr_t>) {
            if (ok) ok = read(out);
        }
        AParcel_delete(out);
        return ok;
    }
    void* library_;
    AIBinder* binder_;
    int32_t capabilities_ = 0;
};

class ShellMotor final : public VibratorMotor {
public:
    explicit ShellMotor(RunCommand run) : run_(std::move(run)) {}
    // VibratorManagerService scales by the touch feedback setting and takes an
    // amplitude only with -a; it decides itself whether the motor has control.
    bool amplitude_control() const override { return true; }
    bool play(int ms, int amplitude) override {
        std::string output;
        return run_({"/system/bin/cmd", "vibrator_manager", "synced", "-f", "-B", "-d", "droidvm", "oneshot", "-a",
                     std::to_string(ms), std::to_string(std::clamp(amplitude, 1, 255))}, output) == 0 &&
            output.find("Error") == std::string::npos;
    }
    bool stop() override {
        std::string output;
        return run_({"/system/bin/cmd", "vibrator_manager", "cancel"}, output) == 0;
    }
    const char* name() const override { return "cmd vibrator_manager"; }
private:
    RunCommand run_;
};
}

std::unique_ptr<VibratorMotor> hal_vibrator(const std::function<void(const std::string&)>& log) {
    // AServiceManager_* is not in the public NDK: looked up at run time, as
    // the platform probe does.
    void* library = dlopen("libbinder_ndk.so", RTLD_NOW | RTLD_LOCAL);
    if (!library) { if (log) log("cannot load libbinder_ndk.so"); return nullptr; }
    using CheckService = AIBinder* (*)(const char*);
    const auto check = reinterpret_cast<CheckService>(dlsym(library, "AServiceManager_checkService"));
    AIBinder* binder = check ? check(hal_instance) : nullptr;
    if (!binder) {
        if (log) log(std::string(hal_instance) + (check ? " is not registered" : ": no service manager API"));
        dlclose(library);
        return nullptr;
    }
    // Process-lifetime class; the NDK has no way to delete one.
    static AIBinder_Class* const clazz = AIBinder_Class_define(hal_descriptor,
        [](void* args) -> void* { return args; }, [](void*) {},
        [](AIBinder*, transaction_code_t, const AParcel*, AParcel*) -> binder_status_t { return STATUS_UNKNOWN_TRANSACTION; });
    if (!clazz || !AIBinder_associateClass(binder, clazz)) {
        if (log) log(std::string(hal_instance) + " is not an " + hal_descriptor);
        AIBinder_decStrong(binder);
        dlclose(library);
        return nullptr;
    }
    auto motor = std::make_unique<HalMotor>(library, binder);
    if (!motor->probe()) {
        if (log) log(std::string(hal_instance) + " did not answer getCapabilities");
        return nullptr;
    }
    return motor;
}
std::unique_ptr<VibratorMotor> shell_vibrator(RunCommand run) {
    if (!run) return nullptr;
    std::string output;
    if (run({"/system/bin/cmd", "vibrator_manager", "list"}, output) != 0) return nullptr;
    // One vibrator id per line, or "No vibrator found".
    if (output.find("No vibrator") != std::string::npos ||
        std::none_of(output.begin(), output.end(), [](char c) { return std::isdigit(static_cast<unsigned char>(c)); }))
        return nullptr;
    return std::make_unique<ShellMotor>(std::move(run));
}

HostVibrator::HostVibrator(Hooks hooks) : hooks_(std::move(hooks)) {
    if (hooks_.thread) worker_ = std::thread(&HostVibrator::run, this);
}
HostVibrator::~HostVibrator() {
    {
        std::lock_guard lock(mutex_);
        closing_ = true;
    }
    wake_.notify_all();
    if (worker_.joinable()) worker_.join();
    if (motor_ && playing_ != 0) motor_->stop();
}
void HostVibrator::run() {
    std::unique_lock lock(mutex_);
    while (!closing_) {
        if (clicks_) wake_.wait_until(lock, clicks_->next, [this] { return closing_ || dirty_; });
        else wake_.wait(lock, [this] { return closing_ || dirty_; });
        if (closing_) break;
        dirty_ = false;
        lock.unlock();
        try { step(); click_due(); } catch (...) {}
        lock.lock();
    }
}
void HostVibrator::on_trackpad_status(const std::string& vm, std::string_view records) {
    {
        std::lock_guard lock(mutex_);
        const auto key = vm + trackpad_key;
        for (size_t at = 0; at + record_bytes <= records.size(); at += record_bytes) {
            uint8_t bytes[record_bytes];
            std::memcpy(bytes, records.data() + at, record_bytes);
            const uint16_t type = static_cast<uint16_t>(bytes[0] | bytes[1] << 8);
            const uint16_t code = static_cast<uint16_t>(bytes[2] | bytes[3] << 8);
            const uint32_t value = static_cast<uint32_t>(bytes[4]) | static_cast<uint32_t>(bytes[5]) << 8 |
                static_cast<uint32_t>(bytes[6]) << 16 | static_cast<uint32_t>(bytes[7]) << 24;
            if (type != ev_ff) continue;
            const int intensity = static_cast<int>(value & 0xff);
            const double scale = intensity == 0 ? 1.0 : std::min(100, intensity) / 100.0;
            switch (code) {
            case haptic_stop: magnitudes_.erase(key); break;
            case haptic_buzz:
            case haptic_rumble: magnitudes_[key] = std::max(1, static_cast<int>(std::lround(scale * 0xffff))); break;
            case haptic_click:
            case haptic_press:
            case haptic_release: {
                if (clicks_) break; // one train at a time
                const int period = static_cast<int>(value >> 16);
                Clicks train;
                // A release is the lighter tick a haptic touchpad gives as the finger lets go.
                train.amplitude = std::max(1, static_cast<int>(std::lround(scale * (code == haptic_release ? 160 : 255))));
                train.remaining = std::min(max_repeats, static_cast<int>((value >> 8) & 0xff));
                train.period_ms = period == 0 ? default_period_ms : std::min(max_period_ms, period);
                train.next = std::chrono::steady_clock::now();
                clicks_ = train;
                break;
            }
            default: break;
            }
        }
        dirty_ = true;
    }
    wake_.notify_all();
}
void HostVibrator::click_due() {
    int amplitude;
    {
        std::lock_guard lock(mutex_);
        if (!clicks_ || std::chrono::steady_clock::now() < clicks_->next) return;
        amplitude = clicks_->amplitude;
        if (clicks_->remaining-- > 0) clicks_->next += std::chrono::milliseconds(clicks_->period_ms);
        else clicks_.reset();
        if (playing_ != 0) return; // a click while something rumbles is dropped
    }
    if (!motor_) return;
    if (!motor_->play(click_ms, amplitude) && hooks_.log) hooks_.log("WARN", std::string("HostVibrator: ") + motor_->name() + " refused");
}
void HostVibrator::on_guest_status(const std::string& vm, std::string_view records) {
    {
        std::lock_guard lock(mutex_);
        for (size_t at = 0; at + record_bytes <= records.size(); at += record_bytes) {
            uint8_t bytes[record_bytes];
            std::memcpy(bytes, records.data() + at, record_bytes);
            const uint16_t type = static_cast<uint16_t>(bytes[0] | bytes[1] << 8);
            const uint16_t code = static_cast<uint16_t>(bytes[2] | bytes[3] << 8);
            const uint32_t value = static_cast<uint32_t>(bytes[4]) | static_cast<uint32_t>(bytes[5]) << 8 |
                static_cast<uint32_t>(bytes[6]) << 16 | static_cast<uint32_t>(bytes[7]) << 24;
            if (type != ev_ff || code != ff_rumble) continue;
            const int magnitude = static_cast<int>(std::max(value >> 16, value & 0xffff));
            if (magnitude == 0) magnitudes_.erase(vm);
            else magnitudes_[vm] = magnitude;
        }
        dirty_ = true;
    }
    wake_.notify_all();
}
void HostVibrator::release(const std::string& vm) {
    {
        std::lock_guard lock(mutex_);
        bool was = magnitudes_.erase(vm) != 0;
        was = magnitudes_.erase(vm + trackpad_key) != 0 || was;
        if (!was) return;
        dirty_ = true;
    }
    wake_.notify_all();
}
int HostVibrator::wanted() const {
    int magnitude = 0;
    for (const auto& [vm, value] : magnitudes_) magnitude = std::max(magnitude, value);
    return magnitude;
}
int HostVibrator::playing() const {
    std::lock_guard lock(mutex_);
    return playing_;
}
int HostVibrator::amplitude_of(int magnitude) {
    return std::clamp(static_cast<int>(std::lround(magnitude * 255.0 / 0xffff)), 1, 255);
}
void HostVibrator::step() {
    int magnitude;
    {
        std::lock_guard lock(mutex_);
        magnitude = wanted();
        if (magnitude == playing_ && (resolved_ || !clicks_)) return;
        playing_ = magnitude;
    }
    // The motor is only touched here, on one thread.
    if (!resolved_) {
        resolved_ = true;
        motor_ = hooks_.open ? hooks_.open() : nullptr;
        if (hooks_.log) {
            if (!motor_) hooks_.log("INFO", "HostVibrator: the phone has no vibrator; VM vibrators play nothing");
            else hooks_.log("INFO", std::string("HostVibrator: playing VM vibrators through ") + motor_->name() +
                            " (amplitude control " + (motor_->amplitude_control() ? "yes" : "no") + ")");
        }
    }
    if (!motor_) return;
    const bool ok = magnitude == 0 ? motor_->stop() : motor_->play(hold_ms, amplitude_of(magnitude));
    if (!ok && hooks_.log) hooks_.log("WARN", std::string("HostVibrator: ") + motor_->name() + " refused");
}
}
