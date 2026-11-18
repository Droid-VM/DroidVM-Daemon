// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

// Plays the VMs' vibrators on the phone's motor (the hackintosh daemon's
// HostVibrator).
//
// What a guest sends its vibrator (crosvm --input vibrator) arrives as 8-byte
// evdev records on the VIBRATOR input channel: EV_FF, code FF_RUMBLE, value
// the strong magnitude in the high 16 bits and the weak in the low, sent as
// each effect starts and stops (both 0 is stop). The guest does the timing
// (Linux's memless force feedback), so this only follows the magnitude it is
// told: the stronger of the two, since a phone has one motor, and across VMs
// the strongest. Each change is a one-shot of at most hold_ms, so a guest that
// stops talking mid-rumble (crashed, or its VM killed) cannot leave the motor
// running; a VM's rumble also stops when the VM does.
namespace droidvm::input {
// The phone's motor.
class VibratorMotor {
public:
    virtual ~VibratorMotor() = default;
    // Whether play() honours an amplitude; otherwise the motor's default.
    virtual bool amplitude_control() const = 0;
    // Runs the motor for [ms] at [amplitude] (1..255; ignored without
    // amplitude control). False: the motor refused.
    virtual bool play(int ms, int amplitude) = 0;
    virtual bool stop() = 0;
    virtual const char* name() const = 0;
};
// android.hardware.vibrator.IVibrator/default, the vibrator HAL, through
// libbinder_ndk (the daemon is root). Null when the service is missing or does
// not answer getCapabilities. [log] gets why.
std::unique_ptr<VibratorMotor> hal_vibrator(const std::function<void(const std::string&)>& log);
// The fallback: VibratorManagerService through the shell,
//   cmd vibrator_manager synced -f -B -d droidvm oneshot [-a] <ms> [<amplitude>]
//   cmd vibrator_manager cancel
// [run] executes argv and returns the exit code (output in its second
// argument). Null when `cmd vibrator_manager list` names no vibrator.
using RunCommand = std::function<int(const std::vector<std::string>& argv, std::string& output)>;
std::unique_ptr<VibratorMotor> shell_vibrator(RunCommand run);

class HostVibrator {
public:
    static constexpr int hold_ms = 5000; // the longest one request runs
    struct Hooks {
        // Looked up once, on the first rumble; null: the phone has no motor.
        std::function<std::unique_ptr<VibratorMotor>()> open;
        std::function<void(const char* level, const std::string& text)> log;
        bool thread = true; // false: the caller drives step() (tests)
    };
    explicit HostVibrator(Hooks hooks);
    ~HostVibrator(); // stops the motor if this was playing
    HostVibrator(const HostVibrator&) = delete;
    HostVibrator& operator=(const HostVibrator&) = delete;
    // Whole evdev records [vm]'s guest sent its vibrator. Never blocks on the motor.
    void on_guest_status(const std::string& vm, std::string_view records);
    // [vm] stopped: whatever it was playing stops with it.
    void release(const std::string& vm);
    // Brings the motor to the strongest wanted magnitude (the worker's step).
    void step();
    // The magnitude being played, 0..0xffff (tests).
    int playing() const;
    // 0..0xffff -> 1..255, as VibrationEffect.createOneShot's amplitude.
    static int amplitude_of(int magnitude);
private:
    int wanted() const; // mutex_ held
    void run();
    Hooks hooks_;
    mutable std::mutex mutex_;
    std::condition_variable wake_;
    std::map<std::string, int> magnitudes_; // rumbling VMs only
    int playing_ = 0;
    bool resolved_ = false, closing_ = false, dirty_ = false;
    std::unique_ptr<VibratorMotor> motor_;
    std::thread worker_;
};
}
