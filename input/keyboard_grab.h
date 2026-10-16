// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "common/fd.h"
#include <json/json.h>
#include <atomic>
#include <bitset>
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace droidvm::input {
// HostKeyboard: an evdev node that has q, a, z, enter and space.
struct HostKeyboard {
    std::string path, name;
    int bus = 0, vendor = 0, product = 0;
    Json::Value json() const;
    std::string text() const; // toString
};
std::vector<HostKeyboard> scan_keyboards(const std::string& directory = "/dev/input");
// JSONObject.optBoolean and JSONArray.optInt.
bool java_boolean(const Json::Value& value, bool fallback);
int java_int(const Json::Value& value, int fallback);
// KeyboardGrabConfig: files/keyboard_grab.json.
struct KeyboardGrabConfig {
    static constexpr const char* name = "keyboard_grab.json";
    bool enabled = true;
    std::vector<int> escape_chord;
    static KeyboardGrabConfig from_json(const Json::Value& object);
    Json::Value json() const;
};
// KeyboardGrabManager: EVIOCGRAB the host keyboards and feed their keys to
// one VM screen's keyboard socket while a console (or kbd_grab) asks for it.
class KeyboardGrab {
public:
    // A console's binder token. link() returns false when it is already dead.
    class Owner {
    public:
        virtual ~Owner() = default;
        virtual bool link(std::function<void()> died) = 0;
        virtual void unlink() = 0;
    };
    // IPhysicalKeyEcho; a callback that throws is a console that has gone.
    struct Echo {
        std::function<void(const std::vector<int>& codes, const std::vector<int>& values)> keys;
        std::function<void(int known, int on)> leds;
    };
    struct Hooks {
        // Canonical id of a known VM, by any accepted spelling.
        std::function<std::optional<std::string>(const std::string& vm)> find;
        std::function<bool(const std::string& vm)> running;
        // writeNativeInput(screen, KEYBOARD, records); false when not delivered.
        std::function<bool(const std::string& vm, const std::string& screen, std::string_view records)> deliver;
        std::function<std::vector<HostKeyboard>()> scan = [] { return scan_keyboards(); };
        std::function<void(const char* level, const std::string& text)> log = [](const char*, const std::string&) {};
    };
    KeyboardGrab(int files_directory, Hooks hooks);
    ~KeyboardGrab();
    KeyboardGrab(const KeyboardGrab&) = delete;
    KeyboardGrab& operator=(const KeyboardGrab&) = delete;
    KeyboardGrabConfig config() const;
    void set_config(const KeyboardGrabConfig& config); // throws when it cannot be saved
    int request(const std::string& vm, const std::string& screen, std::shared_ptr<Owner> owner = {});
    bool release_for(const std::string& vm, const std::string& screen);
    void set_echo(const std::string& vm, const std::string& screen, std::shared_ptr<Echo> echo);
    void release(const std::string& reason);
    // Every VM transition; vm is the canonical id, state the lowercase name.
    void on_vm_state(const std::string& vm, const std::string& name, const std::string& state);
    void on_guest_status(const std::string& vm, const std::string& screen, std::string_view records);
    Json::Value status() const;
private:
    static constexpr size_t key_count = 0x300;
    struct Target {
        std::string vm, canonical, screen;
        std::shared_ptr<Owner> owner;
        std::shared_ptr<Echo> echo; // guarded by target_mutex_
    };
    struct Grab {
        HostKeyboard device;
        Fd fd, wake_read, wake_write;
        std::mutex pressed_mutex;
        std::bitset<key_count> pressed;
        std::atomic<bool> stopping{false};
        std::thread::id reader;
        std::mutex done_mutex;
        std::condition_variable done_ready;
        bool done = false;
    };
    struct Watcher {
        Fd fd, wake_read, wake_write;
        std::atomic<bool> stopping{false};
    };
    struct Worker { std::thread thread; std::shared_ptr<std::atomic<bool>> finished; };
    Fd files_;
    Hooks hooks_;
    mutable std::mutex lock_; // KeyboardGrabManager.lock
    mutable std::mutex target_mutex_;
    std::shared_ptr<Target> target_;
    std::map<std::string, std::shared_ptr<Grab>> grabs_;
    mutable std::mutex config_mutex_;
    KeyboardGrabConfig config_;
    std::mutex save_mutex_;
    std::shared_ptr<Watcher> watcher_;
    std::atomic<int> led_known_{0}, led_on_{0};
    std::mutex workers_mutex_;
    std::vector<Worker> workers_;
    std::shared_ptr<Target> current() const;
    std::shared_ptr<Echo> echo_of(const std::shared_ptr<Target>& target) const;
    void spawn(std::function<void()> body);
    KeyboardGrabConfig load();
    void save(const KeyboardGrabConfig& config);
    int grab_missing_locked();
    bool grab_one_locked(const HostKeyboard& keyboard);
    void drop_grabs_locked(const std::string& reason);
    void release_locked(const std::string& reason);
    void read_events(const std::shared_ptr<Grab>& grab);
    void on_events(Grab& grab, const char* buffer, size_t length);
    bool chord_held(Grab& grab) const;
    void release_held_keys(Grab& grab);
    void deliver(std::string_view records);
    void write_leds(Grab& grab);
    void send_leds(const std::shared_ptr<Echo>& echo);
    bool link(const std::shared_ptr<Target>& target);
    void start_watcher_locked();
    void stop_watcher_locked();
    void read_uevents(const std::shared_ptr<Watcher>& watcher);
    void rescan(const std::shared_ptr<Watcher>& watcher);
};
}
