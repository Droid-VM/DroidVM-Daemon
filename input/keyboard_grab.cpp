// SPDX-License-Identifier: GPL-3.0-or-later
#include "keyboard_grab.h"
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/netlink.h>
#include <poll.h>
#include <pthread.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>

namespace droidvm::input {
namespace {
constexpr int events_per_read = 64;
constexpr int led_count = 3; // LED_NUML, LED_CAPSL, LED_SCROLLL
constexpr int key_up = 0, key_down = 1, key_repeat = 2;
constexpr int rescan_debounce_ms = 200;
constexpr auto reader_join = std::chrono::milliseconds(500);
constexpr int typing_keys[] = {KEY_Q, KEY_A, KEY_Z, KEY_ENTER, KEY_SPACE};
std::string hex4(int value) {
    char text[16];
    std::snprintf(text, sizeof(text), "%04x", static_cast<unsigned>(value));
    return text;
}
// String.trim: every char <= ' ' at either end.
std::string trim(std::string text) {
    size_t begin = 0, end = text.size();
    while (begin < end && static_cast<unsigned char>(text[begin]) <= ' ') ++begin;
    while (end > begin && static_cast<unsigned char>(text[end - 1]) <= ' ') --end;
    return text.substr(begin, end - begin);
}
int saturate(double number) {
    if (std::isnan(number)) return 0;
    if (number >= 2147483647.0) return 2147483647;
    if (number <= -2147483648.0) return -2147483647 - 1;
    return static_cast<int>(number);
}
// One 8-byte record of crosvm's input socket.
void append(std::string& out, uint16_t type, uint16_t code, int32_t value) {
    char record[8];
    std::memcpy(record, &type, 2);
    std::memcpy(record + 2, &code, 2);
    std::memcpy(record + 4, &value, 4);
    out.append(record, sizeof(record));
}
void append_event(std::string& out, uint16_t type, uint16_t code, int32_t value) {
    input_event event{};
    event.type = type;
    event.code = code;
    event.value = value;
    out.append(reinterpret_cast<const char*>(&event), sizeof(event));
}
void wake(const Fd& fd) {
    const char byte = 1;
    while (write(fd.get(), &byte, 1) < 0 && errno == EINTR) {}
}
const char* lamp(int known, int on, int bit) {
    if ((known & bit) == 0) return "?";
    return (on & bit) != 0 ? "on" : "off";
}
}

Json::Value HostKeyboard::json() const {
    Json::Value value;
    value["path"] = path;
    value["name"] = name;
    value["bus"] = hex4(bus);
    value["vendor"] = hex4(vendor);
    value["product"] = hex4(product);
    return value;
}
std::string HostKeyboard::text() const { return path + " \"" + name + "\" " + hex4(vendor) + ":" + hex4(product); }
std::vector<HostKeyboard> scan_keyboards(const std::string& directory) {
    std::vector<HostKeyboard> out;
    std::vector<std::string> names;
    if (DIR* dir = opendir(directory.c_str())) {
        while (auto* entry = readdir(dir)) names.emplace_back(entry->d_name);
        closedir(dir);
    } else return out;
    std::sort(names.begin(), names.end());
    for (const auto& node : names) {
        if (!node.starts_with("event")) continue;
        const auto path = directory + "/" + node;
        int raw = open(path.c_str(), O_RDWR | O_CLOEXEC);
        if (raw < 0) raw = open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (raw < 0) continue;
        Fd fd(raw);
        unsigned char bits[KEY_MAX / 8 + 1] = {};
        if (ioctl(fd.get(), EVIOCGBIT(EV_KEY, sizeof(bits)), bits) < 0) continue;
        bool typing = true;
        for (const int key : typing_keys) typing = typing && (bits[key / 8] & (1 << (key % 8))) != 0;
        if (!typing) continue;
        HostKeyboard keyboard;
        keyboard.path = path;
        char name[256] = {};
        if (ioctl(fd.get(), EVIOCGNAME(sizeof(name) - 1), name) >= 0) keyboard.name = trim(name);
        input_id id{};
        if (ioctl(fd.get(), EVIOCGID, &id) >= 0) { keyboard.bus = id.bustype; keyboard.vendor = id.vendor; keyboard.product = id.product; }
        out.push_back(std::move(keyboard));
    }
    return out;
}
bool java_boolean(const Json::Value& value, bool fallback) {
    if (value.isBool()) return value.asBool();
    if (!value.isString()) return fallback;
    auto text = value.asString();
    for (auto& c : text) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return text == "true" ? true : text == "false" ? false : fallback;
}
int java_int(const Json::Value& value, int fallback) {
    // JSONTokener: integral literals are Integer or Long (intValue wraps), the rest Double.
    if (value.isBool()) return fallback;
    if (value.type() == Json::intValue || value.type() == Json::uintValue) {
        if (value.isInt64()) return static_cast<int32_t>(static_cast<uint32_t>(static_cast<uint64_t>(value.asInt64())));
        return saturate(value.asDouble());
    }
    if (value.type() == Json::realValue) return saturate(value.asDouble());
    if (value.isString()) {
        try {
            size_t used = 0;
            const auto text = value.asString();
            const double number = std::stod(text, &used);
            if (used != text.size()) return fallback;
            return saturate(number);
        } catch (const std::exception&) { return fallback; }
    }
    return fallback;
}
KeyboardGrabConfig KeyboardGrabConfig::from_json(const Json::Value& object) {
    KeyboardGrabConfig config;
    if (!object.isObject()) return config;
    const auto& chord = object.get("escape_chord", Json::Value());
    if (chord.isArray()) {
        for (const auto& item : chord) {
            const int code = java_int(item, -1);
            // A code no key can send would make a chord that never fires.
            if (code > 0 && code <= 0x2ff && std::find(config.escape_chord.begin(), config.escape_chord.end(), code) == config.escape_chord.end())
                config.escape_chord.push_back(code);
        }
    }
    config.enabled = java_boolean(object.get("enabled", Json::Value()), true);
    return config;
}
Json::Value KeyboardGrabConfig::json() const {
    Json::Value value;
    value["enabled"] = enabled;
    value["escape_chord"] = Json::Value(Json::arrayValue);
    for (const int code : escape_chord) value["escape_chord"].append(code);
    return value;
}

KeyboardGrab::KeyboardGrab(int files_directory, Hooks hooks)
    : files_(files_directory >= 0 ? fcntl(files_directory, F_DUPFD_CLOEXEC, 0) : -1), hooks_(std::move(hooks)) {
    config_ = load();
}
KeyboardGrab::~KeyboardGrab() {
    {
        std::lock_guard lock(lock_);
        std::shared_ptr<Target> gone;
        // No target first: nothing is delivered to a store that may be gone.
        { std::lock_guard target(target_mutex_); gone.swap(target_); }
        drop_grabs_locked("daemon stopping");
        if (gone && gone->owner) gone->owner->unlink();
        stop_watcher_locked();
    }
    for (;;) {
        std::vector<Worker> workers;
        { std::lock_guard lock(workers_mutex_); workers.swap(workers_); }
        if (workers.empty()) break;
        for (auto& worker : workers) if (worker.thread.joinable()) worker.thread.join();
    }
}
std::shared_ptr<KeyboardGrab::Target> KeyboardGrab::current() const { std::lock_guard lock(target_mutex_); return target_; }
std::shared_ptr<KeyboardGrab::Echo> KeyboardGrab::echo_of(const std::shared_ptr<Target>& target) const {
    if (!target) return {};
    std::lock_guard lock(target_mutex_);
    return target->echo;
}
void KeyboardGrab::spawn(std::function<void()> body) {
    auto finished = std::make_shared<std::atomic<bool>>(false);
    std::lock_guard lock(workers_mutex_);
    std::erase_if(workers_, [](Worker& worker) {
        if (!worker.finished->load()) return false;
        worker.thread.join();
        return true;
    });
    workers_.push_back({std::thread([body = std::move(body), finished] { body(); finished->store(true); }), finished});
}
KeyboardGrabConfig KeyboardGrab::config() const { std::lock_guard lock(config_mutex_); return config_; }
KeyboardGrabConfig KeyboardGrab::load() {
    if (files_.get() < 0) return {};
    Fd file(openat(files_.get(), KeyboardGrabConfig::name, O_RDONLY | O_CLOEXEC | O_NONBLOCK));
    struct stat info{};
    if (file.get() < 0 || fstat(file.get(), &info) != 0 || !S_ISREG(info.st_mode)) return {};
    std::string text;
    char buffer[4096];
    for (;;) {
        const auto count = read(file.get(), buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0 || text.size() > (1u << 20)) break;
        text.append(buffer, static_cast<size_t>(count));
    }
    Json::Value value;
    Json::CharReaderBuilder builder;
    std::string errors;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    if (!reader->parse(text.data(), text.data() + text.size(), &value, &errors) || !value.isObject()) {
        hooks_.log("WARN", std::string("KeyboardGrab: Cannot read ") + KeyboardGrabConfig::name + "; using the defaults");
        return {};
    }
    return KeyboardGrabConfig::from_json(value);
}
void KeyboardGrab::save(const KeyboardGrabConfig& config) {
    // JSONObject.toString(2), next to the target, then renamed; owned like its directory.
    std::string text = "{\n  \"enabled\": " + std::string(config.enabled ? "true" : "false") + ",\n  \"escape_chord\": ";
    if (config.escape_chord.empty()) text += "[]";
    else {
        text += "[";
        for (size_t i = 0; i < config.escape_chord.size(); ++i) text += (i ? ",\n    " : "\n    ") + std::to_string(config.escape_chord[i]);
        text += "\n  ]";
    }
    text += "\n}";
    const std::string staging = std::string(KeyboardGrabConfig::name) + ".tmp";
    struct stat owner{};
    if (files_.get() < 0 || fstat(files_.get(), &owner) != 0 || !S_ISDIR(owner.st_mode))
        throw std::runtime_error(std::string("no directory for ") + KeyboardGrabConfig::name);
    bool ok = false;
    {
        Fd file(openat(files_.get(), staging.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600));
        if (file.get() >= 0) {
            std::string_view rest = text;
            while (!rest.empty()) {
                const auto count = write(file.get(), rest.data(), rest.size());
                if (count < 0 && errno == EINTR) continue;
                if (count <= 0) break;
                rest.remove_prefix(static_cast<size_t>(count));
            }
            ok = rest.empty() && fsync(file.get()) == 0 && fchmod(file.get(), 0600) == 0 &&
                fchown(file.get(), owner.st_uid, owner.st_gid) == 0;
        }
    }
    ok = ok && renameat(files_.get(), staging.c_str(), files_.get(), KeyboardGrabConfig::name) == 0;
    const int error = errno;
    unlinkat(files_.get(), staging.c_str(), 0);
    if (!ok) throw std::runtime_error(std::string("cannot replace ") + KeyboardGrabConfig::name + ": " + std::strerror(error));
}
void KeyboardGrab::set_config(const KeyboardGrabConfig& config) {
    {
        std::lock_guard lock(save_mutex_);
        save(config);
        std::lock_guard current(config_mutex_);
        config_ = config;
    }
    // A switch that only applied to the next console would leave this one holding it.
    if (!config.enabled) release("disabled");
}
int KeyboardGrab::request(const std::string& vm, const std::string& screen, std::shared_ptr<Owner> owner) {
    if (!config().enabled) return 0;
    const auto canonical = hooks_.find ? hooks_.find(vm) : std::nullopt;
    if (!canonical) return 0;
    std::lock_guard lock(lock_);
    // Only one console is in front: another VM or screen takes it over.
    auto current = this->current();
    if (current && (current->vm != vm || current->screen != screen)) release_locked("taken over by another console");
    if (!this->current()) {
        auto target = std::make_shared<Target>();
        target->vm = vm;
        target->canonical = *canonical;
        target->screen = screen;
        target->owner = std::move(owner);
        if (!link(target)) return 0;
        { std::lock_guard guard(target_mutex_); target_ = target; }
        hooks_.log("INFO", "KeyboardGrab: console for VM " + vm + " screen " + screen + " has the keyboard");
    }
    // Armed either way; the keys are only taken once the guest runs (see on_vm_state).
    if (hooks_.running && hooks_.running(*canonical)) grab_missing_locked();
    start_watcher_locked();
    return static_cast<int>(grabs_.size());
}
bool KeyboardGrab::release_for(const std::string& vm, const std::string& screen) {
    std::lock_guard lock(lock_);
    // The outgoing console reports after the incoming one already asked.
    const auto current = this->current();
    if (!current || current->vm != vm || current->screen != screen) return false;
    release_locked("console released it");
    return true;
}
void KeyboardGrab::set_echo(const std::string& vm, const std::string& screen, std::shared_ptr<Echo> echo) {
    const auto current = this->current();
    if (!current || current->vm != vm || current->screen != screen) return;
    { std::lock_guard lock(target_mutex_); current->echo = echo; }
    if (echo) send_leds(echo);
}
void KeyboardGrab::release(const std::string& reason) {
    std::lock_guard lock(lock_);
    release_locked(reason);
}
void KeyboardGrab::on_vm_state(const std::string& vm, const std::string& name, const std::string& state) {
    auto current = this->current();
    if (!current || current->canonical != vm) return;
    std::lock_guard lock(lock_);
    // A release may have won the race to the lock.
    const auto armed = this->current();
    if (!armed || armed->canonical != vm) return;
    if (state == "running") { grab_missing_locked(); return; }
    const auto reason = "VM " + name + " is " + state;
    if (armed->owner) {
        // A console in front of a guest that is likely back soon stays armed.
        drop_grabs_locked(reason);
        led_known_ = 0;
        led_on_ = 0;
        send_leds(echo_of(armed));
    } else release_locked(reason); // an IPC grab has no token to end it
}
Json::Value KeyboardGrab::status() const {
    Json::Value value;
    value["config"] = config().json();
    const auto current = this->current();
    value["armed"] = current != nullptr;
    if (current) { value["vm_id"] = current->vm; value["screen"] = current->screen; }
    Json::Value held(Json::arrayValue);
    std::vector<std::string> paths;
    {
        std::lock_guard lock(lock_);
        for (const auto& [path, grab] : grabs_) { held.append(grab->device.json()); paths.push_back(path); }
    }
    value["held"] = held;
    const int known = led_known_, on = led_on_;
    auto& leds = value["leds"];
    leds["known"] = known;
    leds["on"] = on;
    leds["num"] = (known & 1) == 0 ? Json::Value() : Json::Value((on & 1) != 0);
    leds["caps"] = (known & 2) == 0 ? Json::Value() : Json::Value((on & 2) != 0);
    leds["scroll"] = (known & 4) == 0 ? Json::Value() : Json::Value((on & 4) != 0);
    Json::Value keyboards(Json::arrayValue);
    for (const auto& keyboard : hooks_.scan()) {
        auto entry = keyboard.json();
        entry["held"] = std::find(paths.begin(), paths.end(), keyboard.path) != paths.end();
        keyboards.append(std::move(entry));
    }
    value["keyboards"] = keyboards;
    return value;
}
int KeyboardGrab::grab_missing_locked() {
    int taken = 0;
    for (const auto& keyboard : hooks_.scan()) {
        if (grabs_.contains(keyboard.path)) continue;
        if (grab_one_locked(keyboard)) ++taken;
    }
    return taken;
}
bool KeyboardGrab::grab_one_locked(const HostKeyboard& keyboard) {
    // Read-write for the lamps; a node that refuses it is still readable.
    int raw = open(keyboard.path.c_str(), O_RDWR | O_CLOEXEC);
    if (raw < 0) raw = open(keyboard.path.c_str(), O_RDONLY | O_CLOEXEC);
    if (raw < 0) { hooks_.log("WARN", "KeyboardGrab: cannot open " + keyboard.text()); return false; }
    Fd fd(raw);
    if (ioctl(fd.get(), EVIOCGRAB, 1) != 0) {
        // EBUSY: somebody else holds this keyboard exclusively.
        const int error = errno;
        hooks_.log("WARN", "KeyboardGrab: cannot grab " + keyboard.text() + ": errno=" + std::to_string(error));
        return false;
    }
    int pipes[2];
    if (pipe2(pipes, O_CLOEXEC) != 0) {
        hooks_.log("WARN", "KeyboardGrab: no wake pipe for " + keyboard.text() + "; leaving it to Android");
        ioctl(fd.get(), EVIOCGRAB, 0);
        return false;
    }
    auto grab = std::make_shared<Grab>();
    grab->device = keyboard;
    grab->fd = std::move(fd);
    grab->wake_read = Fd(pipes[0]);
    grab->wake_write = Fd(pipes[1]);
    grabs_[keyboard.path] = grab;
    auto name = "kbd-grab-" + keyboard.path.substr(keyboard.path.rfind('/') + 1);
    spawn([this, grab, name = name.substr(0, 15)] { pthread_setname_np(pthread_self(), name.c_str()); read_events(grab); });
    // A late keyboard starts with the lamps the guest already reported.
    write_leds(*grab);
    hooks_.log("INFO", "KeyboardGrab: grabbed " + keyboard.text() + " for the guest");
    return true;
}
void KeyboardGrab::drop_grabs_locked(const std::string& reason) {
    if (grabs_.empty()) return;
    // Key-ups first, while the target is there: no modifier stays down in the guest.
    for (auto& [path, grab] : grabs_) release_held_keys(*grab);
    std::vector<std::shared_ptr<Grab>> pending;
    for (auto& [path, grab] : grabs_) pending.push_back(grab);
    grabs_.clear();
    for (auto& grab : pending) { grab->stopping = true; wake(grab->wake_write); }
    for (auto& grab : pending) {
        std::unique_lock done(grab->done_mutex);
        grab->done_ready.wait_for(done, reader_join, [&] { return grab->done; });
    }
    hooks_.log("INFO", "KeyboardGrab: keyboard back to Android (" + reason + ")");
}
void KeyboardGrab::release_locked(const std::string& reason) {
    const auto current = this->current();
    if (!current && grabs_.empty()) return;
    drop_grabs_locked(reason);
    { std::lock_guard lock(target_mutex_); target_.reset(); }
    // The lamps were this guest's; the next console may show another.
    led_known_ = 0;
    led_on_ = 0;
    if (current && current->owner) current->owner->unlink();
    stop_watcher_locked();
}
void KeyboardGrab::read_events(const std::shared_ptr<Grab>& grab) {
    std::vector<char> buffer(sizeof(input_event) * events_per_read);
    while (!grab->stopping) {
        pollfd fds[2] = {{grab->fd.get(), POLLIN, 0}, {grab->wake_read.get(), POLLIN, 0}};
        int ready;
        do ready = poll(fds, 2, -1); while (ready < 0 && errno == EINTR);
        if (ready < 0) { hooks_.log("WARN", "KeyboardGrab: poll failed on " + grab->device.text()); break; }
        // A keyboard that went away hangs up, and its node is gone with it.
        if ((fds[0].revents | fds[1].revents) & (POLLERR | POLLHUP | POLLNVAL)) break;
        if (fds[1].revents & POLLIN) break;
        if (!(fds[0].revents & POLLIN)) continue;
        ssize_t count;
        do count = read(grab->fd.get(), buffer.data(), buffer.size()); while (count < 0 && errno == EINTR);
        if (count <= 0) {
            if (!grab->stopping)
                hooks_.log("INFO", "KeyboardGrab: " + grab->device.text() + " stopped reporting (read=" + std::to_string(count < 0 ? -1 : 0) + "); dropped");
            break;
        }
        on_events(*grab, buffer.data(), static_cast<size_t>(count));
    }
    // A reader that ended by itself is still listed; the console stays armed for its return.
    if (!grab->stopping) {
        std::lock_guard lock(lock_);
        const auto at = grabs_.find(grab->device.path);
        if (at != grabs_.end() && at->second == grab) grabs_.erase(at);
    }
    // The reader ungrabs: nothing is read out of the node as it goes back to Android.
    ioctl(grab->fd.get(), EVIOCGRAB, 0);
    std::lock_guard done(grab->done_mutex);
    grab->done = true;
    grab->done_ready.notify_all();
}
void KeyboardGrab::on_events(Grab& grab, const char* buffer, size_t length) {
    // Auto-repeat is dropped: the guest repeats held keys itself.
    std::string out;
    std::vector<int> codes, values;
    bool escape = false;
    for (size_t offset = 0; offset + sizeof(input_event) <= length; offset += sizeof(input_event)) {
        input_event event;
        std::memcpy(&event, buffer + offset, sizeof(event));
        const auto code = static_cast<int16_t>(event.code);
        if (event.type == EV_KEY) {
            if (event.value == key_repeat) continue;
            if (code >= 0 && static_cast<size_t>(code) < key_count) {
                { std::lock_guard lock(grab.pressed_mutex); grab.pressed[static_cast<size_t>(code)] = event.value != key_up; }
                // The key completing the chord is ours, not the guest's.
                if (event.value == key_down && chord_held(grab)) { escape = true; break; }
            }
            append(out, event.type, event.code, event.value);
            codes.push_back(code);
            values.push_back(event.value);
        } else if (event.type == EV_SYN && event.code == SYN_REPORT) {
            if (!out.empty()) append(out, event.type, event.code, event.value);
        }
    }
    if (!out.empty()) deliver(out);
    // The console's copy goes after the guest's, never in the way of typing.
    if (!codes.empty()) {
        const auto current = this->current();
        const auto echo = echo_of(current);
        if (echo && echo->keys) {
            try { echo->keys(codes, values); }
            catch (...) {
                { std::lock_guard lock(target_mutex_); if (current->echo == echo) current->echo.reset(); }
                hooks_.log("DEBUG", "KeyboardGrab: console echo is gone; keys stay between the daemon and the guest");
            }
        }
    }
    if (escape) spawn([this] { pthread_setname_np(pthread_self(), "kbd-grab-escape"); release("escape chord"); });
}
bool KeyboardGrab::chord_held(Grab& grab) const {
    const auto chord = config().escape_chord;
    if (chord.empty()) return false;
    std::lock_guard lock(grab.pressed_mutex);
    for (const int code : chord) if (code < 0 || static_cast<size_t>(code) >= key_count || !grab.pressed[static_cast<size_t>(code)]) return false;
    return true;
}
void KeyboardGrab::release_held_keys(Grab& grab) {
    std::string out;
    {
        std::lock_guard lock(grab.pressed_mutex);
        for (size_t code = 0; code < key_count; ++code) {
            if (!grab.pressed[code]) continue;
            grab.pressed[code] = false;
            append(out, EV_KEY, static_cast<uint16_t>(code), key_up);
        }
    }
    if (out.empty()) return;
    append(out, EV_SYN, SYN_REPORT, 0);
    deliver(out);
}
void KeyboardGrab::deliver(std::string_view records) {
    const auto current = this->current();
    if (!current || !hooks_.deliver) return;
    try { hooks_.deliver(current->canonical, current->screen, records); } catch (...) {}
}
void KeyboardGrab::on_guest_status(const std::string& vm, const std::string& screen, std::string_view records) {
    const auto current = this->current();
    if (!current || current->canonical != vm || current->screen != screen) return;
    int known = led_known_, on = led_on_;
    bool changed = false;
    for (size_t offset = 0; offset + 8 <= records.size(); offset += 8) {
        int16_t type, code;
        int32_t value;
        std::memcpy(&type, records.data() + offset, 2);
        std::memcpy(&code, records.data() + offset + 2, 2);
        std::memcpy(&value, records.data() + offset + 4, 4);
        // EV_REP is the host keyboard's business: the guest repeats for itself.
        if (type != EV_LED || code < 0 || code >= led_count) continue;
        const int bit = 1 << code;
        known |= bit;
        const int next = value != 0 ? (on | bit) : (on & ~bit);
        if (next != on || known != led_known_) changed = true;
        on = next;
    }
    if (!changed) return;
    led_known_ = known;
    led_on_ = on;
    hooks_.log("INFO", std::string("KeyboardGrab: guest lamps: num=") + lamp(known, on, 1) + " caps=" + lamp(known, on, 2) + " scroll=" + lamp(known, on, 4));
    {
        std::lock_guard lock(lock_);
        for (auto& [path, grab] : grabs_) write_leds(*grab);
    }
    send_leds(echo_of(current));
}
void KeyboardGrab::write_leds(Grab& grab) {
    const int known = led_known_, on = led_on_;
    if (known == 0) return;
    std::string out;
    for (int code = 0; code < led_count; ++code)
        if (known & (1 << code)) append_event(out, EV_LED, static_cast<uint16_t>(code), (on & (1 << code)) != 0 ? 1 : 0);
    if (out.empty()) return;
    append_event(out, EV_SYN, SYN_REPORT, 0);
    while (write(grab.fd.get(), out.data(), out.size()) < 0 && errno == EINTR) {}
}
void KeyboardGrab::send_leds(const std::shared_ptr<Echo>& echo) {
    if (!echo || !echo->leds) return;
    try { echo->leds(led_known_, led_on_); }
    catch (...) { hooks_.log("DEBUG", "KeyboardGrab: console echo refused the lamps"); }
}
bool KeyboardGrab::link(const std::shared_ptr<Target>& target) {
    if (!target->owner) return true;
    if (target->owner->link([this] { release("console gone"); })) return true;
    hooks_.log("WARN", "KeyboardGrab: console token is already dead; not arming");
    return false;
}
void KeyboardGrab::start_watcher_locked() {
    // Best effort: without it only the keyboards present at the request are held.
    if (watcher_) return;
    Fd fd(socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT));
    sockaddr_nl address{};
    address.nl_family = AF_NETLINK;
    address.nl_groups = 1;
    if (fd.get() >= 0) {
        int size = 1 << 20;
        if (setsockopt(fd.get(), SOL_SOCKET, SO_RCVBUFFORCE, &size, sizeof(size)) < 0)
            setsockopt(fd.get(), SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    }
    if (fd.get() < 0 || bind(fd.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
        hooks_.log("WARN", "KeyboardGrab: no uevent socket; a keyboard that reconnects will not be re-grabbed");
        return;
    }
    int pipes[2];
    if (pipe2(pipes, O_CLOEXEC) != 0) return;
    auto watcher = std::make_shared<Watcher>();
    watcher->fd = std::move(fd);
    watcher->wake_read = Fd(pipes[0]);
    watcher->wake_write = Fd(pipes[1]);
    watcher_ = watcher;
    spawn([this, watcher] { pthread_setname_np(pthread_self(), "kbd-grab-uevent"); read_uevents(watcher); });
}
void KeyboardGrab::stop_watcher_locked() {
    // No join: its rescan wants this lock. The thread owns the descriptors.
    auto watcher = std::move(watcher_);
    watcher_.reset();
    if (!watcher) return;
    watcher->stopping = true;
    wake(watcher->wake_write);
}
void KeyboardGrab::read_uevents(const std::shared_ptr<Watcher>& watcher) {
    // A keyboard arrives as several messages: one scan once the batch settles.
    char buffer[4096];
    bool pending = false;
    while (!watcher->stopping) {
        pollfd fds[2] = {{watcher->fd.get(), POLLIN, 0}, {watcher->wake_read.get(), POLLIN, 0}};
        int ready;
        do ready = poll(fds, 2, pending ? rescan_debounce_ms : -1); while (ready < 0 && errno == EINTR);
        if (ready < 0) break;
        if (ready == 0) { pending = false; rescan(watcher); continue; }
        if ((fds[0].revents | fds[1].revents) & (POLLERR | POLLHUP | POLLNVAL)) break;
        if (fds[1].revents & POLLIN) break;
        if (!(fds[0].revents & POLLIN)) continue;
        const auto count = recv(watcher->fd.get(), buffer, sizeof(buffer), 0);
        if (count <= 0) continue;
        if (std::string_view(buffer, static_cast<size_t>(count)).find("SUBSYSTEM=input") != std::string_view::npos) pending = true;
    }
}
void KeyboardGrab::rescan(const std::shared_ptr<Watcher>& watcher) {
    std::lock_guard lock(lock_);
    // The release that retired this watcher may have won the race to the lock.
    if (watcher->stopping || watcher_ != watcher || !current()) return;
    const int taken = grab_missing_locked();
    if (taken > 0) hooks_.log("INFO", "KeyboardGrab: " + std::to_string(taken) + " keyboard(s) joined the grab");
}
}
