// SPDX-License-Identifier: GPL-3.0-or-later
// Device test helper: a virtual keyboard through /dev/uinput, and probes that
// only ever touch the evdev node carrying that keyboard's exact name.
#include "input/keyboard_grab.h"
#include "common/wire.h"
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <linux/uinput.h>
#include <poll.h>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <thread>
#include <unistd.h>

using droidvm::Fd;
namespace {
void say(const std::string& line) { std::printf("%s\n", line.c_str()); std::fflush(stdout); }
bool emit(int fd, uint16_t type, uint16_t code, int32_t value) {
    input_event event{};
    event.type = type;
    event.code = code;
    event.value = value;
    return write(fd, &event, sizeof(event)) == static_cast<ssize_t>(sizeof(event));
}
// Opens path only when it is the named test keyboard.
Fd open_named(const std::string& path, const std::string& name, int flags) {
    Fd fd(open(path.c_str(), flags | O_CLOEXEC));
    char actual[256] = {};
    if (fd.get() < 0 || ioctl(fd.get(), EVIOCGNAME(sizeof(actual) - 1), actual) < 0 || name != actual) return Fd();
    return fd;
}
int create(const std::string& name) {
    Fd fd(open("/dev/uinput", O_RDWR | O_NONBLOCK | O_CLOEXEC));
    if (fd.get() < 0) { say(std::string("error open uinput: ") + std::strerror(errno)); return 1; }
    bool ok = ioctl(fd.get(), UI_SET_EVBIT, EV_KEY) == 0 && ioctl(fd.get(), UI_SET_EVBIT, EV_SYN) == 0 &&
        ioctl(fd.get(), UI_SET_EVBIT, EV_LED) == 0 && ioctl(fd.get(), UI_SET_EVBIT, EV_MSC) == 0 &&
        ioctl(fd.get(), UI_SET_MSCBIT, MSC_SCAN) == 0;
    // Plain keyboard keys plus two codes no layout maps; no buttons, so Android sees a keyboard only.
    for (int key = KEY_ESC; ok && key <= KEY_MICMUTE; ++key) ok = ioctl(fd.get(), UI_SET_KEYBIT, key) == 0;
    for (const int key : {0x2f0, 0x2f1}) ok = ok && ioctl(fd.get(), UI_SET_KEYBIT, key) == 0;
    for (const int led : {LED_NUML, LED_CAPSL, LED_SCROLLL}) ok = ok && ioctl(fd.get(), UI_SET_LEDBIT, led) == 0;
    uinput_setup setup{};
    setup.id.bustype = BUS_VIRTUAL;
    setup.id.vendor = 0x1209;
    setup.id.product = 0xd7a1;
    setup.id.version = 1;
    std::snprintf(setup.name, sizeof(setup.name), "%s", name.c_str());
    ok = ok && ioctl(fd.get(), UI_DEV_SETUP, &setup) == 0 && ioctl(fd.get(), UI_DEV_CREATE) == 0;
    if (!ok) { say(std::string("error setup: ") + std::strerror(errno)); return 1; }
    char sysname[64] = {};
    std::string node;
    if (ioctl(fd.get(), UI_GET_SYSNAME(sizeof(sysname)), sysname) >= 0) {
        for (int attempt = 0; attempt < 50 && node.empty(); ++attempt) {
            if (DIR* dir = opendir(("/sys/devices/virtual/input/" + std::string(sysname)).c_str())) {
                while (auto* entry = readdir(dir)) if (std::string_view(entry->d_name).starts_with("event")) node = std::string("/dev/input/") + entry->d_name;
                closedir(dir);
            }
            if (node.empty()) std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }
    for (int attempt = 0; attempt < 100 && !node.empty() && access(node.c_str(), F_OK) != 0; ++attempt)
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    say("ready " + node);
    std::string line;
    for (;;) {
        pollfd fds[2] = {{STDIN_FILENO, POLLIN, 0}, {fd.get(), POLLIN, 0}};
        if (poll(fds, 2, -1) < 0) { if (errno == EINTR) continue; break; }
        if (fds[1].revents & POLLIN) {
            input_event event;
            while (read(fd.get(), &event, sizeof(event)) == static_cast<ssize_t>(sizeof(event)))
                if (event.type == EV_LED) say("led " + std::to_string(event.code) + " " + std::to_string(event.value));
        }
        if (!(fds[0].revents & (POLLIN | POLLHUP))) continue;
        char buffer[256];
        const auto count = read(STDIN_FILENO, buffer, sizeof(buffer));
        if (count <= 0) break;
        line.append(buffer, static_cast<size_t>(count));
        bool quit = false;
        for (size_t end; (end = line.find('\n')) != std::string::npos; line.erase(0, end + 1)) {
            std::istringstream command(line.substr(0, end));
            std::string verb;
            command >> verb;
            if (verb == "k") {
                int code = 0, value = 0;
                command >> code >> value;
                say(emit(fd.get(), EV_KEY, static_cast<uint16_t>(code), value) && emit(fd.get(), EV_SYN, SYN_REPORT, 0) ? "ok" : "error emit");
            } else if (verb == "m") {
                say(emit(fd.get(), EV_MSC, MSC_SCAN, 0x70004) && emit(fd.get(), EV_SYN, SYN_REPORT, 0) ? "ok" : "error emit");
            } else if (verb == "q") quit = true;
        }
        if (quit) break;
    }
    ioctl(fd.get(), UI_DEV_DESTROY);
    say("destroyed");
    return 0;
}
// Every event another reader of the node gets within the window.
int observe(const std::string& path, const std::string& name, int ms) {
    auto fd = open_named(path, name, O_RDONLY | O_NONBLOCK);
    if (fd.get() < 0) { say("error not the test keyboard"); return 1; }
    say("watching");
    Json::Value seen(Json::arrayValue);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    for (;;) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) break;
        pollfd item{fd.get(), POLLIN, 0};
        if (poll(&item, 1, static_cast<int>(left)) <= 0) continue;
        if (item.revents & (POLLERR | POLLHUP)) break;
        input_event event;
        while (read(fd.get(), &event, sizeof(event)) == static_cast<ssize_t>(sizeof(event))) {
            if (event.type == EV_SYN) continue;
            Json::Value row(Json::arrayValue);
            row.append(event.type); row.append(event.code); row.append(event.value);
            seen.append(row);
        }
    }
    say("seen " + droidvm::wire::stringify(seen));
    return 0;
}
int try_grab(const std::string& path, const std::string& name) {
    auto fd = open_named(path, name, O_RDONLY);
    if (fd.get() < 0) { say("error not the test keyboard"); return 1; }
    const int result = ioctl(fd.get(), EVIOCGRAB, 1) == 0 ? 0 : errno;
    if (result == 0) ioctl(fd.get(), EVIOCGRAB, 0);
    say("grab " + std::to_string(result));
    return 0;
}
}

int main(int argc, char** argv) {
    const std::string mode = argc > 1 ? argv[1] : "";
    if (mode == "list" && argc == 2) {
        Json::Value rows(Json::arrayValue);
        for (const auto& keyboard : droidvm::input::scan_keyboards()) rows.append(keyboard.json());
        say(droidvm::wire::stringify(rows));
        return 0;
    }
    if (mode == "create" && argc == 3) return create(argv[2]);
    if (mode == "observe" && argc == 5) return observe(argv[2], argv[3], std::atoi(argv[4]));
    if (mode == "grab" && argc == 4) return try_grab(argv[2], argv[3]);
    std::fprintf(stderr, "usage: %s list | create <name> | observe <node> <name> <ms> | grab <node> <name>\n", argv[0]);
    return 2;
}
