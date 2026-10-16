// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "common/identity.h"
#include "input/keyboard_grab.h"
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <linux/input.h>
#include <sys/stat.h>

using namespace droidvm;
using namespace droidvm::test;
using namespace droidvm::input;
namespace {
struct Temporary {
    std::string path = "/data/local/tmp/droidvm-keyboard-" + random_id(false);
    Fd directory;
    Temporary() {
        check(mkdir(path.c_str(), 0700) == 0, "create test directory");
        directory = Fd(open(path.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC));
        check(directory.get() >= 0, "open test directory");
    }
    ~Temporary() {
        if (DIR* scan = opendir(path.c_str())) {
            while (auto* entry = readdir(scan)) if (std::string_view(entry->d_name) != "." && std::string_view(entry->d_name) != "..")
                unlinkat(directory.get(), entry->d_name, 0);
            closedir(scan);
        }
        rmdir(path.c_str());
    }
    void put(std::string_view bytes) {
        Fd file(openat(directory.get(), KeyboardGrabConfig::name, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
        check(file.get() >= 0 && write(file.get(), bytes.data(), bytes.size()) == static_cast<ssize_t>(bytes.size()), "write fixture");
    }
    std::string get() {
        Fd file(openat(directory.get(), KeyboardGrabConfig::name, O_RDONLY | O_CLOEXEC));
        std::string text;
        char buffer[512];
        for (ssize_t count; file.get() >= 0 && (count = read(file.get(), buffer, sizeof(buffer))) > 0;) text.append(buffer, static_cast<size_t>(count));
        return text;
    }
};
// Two VMs; "vm-a" is running. A keyboard whose node does not exist cannot be grabbed.
struct World {
    std::mutex mutex;
    std::vector<std::string> delivered, logs;
    bool running = true;
    KeyboardGrab::Hooks hooks() {
        KeyboardGrab::Hooks hooks;
        hooks.find = [](const std::string& vm) -> std::optional<std::string> {
            if (vm == "vm-a" || vm == "VM-A") return "vm-a";
            if (vm == "vm-b") return "vm-b";
            return std::nullopt;
        };
        hooks.running = [this](const std::string& vm) { std::lock_guard lock(mutex); return vm == "vm-a" && running; };
        hooks.deliver = [this](const std::string& vm, const std::string& screen, std::string_view records) {
            std::lock_guard lock(mutex); delivered.push_back(vm + "/" + screen + "/" + std::to_string(records.size())); return true;
        };
        hooks.scan = [] {
            HostKeyboard keyboard;
            keyboard.path = "/dev/input/event-droidvm-absent";
            keyboard.name = "Absent";
            keyboard.bus = 3; keyboard.vendor = 0x46d; keyboard.product = 0xc31c;
            return std::vector<HostKeyboard>{keyboard};
        };
        hooks.log = [this](const char* level, const std::string& text) { std::lock_guard lock(mutex); logs.push_back(std::string(level) + " " + text); };
        return hooks;
    }
    bool logged(const std::string& text) {
        std::lock_guard lock(mutex);
        for (const auto& line : logs) if (line.find(text) != std::string::npos) return true;
        return false;
    }
};
struct Token : KeyboardGrab::Owner {
    bool alive = true;
    int links = 0, unlinks = 0;
    std::function<void()> died;
    bool link(std::function<void()> callback) override { ++links; died = std::move(callback); return alive; }
    void unlink() override { ++unlinks; }
};
Json::Value parse(const std::string& text) { return wire::parse(text); }
void java_values() {
    check(java_int(parse("12"), -1) == 12 && java_int(parse("12.9"), -1) == 12 && java_int(parse("\"30\""), -1) == 30, "optInt numbers");
    check(java_int(parse("\"3x\""), -1) == -1 && java_int(parse("true"), -1) == -1 && java_int(parse("null"), -1) == -1, "optInt fallback");
    check(java_int(parse("4294967326"), -1) == 30, "Long.intValue wraps");
    check(java_int(parse("1e10"), -1) == 2147483647 && java_int(parse("18446744073709551615"), -1) == 2147483647, "Double saturates");
    check(java_boolean(parse("\"FALSE\""), true) == false && java_boolean(parse("\"yes\""), true) && !java_boolean(parse("1"), false), "optBoolean");
}
void config_shape() {
    auto config = KeyboardGrabConfig::from_json(parse(R"({"enabled":"false","escape_chord":[29,"56",29,0,768,767,-1,"x",1.5]})"));
    check(!config.enabled && config.escape_chord == std::vector<int>({29, 56, 767, 1}), "chord filtered and deduplicated in order");
    config = KeyboardGrabConfig::from_json(parse(R"({"escape_chord":"29"})"));
    check(config.enabled && config.escape_chord.empty(), "defaults: enabled, nothing bound");
    check(wire::stringify(config.json()) == R"({"enabled":true,"escape_chord":[]})", "toJson shape");
}
void persistence() {
    Temporary dir;
    World world;
    {
        KeyboardGrab grab(dir.directory.get(), world.hooks());
        check(grab.config().enabled && grab.config().escape_chord.empty(), "absent file is the defaults");
        grab.set_config({true, {29, 56}});
        check(dir.get() == "{\n  \"enabled\": true,\n  \"escape_chord\": [\n    29,\n    56\n  ]\n}", "JSONObject.toString(2) text");
        struct stat info{};
        check(fstatat(dir.directory.get(), KeyboardGrabConfig::name, &info, 0) == 0 && (info.st_mode & 0777) == 0600, "file mode 0600");
        check(faccessat(dir.directory.get(), "keyboard_grab.json.tmp", F_OK, 0) != 0, "no staging file left");
        grab.set_config({false, {}});
        check(dir.get() == "{\n  \"enabled\": false,\n  \"escape_chord\": []\n}", "empty chord text");
    }
    {
        KeyboardGrab grab(dir.directory.get(), world.hooks());
        check(!grab.config().enabled, "saved settings load back");
    }
    dir.put("{not json");
    KeyboardGrab grab(dir.directory.get(), world.hooks());
    check(grab.config().enabled && world.logged("Cannot read keyboard_grab.json; using the defaults"), "corrupt file is the defaults");
    KeyboardGrab orphan(-1, world.hooks());
    bool refused = false;
    try { orphan.set_config({true, {}}); } catch (const std::exception&) { refused = true; }
    check(refused, "no directory refuses the save");
}
void status_and_ipc_grab() {
    Temporary dir;
    World world;
    KeyboardGrab grab(dir.directory.get(), world.hooks());
    auto status = grab.status();
    check(status["armed"] == false && !status.isMember("vm_id") && status["held"] == Json::Value(Json::arrayValue), "idle status");
    check(wire::stringify(status["leds"]) == R"({"caps":null,"known":0,"num":null,"on":0,"scroll":null})", "unknown lamps are null");
    check(wire::stringify(status["keyboards"]) == R"([{"bus":"0003","held":false,"name":"Absent","path":"/dev/input/event-droidvm-absent","product":"c31c","vendor":"046d"}])", "keyboard rows");
    check(grab.request("vm-x", "simplefb") == 0 && grab.status()["armed"] == false, "unknown VM is not armed");
    check(grab.request("VM-A", "simplefb") == 0, "nothing held: the node cannot be opened");
    status = grab.status();
    check(status["armed"] == true && status["vm_id"] == "VM-A" && status["screen"] == "simplefb", "armed as asked");
    check(world.logged("cannot open /dev/input/event-droidvm-absent \"Absent\" 046d:c31c"), "open failure logged as HostKeyboard");
    grab.on_vm_state("vm-b", "b", "stopping");
    check(grab.status()["armed"] == true, "another VM's transition is ignored");
    // Records arrive under the canonical id and are matched against it.
    std::string records(8, '\0');
    const int16_t type = EV_LED, code = LED_CAPSL;
    const int32_t value = 1;
    std::memcpy(records.data(), &type, 2); std::memcpy(records.data() + 2, &code, 2); std::memcpy(records.data() + 4, &value, 4);
    grab.on_guest_status("vm-a", "gpu-0", records);
    check(grab.status()["leds"]["known"] == 0, "another screen's lamps are ignored");
    grab.on_guest_status("vm-a", "simplefb", records + std::string(3, '\0'));
    status = grab.status();
    check(status["leds"]["known"] == 2 && status["leds"]["on"] == 2 && status["leds"]["caps"] == true && status["leds"]["num"].isNull(), "guest caps lamp");
    check(world.logged("guest lamps: num=? caps=on scroll=?"), "lamp log");
    check(!grab.release_for("VM-A", "gpu-0") && grab.status()["armed"] == true, "release for another screen");
    grab.on_vm_state("vm-a", "alpha", "stopping");
    status = grab.status();
    check(status["armed"] == false && status["leds"]["known"] == 0, "IPC grab ends when the VM leaves RUNNING");
    check(grab.request("vm-a", "simplefb") == 0 && grab.status()["armed"] == true, "re-armed");
    check(grab.request("vm-b", "simplefb") == 0 && grab.status()["vm_id"] == "vm-b", "another VM takes it over");
    grab.set_config({false, {}});
    check(grab.status()["armed"] == false, "disabling releases");
    check(grab.request("vm-a", "simplefb") == 0 && grab.status()["armed"] == false, "disabled refuses");
}
void console_token() {
    Temporary dir;
    World world;
    KeyboardGrab grab(dir.directory.get(), world.hooks());
    auto dead = std::make_shared<Token>();
    dead->alive = false;
    check(grab.request("vm-a", "simplefb", dead) == 0 && grab.status()["armed"] == false && world.logged("already dead; not arming"), "dead token");
    auto token = std::make_shared<Token>();
    grab.request("vm-a", "simplefb", token);
    check(token->links == 1 && grab.status()["armed"] == true, "linked");
    grab.request("vm-a", "simplefb", std::make_shared<Token>());
    check(token->links == 1, "same console asking again keeps its token");
    std::vector<std::pair<int, int>> lamps;
    auto echo = std::make_shared<KeyboardGrab::Echo>();
    echo->leds = [&](int known, int on) { lamps.emplace_back(known, on); };
    grab.set_echo("vm-a", "gpu-0", echo);
    check(lamps.empty(), "echo of another console ignored");
    grab.set_echo("vm-a", "simplefb", echo);
    check(lamps.size() == 1 && lamps[0] == std::make_pair(0, 0), "echo answered with the lamps");
    grab.on_vm_state("vm-a", "alpha", "rebooting");
    check(grab.status()["armed"] == true && lamps.size() == 2, "console stays armed across a reboot");
    token->died();
    check(grab.status()["armed"] == false && token->unlinks == 1, "token death releases");
}
}

int main() {
    return run({{"java_opt_semantics", java_values},
                {"config_from_json", config_shape},
                {"config_file", persistence},
                {"status_and_ipc_grab", status_and_ipc_grab},
                {"console_token", console_token}});
}
