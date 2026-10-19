// SPDX-License-Identifier: GPL-3.0-or-later
// Host contract for the native USB passthrough port (daemon/usb). Runs over a
// fake sysfs tree in a scratch directory, a modelled kernel behind the sysfs
// writer and a fake crosvm control channel; never touches the real /sys.
#include "contracts.h"
#include "usb/control.h"
#include "usb/device.h"
#include "usb/engine.h"
#include "usb/host.h"
#include "usb/java.h"
#include "usb/rules.h"
#include "usb/rules_file.h"
#include "usb/service.h"
#include "services/context.h"
#include <sys/stat.h>
#include <unistd.h>
#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>

namespace fs = std::filesystem;
using namespace droidvm;
using namespace droidvm::usb;
using droidvm::test::check;

namespace {
std::string scratch = "/data/local/tmp";
Json::Value parse(const std::string& text) { return wire::parse(text); }
// One NETLINK_KOBJECT_UEVENT datagram: NUL-terminated fields.
std::string uevent(std::initializer_list<std::string_view> fields) {
    std::string out;
    for (auto field : fields) { out.append(field); out.push_back('\0'); }
    return out;
}
template <typename F> std::string request_error(F&& fn) {
    try { fn(); } catch (const RequestError& error) { return error.what(); }
    throw std::runtime_error("expected a RequestError");
}
void expect(const std::string& actual, const std::string& wanted) {
    if (actual != wanted) throw std::runtime_error("got \"" + actual + "\", wanted \"" + wanted + "\"");
}
void write_file(const fs::path& path, const std::string& text) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << text;
    check(static_cast<bool>(out), "write fixture file");
}
std::string read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), {});
}

// A fake /sys/bus/usb plus /dev/bus/usb and the app files directory.
struct Tree {
    struct Spec {
        std::string vid, pid, cls, serial;
        int busnum = 1, devnum = 1;
        std::vector<std::pair<std::string, std::string>> interfaces; // name, class
    };
    fs::path root, devices, files;
    std::map<std::string, Spec> specs;
    Tree() {
        auto pattern = scratch + "/droidvm-usb-XXXXXX";
        std::vector<char> name(pattern.begin(), pattern.end());
        name.push_back('\0');
        check(mkdtemp(name.data()) != nullptr, "mkdtemp");
        root = name.data();
        devices = root / "sys/bus/usb/devices";
        files = root / "files";
        fs::create_directories(devices);
        fs::create_directories(root / "sys/bus/usb/drivers");
        fs::create_directories(root / "dev/bus/usb");
        fs::create_directories(files);
        write_file(root / "sys/bus/usb/drivers_autoprobe", "1\n");
        write_file(root / "sys/bus/usb/drivers_probe", "");
    }
    ~Tree() { std::error_code ignored; fs::remove_all(root, ignored); }
    std::string sys() const { return (root / "sys").string(); }
    std::string dev() const { return (root / "dev/bus/usb").string(); }
    fs::path dir(const std::string& sysfs) const { return devices / sysfs; }
    // A device; [configured] false is one enumerated under the shut gate:
    // no configuration and no interface directory until a device probe.
    void add(const std::string& sysfs, Spec spec, bool configured = true, std::map<std::string, std::string> drivers = {}) {
        const auto d = dir(sysfs);
        fs::create_directories(d);
        write_file(d / "idVendor", spec.vid + "\n");
        write_file(d / "idProduct", spec.pid + "\n");
        write_file(d / "busnum", std::to_string(spec.busnum) + "\n");
        write_file(d / "devnum", std::to_string(spec.devnum) + "\n");
        write_file(d / "bDeviceClass", spec.cls + "\n");
        write_file(d / "manufacturer", "Maker\n");
        write_file(d / "product", "Thing " + sysfs + "\n");
        if (!spec.serial.empty()) write_file(d / "serial", spec.serial + "\n");
        write_file(d / "speed", "480\n");
        write_file(d / "authorized", "1\n");
        write_file(d / "bConfigurationValue", configured ? "1\n" : "\n");
        specs[sysfs] = spec;
        if (configured) publish(sysfs, drivers);
    }
    void publish(const std::string& sysfs, const std::map<std::string, std::string>& drivers = {}) {
        for (const auto& [name, cls] : specs[sysfs].interfaces) {
            const auto i = dir(sysfs) / name;
            if (fs::exists(i)) continue;
            fs::create_directories(i);
            write_file(i / "bInterfaceClass", cls + "\n");
            write_file(i / "bInterfaceSubClass", "01\n");
            write_file(i / "bInterfaceProtocol", "02\n");
            fs::create_directory_symlink(fs::path(sysfs) / name, devices / name);
            auto driver = drivers.find(name);
            if (driver != drivers.end() && !driver->second.empty()) bind(name, driver->second);
        }
        write_file(dir(sysfs) / "bConfigurationValue", "1\n");
    }
    void remove(const std::string& sysfs) {
        for (const auto& [name, cls] : specs[sysfs].interfaces) fs::remove(devices / name);
        fs::remove_all(dir(sysfs));
        specs.erase(sysfs);
    }
    fs::path iface(const std::string& name) const { return devices / name; }
    void bind(const std::string& name, const std::string& driver) {
        const auto link = iface(name) / "driver";
        std::error_code ignored;
        fs::remove(link, ignored);
        fs::create_directory_symlink("../../../../bus/usb/drivers/" + driver, link);
    }
    void unbind(const std::string& name) { std::error_code ignored; fs::remove(iface(name) / "driver", ignored); }
    std::string driver(const std::string& name) const { return read_driver(iface(name).string()); }
    std::string owner_of_node(const std::string& node) const {
        for (const auto& [sysfs, spec] : specs) {
            char buffer[64];
            std::snprintf(buffer, sizeof(buffer), "/%03d/%03d", spec.busnum, spec.devnum);
            if (node.ends_with(buffer)) return sysfs;
        }
        return {};
    }
};

// The kernel behind drivers_probe, unbind, authorized and the autoprobe flag.
struct Kernel : SysfsWriter {
    Tree& tree;
    std::mutex mutex;
    std::vector<std::pair<std::string, std::string>> writes;
    std::set<std::string> refuse; // interfaces no driver wants
    explicit Kernel(Tree& t) : tree(t) {}
    std::string write(const std::string& path, std::string_view text) override {
        std::lock_guard lock(mutex);
        const std::string value = trim(text);
        const std::string usb = tree.sys() + "/bus/usb/";
        writes.emplace_back(path.substr(path.starts_with(usb) ? usb.size() : 0), value);
        if (path == usb + "drivers_probe") {
            if (value.find(':') == std::string::npos) {
                if (!fs::exists(tree.dir(value))) return "No such device";
                tree.publish(value);
                if (!fs::is_symlink(tree.dir(value) / "driver")) fs::create_directory_symlink("../../../bus/usb/drivers/usb", tree.dir(value) / "driver");
            } else if (fs::exists(tree.iface(value)) && tree.driver(value).empty() && !refuse.contains(value)) {
                tree.bind(value, read_file(tree.iface(value) / "bInterfaceClass") == "09\n" ? "hub" : "usbhid");
            }
            return {};
        }
        if (path.ends_with("/unbind")) { tree.unbind(value); return {}; }
        write_file(path, std::string(text));
        return {};
    }
    size_t count(const std::string& path, const std::string& value) {
        std::lock_guard lock(mutex);
        return static_cast<size_t>(std::count(writes.begin(), writes.end(), std::pair{path, value}));
    }
    void clear() { std::lock_guard lock(mutex); writes.clear(); }
};

// crosvm usb over the fake tree: attach claims every interface through usbfs.
struct Control : UsbControl {
    Tree& tree;
    std::mutex mutex;
    int next_port = 1;
    std::map<int, std::string> ports;
    std::optional<std::string> refuse_token;
    std::string refuse_stderr;
    bool unreachable = false, sticky = false, socket_ready = true;
    std::vector<std::string> calls;
    explicit Control(Tree& t) : tree(t) {}
    int attach(const std::string& socket, const std::string& node) override {
        std::lock_guard lock(mutex);
        calls.push_back("attach " + node + " " + socket);
        if (unreachable) throw VmmUnreachable("failed to connect to socket: No such file\nmore");
        const auto sysfs = tree.owner_of_node(node);
        if (refuse_token) {
            // A refusal after a partial claim.
            if (!sysfs.empty() && !tree.specs[sysfs].interfaces.empty()) tree.bind(tree.specs[sysfs].interfaces[0].first, "usbfs");
            throw ControlRefused(*refuse_token, refuse_stderr);
        }
        check(!sysfs.empty(), "attach of an unknown node");
        for (const auto& [name, cls] : tree.specs[sysfs].interfaces) tree.bind(name, "usbfs");
        ports[next_port] = sysfs;
        return next_port++;
    }
    int detach(const std::string& socket, int port) override {
        std::lock_guard lock(mutex);
        calls.push_back("detach " + std::to_string(port) + " " + socket);
        if (unreachable) throw VmmUnreachable("failed to connect to socket");
        auto it = ports.find(port);
        if (it == ports.end()) throw ControlRefused("no_such_port");
        if (!sticky && tree.specs.contains(it->second))
            for (const auto& [name, cls] : tree.specs[it->second].interfaces) if (tree.driver(name) == "usbfs") tree.unbind(name);
        ports.erase(it);
        return port;
    }
    std::vector<ListEntry> list(const std::string&) override { return {}; }
    bool ready(const std::string&) override { return socket_ready; }
    void release_claims() {
        std::lock_guard lock(mutex);
        for (const auto& [sysfs, spec] : tree.specs)
            for (const auto& [name, cls] : spec.interfaces) if (tree.driver(name) == "usbfs") tree.unbind(name);
    }
};

struct Vms : UsbVms {
    mutable std::mutex mutex;
    std::map<std::string, UsbVm> vms;
    std::string stderr_text;
    std::optional<UsbVm> find(const std::string& id) const override {
        std::lock_guard lock(mutex);
        auto it = vms.find(id);
        return it == vms.end() ? std::nullopt : std::optional(it->second);
    }
    std::vector<UsbVm> list() const override {
        std::lock_guard lock(mutex);
        std::vector<UsbVm> out;
        for (const auto& [id, vm] : vms) out.push_back(vm);
        return out;
    }
    std::optional<uint64_t> stderr_mark(const std::string&) const override { std::lock_guard lock(mutex); return stderr_text.size(); }
    std::string stderr_since(const std::string&, uint64_t mark) const override { std::lock_guard lock(mutex); return stderr_text.substr(std::min<size_t>(mark, stderr_text.size())); }
    void add(const std::string& id, const std::string& name, VmState state, std::vector<std::string> controllers) {
        UsbVm vm;
        vm.id = id; vm.name = name; vm.state = state;
        vm.control_socket = "/run/" + name + ".sock";
        vm.config["peripherals"] = Json::Value(Json::arrayValue);
        Json::Value sound;
        sound["type"] = "virtio_sound";
        vm.config["peripherals"].append(sound);
        for (const auto& c : controllers) { Json::Value x; x["type"] = "xhci_usb"; x["id"] = c; vm.config["peripherals"].append(x); }
        std::lock_guard lock(mutex);
        vms[id] = std::move(vm);
    }
    void set_state(const std::string& id, VmState state) { std::lock_guard lock(mutex); vms[id].state = state; }
};

const std::string vm_a = "11111111-1111-1111-1111-111111111111";
const std::string vm_b = "22222222-2222-2222-2222-222222222222";

struct Rig {
    Tree tree;
    std::shared_ptr<Kernel> kernel = std::make_shared<Kernel>(tree);
    Control control{tree};
    Vms vms;
    std::mutex events_mutex;
    std::vector<Json::Value> events;
    std::vector<std::string> logs;
    struct Watch : UsbWatch {
        std::function<void(const WatchEvent&)> notify;
        std::atomic<bool> stopped{false};
        void start(std::function<void(const WatchEvent&)> n) override { notify = std::move(n); }
        void stop() override { stopped = true; }
    };
    Watch* watch = nullptr;
    std::unique_ptr<UsbService> service;
    void make(bool with_files = true, config::JsonFile::Observer observer = {}) {
        UsbOptions options;
        options.sys_root = tree.sys();
        options.dev_root = tree.dev();
        if (with_files) options.files_dir = tree.files.string();
        options.rules_observer = std::move(observer);
        options.vms = &vms;
        options.control = &control;
        auto owned = std::make_unique<Watch>();
        watch = owned.get();
        options.watch = std::move(owned);
        options.writer = kernel;
        options.publish = [this](const Json::Value& data) { std::lock_guard lock(events_mutex); events.push_back(data); };
        options.log = [this](const char* level, const std::string& message) { std::lock_guard lock(events_mutex); logs.push_back(std::string(level) + " " + message); };
        auto& t = options.timing;
        t.quiet_period = t.auto_attach_debounce = std::chrono::milliseconds(20);
        t.usbfs_release_timeout = std::chrono::milliseconds(150);
        t.usbfs_poll = t.interfaces_poll = std::chrono::milliseconds(5);
        t.interfaces_timeout = std::chrono::milliseconds(300);
        t.vmm_log_grace = std::chrono::milliseconds(5);
        t.ready_poll = t.retry_delay = std::chrono::milliseconds(20);
        t.ready_max_polls = 5;
        t.shutdown_wait = std::chrono::milliseconds(2000);
        service = std::make_unique<UsbService>(std::move(options));
    }
    void settle() { check(service->settle(std::chrono::seconds(10)), "service settle"); }
    size_t count_events(const std::string& name) {
        std::lock_guard lock(events_mutex);
        return static_cast<size_t>(std::count_if(events.begin(), events.end(), [&](const auto& e) { return e["event"].asString() == name; }));
    }
    bool logged(const std::string& text) {
        std::lock_guard lock(events_mutex);
        return std::any_of(logs.begin(), logs.end(), [&](const auto& line) { return line.find(text) != std::string::npos; });
    }
    Json::Value host_row(const std::string& sysfs) {
        const auto list = service->usb_host_list({});
        for (const auto& row : list["devices"]) if (row["sysfs"] == sysfs) return row;
        return {};
    }
};
Tree::Spec keyboard(int devnum = 3) { return {"046D", "C31C", "00", "KB01", 1, devnum, {{"1-1.1:1.0", "03"}, {"1-1.1:1.1", "03"}}}; }
Tree::Spec stick(int devnum = 4) { return {"0781", "5567", "00", "", 1, devnum, {{"1-1.2:1.0", "08"}}}; }
Tree::Spec hub() { return {"05e3", "0610", "09", "", 1, 2, {{"1-1:1.0", "09"}}}; }
Tree::Spec root_hub() { return {"1d6b", "0002", "09", "0000:00:14.0", 1, 1, {{"1-0:1.0", "09"}}}; }

// --- pure model ---
void java_values() {
    expect(java_double(1.0), "1.0");
    expect(java_double(2.5), "2.5");
    expect(java_double(1e7), "1.0E7");
    expect(java_double(1.25e-4), "1.25E-4");
    expect(java_double(0.001), "0.001");
    expect(java_double(123456.789), "123456.789");
    expect(java_string(parse(R"({"b":[1,2.0,"/"],"a":null})")), R"({"a":null,"b":[1,2,"\/"]})");
    const auto params = parse(R"({"n":null,"i":5,"d":5.0,"s":"x","t":true,"p":"7.9","q":"x"})");
    expect(opt_string(params, "n"), "null");
    expect(opt_string(params, "i"), "5");
    expect(opt_string(params, "d"), "5.0");
    expect(opt_string(params, "missing", "fb"), "fb");
    check(opt_int(params, "i", -1) == 5 && opt_int(params, "p", -1) == 7 && opt_int(params, "q", -1) == -1 && opt_int(params, "t", -1) == -1, "optInt");
    check(int_value(parse("[4294967297]")[0]) == 1, "Long.intValue wraps");
}
void rules_parse() {
    const auto exists = [](const std::string& vm, const std::optional<std::string>&) { return vm == vm_a; };
    const auto rules = Rules::from_json(parse(R"({"version":1,"enabled":false,
        "exact":[{"id":"046D:C31C:KB01","port":"1.1","vm":")" + vm_a + R"(","controller":"xhci-1"}],
        "port":[{"port":"1.2","target":"sink"}],
        "device":[{"id":"0781:5567","target":"host"},{"id":"abcd:EF01:SeRiAl"}],
        "any":null})"), exists);
    check(!rules.enabled(), "enabled false");
    check(rules.layer(Layer::exact)[0].id == "046d:c31c:KB01" && rules.layer(Layer::exact)[0].target == Target::vm, "id lowercased, serial kept, vm implied");
    check(rules.layer(Layer::device)[1].id == "abcd:ef01:SeRiAl" && rules.layer(Layer::device)[1].target == Target::host, "no vm is host");
    check(rules.layer(Layer::any).empty(), "null layer");
    const auto json = rules.to_json();
    check(json["version"] == 1 && json["enabled"] == false && json["exact"][0]["target"] == "vm" && json["exact"][0]["controller"] == "xhci-1", "to_json");
    check(!json["port"][0].isMember("vm") && json["port"][0]["target"] == "sink" && json["any"].isArray() && json["any"].empty(), "to_json shape");
    check(Rules::from_json(json, exists).to_json() == json, "round trip");
    check(Rules::from_json(parse(R"({"version":1.0})"), nullptr).enabled(), "1.0 is version 1; enabled defaults on");
    const std::vector<std::pair<std::string, std::string>> refused{
        {R"({"version":2})", "unsupported rules version 2"},
        {R"({"version":"1"})", "unsupported rules version 1"},
        {R"({"version":2.5})", "unsupported rules version 2.5"},
        {R"({"enabled":"yes"})", "enabled must be true or false"},
        {R"({"bogus":[]})", "unknown rules key: bogus"},
        {R"({"exact":{}})", "exact must be a list"},
        {R"({"any":[5]})", "any[0] must be an object"},
        {R"({"any":[{"color":1}]})", "any[0]: unknown field color"},
        {R"({"any":[{"vm":5}]})", "vm must be a string or null"},
        {R"({"any":[{"target":"guest"}]})", "any[0]: unknown target guest"},
        {R"({"exact":[{"port":"1"}]})", "exact[0]: missing id"},
        {R"({"port":[{"id":"0000:0000","port":"1"}]})", "port[0]: a port rule takes no id"},
        {R"({"exact":[{"id":"0000:0000"}]})", "exact[0]: missing port"},
        {R"({"device":[{"id":"0000:0000","port":"1"}]})", "device[0]: a device rule takes no port"},
        {R"({"any":[{"target":"sink","vm":"x"}]})", "any[0]: a sink rule takes no vm"},
        {R"({"any":[{"target":"vm"}]})", "any[0]: a vm rule needs a vm"},
        {R"({"any":[{"target":"host","vm":"x"}]})", "any[0]: a host rule takes no vm"},
        {R"({"any":[{"controller":"c"}]})", "any[0]: controller needs a vm"},
        {R"({"any":[{"vm":"x","controller":""}]})", "any[0]: controller must be a controller id or null"},
        {R"({"device":[{"id":"046d:c31"}]})", "device[0]: bad id 046d:c31 (want vid:pid or vid:pid:serial)"},
        {R"({"device":[{"id":"046d:c31c:"}]})", "device[0]: bad id 046d:c31c: (want vid:pid or vid:pid:serial)"},
        {R"({"device":[{"id":"046d:c31c:a\nb"}]})", "device[0]: bad id 046d:c31c:a\nb (want vid:pid or vid:pid:serial)"},
        {R"({"port":[{"port":"1..2"}]})", "port[0]: bad port 1..2 (want a port chain such as 1.2.2)"},
        {R"({"any":[{"vm":""}]})", "any[0]: vm must be a VM id or null"},
        {R"({"any":[{"vm":"ghost"}]})", "any[0]: VM not found: ghost"},
        {R"({"any":[{"vm":"ghost","controller":"c"}]})", "any[0]: VM ghost has no USB controller c"},
    };
    for (const auto& [text, message] : refused) expect(request_error([&] { Rules::from_json(parse(text), exists); }), message);
    // Null target check (start-up read): a rule for an unknown VM is kept.
    check(Rules::from_json(parse(R"({"any":[{"vm":"ghost"}]})"), nullptr).layer(Layer::any)[0].vm == "ghost", "start-up keeps dangling rule");
    check(valid_rule_port("3") && valid_rule_port("1.2.2") && !valid_rule_port("") && !valid_rule_port("1.") && !valid_rule_port("a"), "port pattern");
    // Android's regex is ICU: \d is any Nd digit, '.' also stops at \v and \f.
    check(valid_rule_port("\xd9\xa3.1") && !valid_rule_id("046d:c31c:a\vb") && !valid_rule_id("046d:c31c:a\fb"), "ICU pattern semantics");
}
void engine_decisions() {
    RuleEngine engine;
    std::map<std::string, VmState> states{{vm_a, VmState::running}, {vm_b, VmState::stopped}};
    std::map<std::string, std::vector<std::string>> controllers{{vm_a, {"xhci-0", "xhci-1"}}, {vm_b, {"xhci-0"}}};
    StateOf state_of = [&](const std::string& vm) -> std::optional<VmState> { auto it = states.find(vm); return it == states.end() ? std::nullopt : std::optional(it->second); };
    HasController has = [&](const std::string& vm, const std::optional<std::string>& c) {
        auto it = controllers.find(vm);
        if (it == controllers.end() || it->second.empty()) return false;
        return !c || std::find(it->second.begin(), it->second.end(), *c) != it->second.end();
    };
    engine.set_rules(Rules::from_json(parse(R"({"exact":[{"id":"046d:c31c:KB01","port":"1.1","vm":")" + vm_b + R"("}],
        "port":[{"port":"1.1","vm":")" + vm_a + R"(","controller":"xhci-9"}],
        "device":[{"id":"046d:c31c:KB01","vm":")" + vm_a + R"(","controller":"xhci-1"},{"id":"0781:5567","target":"sink"}],
        "any":[{"target":"host"}]})"), nullptr));
    EngineDevice kb{"1-1.1", "046d:c31c:KB01", "1.1", 3, DeviceState::hostuse};
    auto d = engine.decide(kb, state_of, has);
    check(d && d->layer == Layer::device && d->index == 0 && d->target == Target::vm && d->vm == vm_a && d->controller == "xhci-1", "stopped VM and missing controller skipped");
    expect(d->where(), "device[0]");
    engine.mark_failed("1-1.1", vm_a);
    d = engine.decide(kb, state_of, has);
    check(d && d->layer == Layer::any && d->target == Target::host, "failure skipped");
    engine.forget_failures_for(vm_a);
    check(engine.decide(kb, state_of, has)->target == Target::vm, "failure forgotten when the VM comes back");
    EngineDevice st{"1-1.2", "0781:5567", "1.2", 4, DeviceState::idle};
    engine.mark_failed("1-1.2", vm_a);
    check(engine.decide(st, state_of, has)->target == Target::sink, "sink never held back by a failure");
    EngineDevice other{"2-3", "ffff:0001", "3", 5, DeviceState::idle};
    engine.set_rules(Rules::from_json(parse(R"({"device":[{"id":"0781:5567","target":"sink"}]})"), nullptr));
    d = engine.decide(other, state_of, has);
    check(d && !d->layer && d->index == -1 && d->target == Target::host, "fifth zone");
    expect(d->where(), "the default rule");
    // Locks are per instance.
    engine.lock("2-3", 5);
    check(engine.is_locked("2-3", 5) && !engine.is_locked("2-3", 6), "lock by devnum");
    EngineDevice vmuse{"1-9", "aaaa:bbbb", "9", 9, DeviceState::vmuse};
    const auto plan = engine.plan({kb, st, other, vmuse}, state_of, has);
    check(plan.size() == 2 && plan[0].device.sysfs == "1-1.1" && plan[1].device.sysfs == "1-1.2", "plan skips locked and vmuse");
    engine.clear_locks();
    check(!engine.is_locked("2-3", 5), "clear_locks");
    // The master switch.
    const auto off = Rules::from_json(parse(R"({"enabled":false})"), nullptr);
    check(engine.save_owes(off) == SaveOwes::release, "falling edge releases");
    engine.set_rules(off);
    check(engine.save_owes(off) == SaveOwes::nothing && engine.save_owes(Rules::empty()) == SaveOwes::pass, "save owes");
    check(!engine.decide(kb, state_of, has) && engine.plan({kb}, state_of, has).empty(), "switch off decides nothing");
    check(!engine.recovers_idle_devices(false) && engine.recovers_idle_devices(true), "daemon start recovers");
}
void inventory_scan() {
    Tree tree;
    tree.add("usb1", root_hub(), true, {{"1-0:1.0", "hub"}});
    tree.add("1-1", hub(), true, {{"1-1:1.0", "hub"}});
    tree.add("1-1.1", keyboard(), true, {{"1-1.1:1.0", "usbhid"}});
    tree.add("1-1.2", stick(), true, {{"1-1.2:1.0", "usbfs"}});
    tree.add("1-1.3", {"1234", "ABCD", "ef", "", 1, 7, {{"1-1.3:1.0", "0e"}}}, false);
    fs::create_directories(tree.dir("1-1.9")); // torn down mid-scan
    fs::create_directories(tree.devices / "garbage");
    std::vector<std::string> warnings;
    const auto devices = scan_devices(tree.devices.string(), tree.dev(), [&](const std::string& w) { warnings.push_back(w); });
    check(devices.size() == 5 && devices[0].sysfs == "1-1" && devices[4].sysfs == "usb1", "sorted, torn skipped, names filtered");
    check(warnings.size() == 1 && warnings[0].starts_with("Skipping USB device 1-1.9: "), "torn device warned");
    const auto& kb = devices[1];
    check(kb.id == "046d:c31c:KB01" && kb.port == "1.1" && kb.node == tree.dev() + "/001/003" && kb.vid == "046d", "ids and node");
    check(kb.interfaces.size() == 2 && kb.interfaces[0].driver == "usbhid" && kb.interfaces[1].driver.empty(), "interfaces");
    check(kb.state() == DeviceState::hostuse && devices[2].state() == DeviceState::vmuse && devices[3].state() == DeviceState::idle, "states");
    check(devices[0].is_hub() && devices[4].is_hub() && !kb.is_hub(), "hubs");
    check(devices[4].interfaces.size() == 1 && devices[4].interfaces[0].name == "1-0:1.0", "root hub interface prefix");
    check(devices[3].interfaces.empty() && devices[3].id == "1234:abcd", "unconfigured device has no interface");
    const auto row = kb.to_json();
    check(row["state"] == "hostuse" && row["device_class"] == "00" && row["busnum"] == 1 && row["interfaces"][0]["class"] == "03" &&
          row["manufacturer"] == "Maker" && row["serial"] == "KB01" && row["speed"] == "480", "to_json");
    // Diff: a driver change, then a replug at the same address.
    tree.unbind("1-1.1:1.0");
    auto now = scan_devices(tree.devices.string(), tree.dev());
    auto diff = Diff::between(devices, now);
    check(diff.changed.size() == 1 && diff.added.empty() && diff.removed.empty() && std::string(diff.reason()) == "drivers", "driver change");
    tree.remove("1-1.2");
    tree.add("1-1.2", stick(11));
    diff = Diff::between(now, scan_devices(tree.devices.string(), tree.dev()));
    check(diff.added.size() == 1 && diff.removed.size() == 1 && std::string(diff.reason()) == "plug", "replug is add and remove");
    check(child_name("1-1/") == "1-1" && child_name("/1-1") == "1-1" && !child_name("../x") && !child_name("a/b") && !child_name(""), "File(root, name) normalisation");
    check(derive_port("usb1") == "usb1" && interface_prefix("usb12") == "12-0:", "port and prefix");
}
void pure_helpers() {
    auto event = Uevent::parse(uevent({"bind@/devices/x/usb1/1-1/1-1.6/1-1.6:1.0", "ACTION=bind", "DEVPATH=/devices/x/usb1/1-1/1-1.6/1-1.6:1.0",
                                      "SUBSYSTEM=usb", "DEVTYPE=usb_interface", "DRIVER=usbhid"}));
    check(event && event->action == "bind" && event->name == "1-1.6:1.0" && event->driver_change(), "uevent parse");
    expect(event->text(), "bind 1-1.6:1.0 (usbhid)");
    check(!Uevent::parse(uevent({"ACTION=add", "SUBSYSTEM=block", "DEVPATH=/x"})), "non-usb dropped");
    check(!Uevent::parse(uevent({"ACTION=add", "SUBSYSTEM=usb"})), "no devpath dropped");
    Leftovers left;
    left.leave("1-1.2:1.0", vm_a); left.leave("1-1.2:1.1", vm_a); left.leave("1-3:1.0", vm_b);
    check(left.left_by(vm_a) == std::vector<std::string>{"1-1.2:1.0", "1-1.2:1.1"}, "left_by in order");
    const auto scan = left.scan({{"1-1.2:1.0", ""}, {"1-1.2:1.1", "usbhid"}, {"1-3:1.0", "usbfs"}});
    check(scan.free == std::vector<std::string>{"1-1.2:1.0"} && scan.reclaimed.size() == 1 && left.size() == 2, "leftover scan");
    check(left.take({"1-1.2:1.0", "nope"}).size() == 1 && left.forget_device("1-3") == std::vector<std::string>{"1-3:1.0"} && left.empty(), "take and forget");
    check(parse_ok_port("\nok 3\n") == 3, "ok port");
    try { parse_ok_port("no_available_port\n"); throw std::runtime_error("refusal parsed"); } catch (const ControlRefused& e) { expect(e.token, "no_available_port"); }
    try { parse_ok_port("ok x"); throw std::runtime_error("bad port parsed"); } catch (const ControlRefused& e) { expect(e.token, "ok x"); }
    const auto list = parse_list("devices 1 046d c31c 2 0781 5567\n");
    check(list.size() == 2 && list[1].port == 2 && list[1].pid == "5567" && parse_list("devices").empty(), "list");
    try { parse_list("devices 1 046d"); throw std::runtime_error("partial list parsed"); } catch (const ControlRefused& e) { expect(e.token, "devices 1 046d"); }
    expect(first_error_line("[1.2 ERROR gpu] bad gpu\n[ERROR devices::usb::xhci] ring died\n").value(), "ring died");
    expect(first_error_line("[ERROR gpu] bad gpu\n[WARN usb] x").value(), "bad gpu");
    check(!first_error_line("nothing here"), "no error line");
    expect(attach_failure_message("no_available_port", "", "[t ERROR usb_host] event ring dead"), "crosvm usb attach failed: no_available_port (event ring dead)");
    expect(attach_failure_message("x", "", ""), "crosvm usb attach failed: x");
    try { require_output(" \n", "error: failed to connect to socket /x\nline2"); throw std::runtime_error("no throw"); }
    catch (const VmmUnreachable& e) { expect(e.what(), "control socket not reachable: error: failed to connect to socket /x"); }
    try { require_output("", "boom"); throw std::runtime_error("no throw"); }
    catch (const VmmUnreachable&) { throw std::runtime_error("wrong type"); }
    catch (const ControlIoError& e) { expect(e.what(), "crosvm usb printed nothing; stderr: boom"); }
    CrosvmCli cli("/data/data/cn.classfun.droidvm", "14");
    check(cli.argv({"usb", "list", "/s"}) == std::vector<std::string>{"/data/data/cn.classfun.droidvm/usr/bin/crosvm", "usb", "list", "/s"}, "cli argv");
    check(cli.environment()[0].second == "/data/data/cn.classfun.droidvm/lib/libsimpledump.so:/data/data/cn.classfun.droidvm/lib/libcompat_a14.so", "cli env");
    Json::Value config = parse(R"({"peripherals":[{"type":"virtio_sound"},{"type":"XHCI_USB"},{"type":"xhci_usb","id":"xhci-3"}]})");
    check(find_controller(config, std::nullopt) == "" && find_controller(config, "xhci-3") == "xhci-3" && !find_controller(config, "xhci-9"), "find_controller");
    check(!find_controller(parse(R"({"peripherals":{}})"), std::nullopt), "no controllers");
}
void rules_file() {
    Tree tree;
    std::vector<std::string> logs;
    RulesFile file(tree.files.string(), [&](const char* level, const std::string& m) { logs.push_back(std::string(level) + m); });
    check(file.load().is_empty(), "absent file");
    const auto rules = Rules::from_json(parse(R"({"enabled":false,"device":[{"id":"0781:5567","target":"sink"}]})"), nullptr);
    file.save(rules);
    struct stat info{};
    check(stat(file.path().c_str(), &info) == 0 && (info.st_mode & 0777) == 0600, "mode 0600");
    RulesFile again(tree.files.string(), {});
    const auto loaded = again.load();
    check(!loaded.enabled() && loaded.layer(Layer::device).size() == 1 && loaded.to_json() == rules.to_json(), "round trip");
    // Valid JSON the rules refuse: empty, file kept.
    write_file(file.path(), R"({"bogus":1})");
    check(RulesFile(tree.files.string(), {}).load().is_empty() && fs::exists(file.path()), "invalid rules read as empty");
    // Not JSON at all: empty, and the next save still lands.
    write_file(file.path(), "{not json");
    fs::remove(file.path() + ".bak");
    RulesFile corrupt(tree.files.string(), [&](const char* level, const std::string& m) { logs.push_back(std::string(level) + m); });
    check(corrupt.load().is_empty(), "corrupt read as empty");
    corrupt.save(rules);
    check(RulesFile(tree.files.string(), {}).load().to_json() == rules.to_json(), "save over a corrupt file");
    check(fs::exists(file.path() + ".corrupt"), "corrupt file kept as evidence");
    check(std::any_of(logs.begin(), logs.end(), [](const auto& l) { return l.starts_with("WCannot read "); }), "corrupt warned");
}

// --- the service ---
void handler_messages() {
    Rig rig;
    rig.make();
    rig.vms.add(vm_a, "alpha", VmState::stopped, {"xhci-0"});
    rig.vms.add(vm_b, "beta", VmState::running, {});
    auto& s = *rig.service;
    expect(request_error([&] { s.usb_attach(parse("{}")); }), "missing vm_id");
    expect(request_error([&] { s.usb_attach(parse(R"({"vm_id":null})")); }), "VM not found: null");
    expect(request_error([&] { s.usb_attach(parse(R"({"vm_id":")" + vm_a + "\"}")); }), "missing device");
    expect(request_error([&] { s.usb_attach(parse(R"({"vm_id":")" + vm_a + R"(","device":"1-1"})")); }), "VM is not running");
    expect(request_error([&] { s.usb_attach(parse(R"({"vm_id":")" + vm_b + R"(","device":"1-1"})")); }), "VM has no USB controller");
    expect(request_error([&] { s.usb_detach(parse(R"({"vm_id":")" + vm_a + R"(","port":null})")); }), "missing device or port");
    expect(request_error([&] { s.usb_detach(parse(R"({"vm_id":")" + vm_a + R"(","port":3})")); }), "device not attached to this VM");
    expect(request_error([&] { s.usb_vm_list(parse(R"({"vm_id":5})")); }), "VM not found: 5");
    expect(request_error([&] { s.usb_rules_set(parse(R"({"rules":[]})")); }), "missing rules");
    expect(request_error([&] { s.usb_rules_set(parse(R"({"rules":{"any":[{"vm":"ghost"}]}})")); }), "any[0]: VM not found: ghost");
    expect(request_error([&] { s.usb_set_target(parse("{}")); }), "missing device");
    expect(request_error([&] { s.usb_set_target(parse(R"({"device":"1-1","target":"cloud"})")); }), "unknown target: cloud");
    expect(request_error([&] { s.usb_set_target(parse(R"({"device":"1-1","target":"vm"})")); }), "missing vm_id");
    expect(request_error([&] { s.usb_set_target(parse(R"({"device":"1-1","target":"vm","vm_id":"x"})")); }), "VM not found: x");
    expect(request_error([&] { s.usb_set_target(parse(R"({"device":"../1-1","target":"host"})")); }), "no such USB device: ../1-1");
    rig.tree.add("1-1", hub());
    expect(request_error([&] { s.usb_set_target(parse(R"({"device":"1-1","target":"sink"})")); }), "refusing to take a hub away from the host");
    const auto vm_list = s.usb_vm_list(parse(R"({"vm_id":")" + vm_a + "\"}"));
    check(vm_list["vm_id"] == vm_a && vm_list["devices"].isArray() && vm_list["devices"].empty(), "empty vm list");
    const auto got = s.usb_rules_get({});
    check(got["rules"]["enabled"] == true && got["rules"]["version"] == 1, "default rules");
    check(rig.kernel->writes.empty(), "validation wrote nothing");
}
void attach_detach_flow() {
    Rig rig;
    rig.make();
    rig.vms.add(vm_a, "alpha", VmState::running, {"xhci-0", "xhci-1"});
    rig.tree.add("1-1.1", keyboard(), true, {{"1-1.1:1.0", "usbhid"}, {"1-1.1:1.1", "usbhid"}});
    auto& s = *rig.service;
    auto res = s.usb_attach(parse(R"({"vm_id":")" + vm_a + R"(","device":"1-1.1"})"));
    check(res["port"] == 1 && res["controller"] == "xhci-0" && res["device"] == "1-1.1", "attach result");
    check(rig.control.calls.back() == "attach " + rig.tree.dev() + "/001/003 /run/alpha.sock", "attach wire");
    auto row = rig.host_row("1-1.1");
    check(row["attached_vm"] == vm_a && row["attached_vm_name"] == "alpha" && row["attached_port"] == 1 && row["attached_controller"] == "xhci-0" &&
          row["state"] == "vmuse" && row["lock"] == false && row["auto_rule"].isNull(), "host row while attached");
    const auto list = s.usb_vm_list(parse(R"({"vm_id":")" + vm_a + "\"}"))["devices"];
    check(list.size() == 1 && list[0]["node"] == rig.tree.dev() + "/001/003" && list[0]["vid"] == "046d" && list[0]["controller"] == "xhci-0", "vm list");
    expect(request_error([&] { s.usb_attach(parse(R"({"vm_id":")" + vm_a + R"(","device":"1-1.1"})")); }), "device already attached to VM alpha");
    check(rig.count_events("usb_vm_changed") >= 1 && rig.count_events("usb_host_changed") >= 1, "attach broadcasts");
    rig.kernel->clear();
    s.usb_detach(parse(R"({"vm_id":")" + vm_a + R"(","port":1})"));
    check(rig.control.calls.back() == "detach 1 /run/alpha.sock", "detach wire");
    // The interfaces were offered back through drivers_probe, and the user's
    // detach locks the instance against the rules.
    check(rig.kernel->count("drivers_probe", "1-1.1:1.0") == 1 && rig.kernel->count("drivers_probe", "1-1.1:1.1") == 1, "restore probes interfaces");
    row = rig.host_row("1-1.1");
    check(row["state"] == "hostuse" && row["lock"] == true && row["attached_vm"].isNull(), "after detach");
    // A refusal after a partial claim: the claim is waited out, offered back,
    // and the reason crosvm logged is in the message.
    rig.control.refuse_token = "no_available_port";
    rig.vms.stderr_text = "old line\n";
    rig.control.refuse_stderr = "[2024 ERROR devices::usb::xhci] event ring is dead";
    rig.tree.unbind("1-1.1:1.0"); rig.tree.unbind("1-1.1:1.1");
    expect(request_error([&] { s.usb_attach(parse(R"({"vm_id":")" + vm_a + R"(","device":"1-1.1"})")); }),
           "crosvm usb attach failed: no_available_port (event ring is dead)");
    check(rig.tree.driver("1-1.1:1.0") == "usbfs" && rig.logged("1-1.1:1.0 is still claimed through usbfs after 150 ms"), "partial claim left as leftover");
    rig.control.refuse_token.reset();
    rig.control.unreachable = true;
    rig.control.release_claims();
    expect(request_error([&] { s.usb_attach(parse(R"({"vm_id":")" + vm_a + R"(","device":"1-1.1"})")); }),
           "crosvm usb attach failed: control socket not reachable: failed to connect to socket: No such file");
    rig.control.unreachable = false;
    // A hub is refused, a gone device too.
    rig.tree.add("1-1", hub());
    expect(request_error([&] { s.usb_attach(parse(R"({"vm_id":")" + vm_a + R"(","device":"1-1"})")); }), "refusing to attach a hub");
    expect(request_error([&] { s.usb_attach(parse(R"({"vm_id":")" + vm_a + R"(","device":"9-9"})")); }), "no such USB device: 9-9");
    // An unconfigured device is configured first; one that never publishes is refused.
    rig.tree.add("1-1.2", stick(), false);
    res = s.usb_attach(parse(R"({"vm_id":")" + vm_a + R"(","device":"1-1.2"})"));
    check(rig.kernel->count("drivers_probe", "1-1.2") == 1 && rig.kernel->count("drivers_probe", "1-1.2:1.0") == 0 && res["port"] == 2, "device probe before handing over");
    rig.tree.add("1-1.4", {"aaaa", "0001", "00", "", 1, 9, {}}, false);
    expect(request_error([&] { s.usb_attach(parse(R"({"vm_id":")" + vm_a + R"(","device":"1-1.4"})")); }),
           "USB 1-1.4 has no configuration and published no interface within 300 ms of being probed");
    rig.settle();
}
void set_target_flow() {
    Rig rig;
    rig.make();
    rig.vms.add(vm_a, "alpha", VmState::running, {"xhci-0"});
    rig.vms.add(vm_b, "beta", VmState::running, {"xhci-7"});
    rig.tree.add("1-1.1", keyboard(), true, {{"1-1.1:1.0", "usbhid"}, {"1-1.1:1.1", "usbhid"}});
    auto& s = *rig.service;
    auto res = s.usb_set_target(parse(R"({"device":"1-1.1","target":"sink"})"));
    check(res["target"] == "sink" && res["previous"]["state"] == "hostuse" && res["previous"]["vm_id"].isNull() && res["state"] == "idle" &&
          res["vm_id"].isNull() && res["port"].isNull() && res["controller"].isNull(), "sink result");
    check(rig.kernel->count("drivers/usbhid/unbind", "1-1.1:1.0") == 1 && rig.host_row("1-1.1")["lock"] == true, "sink unbinds and locks");
    res = s.usb_set_target(parse(R"({"device":"1-1.1","target":"vm","vm_id":")" + vm_a + "\"}"));
    check(res["port"] == 1 && res["vm_id"] == vm_a && res["controller"] == "xhci-0" && res["state"] == "vmuse", "to a VM");
    check(rig.host_row("1-1.1")["lock"] == false, "a landed move unlocks");
    res = s.usb_set_target(parse(R"({"device":"1-1.1","target":"vm","vm_id":")" + vm_b + "\"}"));
    check(res["previous"]["vm_id"] == vm_a && res["previous"]["port"] == 1 && res["port"] == 2 && res["controller"] == "xhci-7", "moved between VMs");
    check(rig.service->usb_vm_list(parse(R"({"vm_id":")" + vm_a + "\"}"))["devices"].empty(), "old VM lost it");
    res = s.usb_set_target(parse(R"({"device":"1-1.1","target":"vm","vm_id":")" + vm_b + "\"}"));
    check(res["port"] == 2, "same VM is a no-op");
    res = s.usb_set_target(parse(R"({"device":"1-1.1","target":"host"})"));
    check(res["previous"]["vm_id"] == vm_b && res["state"] == "hostuse" && rig.host_row("1-1.1")["lock"] == true, "back to the host, locked");
    rig.settle();
}
void checked_target() {
    Rig rig;
    rig.tree.add("1-1.1", keyboard(), true);
    rig.make();
    auto& s = *rig.service;
    const auto params = parse(R"({"device":"1-1.1","target":"sink"})");
    expect(request_error([&] { s.set_target_checked(params, [](const Json::Value&) {}); }), "USB manager unavailable");
    s.start();
    rig.settle();
    rig.kernel->clear();
    const auto observed = s.host_catalog();
    check(observed["available"].asBool() && observed["devices"].size() == 1, "checked catalogue ready");
    write_file(rig.tree.dir("1-1.1") / "devnum", "99\n");
    expect(request_error([&] {
        s.set_target_checked(params, [&](const Json::Value& current) {
            if (current != observed) throw RequestError("stale USB observation");
        });
    }), "stale USB observation");
    check(rig.kernel->writes.empty() && rig.control.calls.empty(), "stale observation made no writes");
    const auto fresh = s.host_catalog();
    const auto result = s.set_target_checked(params, [&](const Json::Value& current) {
        check(current == fresh, "validator receives fresh catalogue");
    });
    check(result["state"] == "idle" && s.host_catalog()["devices"][0]["lock"] == true, "checked target applied");
    s.shutdown();
    expect(request_error([&] { s.set_target_checked(params, [](const Json::Value&) {}); }), "USB manager stopped");
}
void checked_rules() {
    Rig rig;
    rig.vms.add(vm_a, "stopped", VmState::stopped, {"xhci-0", "xhci-1"});
    rig.vms.add(vm_b, "no-controller", VmState::running, {});
    rig.make();
    auto& service = *rig.service;
    check(!service.rules_snapshot()["available"].asBool(), "rules unavailable before start");
    service.start(); rig.settle();
    const auto targets = service.rule_targets();
    check(targets.size() == 2 && targets[0]["controllerId"] == "xhci-0" && targets[1]["controllerId"].isNull(), "rule targets include stopped VMs and report first controller only");
    const auto first = service.rules_snapshot();
    check(first["available"].asBool() && first["persistence"] == "unpersisted", "default rules not saved");
    const auto off = parse(R"({"version":1,"enabled":false})");
    Json::Value params; params["rules"] = off;
    service.usb_rules_set(params);
    const auto legacy = service.rules_snapshot();
    check(legacy["revision"] != first["revision"] && legacy["persistence"] == "persisted", "App save advances shared version");
    rig.kernel->clear();
    try {
        service.set_rules_checked(off, first["revision"].asString());
        check(false, "old App baseline accepted");
    } catch (const ServiceError& error) { check(error.code() == ErrorCode::conflict, "old baseline conflicts"); }
    check(rig.kernel->writes.empty() && service.rules_snapshot() == legacy, "conflict has no runtime side effects");
    const auto saved = service.set_rules_checked(off, legacy["revision"].asString());
    check(saved["revision"] != legacy["revision"] && saved["persistence"] == "persisted", "conditional save advances even identical rules");
    const auto revision = saved["revision"].asString();
    try {
        service.set_rules_checked(parse(R"({"bogus":[]})"), revision);
        check(false, "invalid rules accepted");
    } catch (const ServiceError& error) { check(error.code() == ErrorCode::invalid_argument, "invalid rules refused"); }
    check(service.rules_snapshot()["revision"] == revision, "validation failure preserves version");
    service.shutdown();
    check(!service.rules_snapshot()["available"].asBool(), "rules unavailable after stop");
    try {
        service.set_rules_checked(off, revision);
        check(false, "rules accepted after stop");
    } catch (const ServiceError& error) { check(error.code() == ErrorCode::unavailable, "stopped rules unavailable"); }
    Rig temporary;
    temporary.make(false); temporary.service->start(); temporary.settle();
    const auto before = temporary.service->rules_snapshot();
    try {
        temporary.service->set_rules_checked(off, before["revision"].asString());
        check(false, "disabled persistence accepted");
    } catch (const ServiceError& error) { check(error.code() == ErrorCode::unavailable, "disabled persistence refused"); }
    check(temporary.service->rules_snapshot() == before, "disabled persistence leaves active rules unchanged");
}
void readonly_rules_preview() {
    Rig rig;
    write_file(rig.tree.files / "usb_rules.json", R"({"enabled":false})");
    rig.make();
    auto& service = *rig.service;
    try { service.rules_preview("before-start"); check(false, "preview before start"); }
    catch (const ServiceError& error) { check(error.code() == ErrorCode::unavailable, "preview requires started service"); }
    service.start(); rig.settle();
    // Publish devices after startup without delivering a uevent. Only a fresh
    // read can see these; there is no automatic pass to confuse write counts.
    rig.tree.add("1-1.1", keyboard(), true);
    rig.tree.add("1-1.2", stick(), true);
    rig.vms.add(vm_a, "preview", VmState::running, {"xhci-0"});
    const auto off = service.rules_snapshot();
    auto preview = service.rules_preview(off["revision"].asString());
    check(!preview["enabled"].asBool() && preview["devices"].size() == 2, "disabled preview has fresh devices");
    check(preview["devices"][0]["result"].isNull() && !preview["devices"][0]["eligible"].asBool(), "disabled preview has no decision");
    const auto rules = parse(R"({"enabled":true,"exact":[
        {"id":"046d:c31c:KB01","port":"1.1","target":"vm","vm":"missing"},
        {"id":"046d:c31c:KB01","port":"1.1","target":"vm","vm":"11111111-1111-1111-1111-111111111111","controller":"xhci-0"}
    ],"any":[{"target":"sink"}]})");
    write_file(rig.tree.files / "usb_rules.json", wire::stringify(rules));
    service.load_rules(); // Test-only load hook, no rule application.
    const auto before = service.rules_snapshot();
    const auto disk = read_file(rig.tree.files / "usb_rules.json");
    rig.kernel->clear();
    const auto calls = rig.control.calls.size();
    preview = service.rules_preview(before["revision"].asString());
    check(preview["devices"][0]["result"]["layer"] == "exact" && preview["devices"][0]["result"]["index"] == 1, "real engine skips missing VM and matches exact rule");
    check(preview["devices"][0]["result"]["vm"] == vm_a && preview["devices"][0]["eligible"] == true, "running VM is eligible");
    check(preview["devices"][1]["result"]["target"] == "sink", "real engine matches fallback");
    check(service.rules_preview(before["revision"].asString()) == preview, "repeated observation preserves flags");
    check(rig.kernel->writes.empty() && rig.control.calls.size() == calls && service.rules_snapshot() == before && read_file(rig.tree.files / "usb_rules.json") == disk, "preview has no driver/control/rule/file writes");
    try { service.rules_preview(off["revision"].asString()); check(false, "stale preview accepted"); }
    catch (const ServiceError& error) { check(error.code() == ErrorCode::conflict, "old preview version conflicts"); }
    rig.vms.set_state(vm_a, VmState::stopped);
    preview = service.rules_preview(before["revision"].asString());
    check(preview["devices"][0]["result"]["target"] == "sink", "fresh VM states participate in preview");
    service.usb_set_target(parse(R"({"device":"1-1.1","target":"sink"})"));
    rig.settle(); rig.kernel->clear();
    preview = service.rules_preview(before["revision"].asString());
    check(preview["devices"][0]["lock"] == true && preview["devices"][0]["eligible"] == false && !preview["devices"][0]["result"].isNull(), "locked devices still report matches separately from eligibility");
    check(rig.kernel->writes.empty(), "locked preview does not recover drivers");
    service.shutdown();
    try { service.rules_preview(before["revision"].asString()); check(false, "preview after stop"); }
    catch (const ServiceError& error) { check(error.code() == ErrorCode::unavailable, "stopped preview unavailable"); }
}
void rules_persistence_state() {
    for (const auto* boundary : {"before_install", "installed"}) {
        std::string fault;
        Rig rig;
        rig.make(true, [&](const char* stage) {
            if (fault == stage) throw std::runtime_error("injected rules persistence failure");
        });
        auto& service = *rig.service;
        service.start(); rig.settle();
        const auto initial = service.set_rules_checked(parse(R"({"enabled":false})"), service.rules_snapshot()["revision"].asString());
        fault = boundary;
        try {
            service.set_rules_checked(parse(R"({"enabled":true})"), initial["revision"].asString());
            check(false, "failed persistence reported success");
        } catch (const ServiceError& error) { check(error.code() == ErrorCode::commit_uncertain, "active but unsaved rules require readback"); }
        const auto current = service.rules_snapshot();
        check(current["rules"]["enabled"].asBool() && current["revision"] != initial["revision"], "failed write still has new active rules and revision");
        const bool installed = fault == "installed";
        check(current["persistence"] == (installed ? "uncertain" : "unpersisted"), "disk failure boundary reported accurately");
        check(parse(read_file(rig.tree.files / RulesFile::name))["enabled"].asBool() == installed, "disk contents reflect installation boundary");
        fault.clear();
        const auto repaired = service.set_rules_checked(current["rules"], current["revision"].asString());
        check(repaired["persistence"] == "persisted", "explicit fresh save repairs persistence");
        fault = "before_install";
        Json::Value params; params["rules"] = parse(R"({"enabled":false})");
        service.usb_rules_set(params);
        check(service.rules_snapshot()["persistence"] == "unpersisted" && !service.rules_snapshot()["rules"]["enabled"].asBool(), "legacy save remains active but snapshot reports failed persistence");
    }
}
void rules_passes_and_hooks() {
    Rig rig;
    rig.make();
    rig.vms.add(vm_a, "alpha", VmState::running, {"xhci-0"});
    rig.tree.add("1-1.1", keyboard(), true, {});
    rig.tree.add("1-1.2", stick(), true, {});
    auto& s = *rig.service;
    const auto rules = parse(R"({"rules":{"device":[{"id":"046d:c31c:KB01","vm":")" + vm_a + R"("},{"id":"0781:5567","target":"sink"}]}})");
    const auto applied = s.usb_rules_set(rules);
    check(applied["applied"] == 1 && rig.kernel->count("drivers_autoprobe", "0") == 1, "pass attached one, gate shut");
    check(fs::exists(rig.tree.files / RulesFile::name), "rules persisted");
    auto row = rig.host_row("1-1.1");
    check(row["attached_vm"] == vm_a && row["auto_rule"]["layer"] == "device" && row["auto_rule"]["index"] == 0 && row["auto_rule"]["controller"].isNull(), "auto attachment");
    check(rig.count_events("usb_auto_attached") == 1, "auto event");
    const auto test = s.usb_rules_test({});
    check(test["enabled"] == true && test["devices"].size() == 2 && test["devices"][1]["result"]["target"] == "sink" &&
          test["devices"][0]["attached_vm"] == vm_a && test["devices"][0]["result"]["vm"] == vm_a, "dry run");
    check(rig.host_row("1-1.2")["state"] == "idle", "sink left idle");
    // STOPPED: the VMM is gone with its claims; released and given back.
    rig.control.release_claims();
    rig.vms.set_state(vm_a, VmState::stopped);
    s.on_vm_state(vm_a, VmState::stopped);
    rig.settle();
    check(rig.host_row("1-1.1")["attached_vm"].isNull() && rig.host_row("1-1.1")["state"] == "hostuse", "released on stop");
    // RUNNING again: the pass waits for the socket and takes it back.
    rig.control.release_claims();
    rig.tree.unbind("1-1.1:1.0"); rig.tree.unbind("1-1.1:1.1");
    rig.vms.set_state(vm_a, VmState::running);
    s.on_vm_state(vm_a, VmState::running);
    rig.settle();
    check(rig.host_row("1-1.1")["attached_vm"] == vm_a, "re-attached when running");
    // Switch off: everything taken goes back, the gate opens.
    rig.kernel->clear();
    const auto off = s.usb_rules_set(parse(R"({"rules":{"enabled":false,"device":[{"id":"0781:5567","target":"sink"}]}})"));
    check(off["applied"] == 2 && rig.kernel->count("drivers_autoprobe", "1") == 1, "release everything");
    check(rig.host_row("1-1.1")["state"] == "hostuse" && rig.host_row("1-1.2")["state"] == "hostuse", "all back to the host");
    check(s.usb_rules_test({})["enabled"] == false && s.usb_rules_test({})["devices"][0]["result"].isNull(), "switch off reads null");
    rig.settle();
}
void uevent_plug_and_unplug() {
    Rig rig;
    rig.make();
    rig.vms.add(vm_a, "alpha", VmState::running, {"xhci-0"});
    rig.tree.add("usb1", root_hub(), true, {{"1-0:1.0", "hub"}});
    fs::create_directory_symlink("../../../bus/usb/drivers/usb", rig.tree.dir("usb1") / "driver");
    write_file(rig.tree.files / RulesFile::name, R"({"version":1,"enabled":true,"device":[{"id":"0781:5567","target":"vm","vm":")" + vm_a + R"("}]})");
    auto& s = *rig.service;
    s.start();
    rig.settle();
    check(rig.kernel->count("drivers_autoprobe", "0") == 1, "start shuts the gate from the file");
    // A keyboard enumerated under the gate: unconfigured; the uevent asks for
    // a rescan and the fifth zone gives it to the host, device then interfaces.
    rig.tree.add("1-1", keyboard(5), false);
    rig.tree.specs["1-1"].interfaces = {{"1-1:1.0", "03"}};
    rig.watch->notify({false, Uevent::parse(uevent({"ACTION=add", "DEVPATH=/d/usb1/1-1", "SUBSYSTEM=usb"}))});
    rig.settle();
    check(rig.kernel->count("drivers_probe", "1-1") == 1 && rig.kernel->count("drivers_probe", "1-1:1.0") == 1 && rig.host_row("1-1")["state"] == "hostuse", "plug pass gives it to the host");
    // A stick the rules hand to the VM.
    rig.tree.add("1-2", {"0781", "5567", "00", "", 1, 6, {{"1-2:1.0", "08"}}}, false);
    rig.watch->notify({});
    rig.settle();
    check(rig.host_row("1-2")["attached_vm"] == vm_a && rig.host_row("1-2")["state"] == "vmuse", "plug pass attaches");
    // Unplugged while attached: the VMM is told, the record goes.
    rig.tree.remove("1-2");
    rig.watch->notify({});
    rig.settle();
    check(rig.control.calls.back().starts_with("detach 1 "), "unplug detaches");
    check(s.usb_vm_list(parse(R"({"vm_id":")" + vm_a + "\"}"))["devices"].empty(), "unplug drops the record");
    // A driver unbound by hand (the uevent-only change) is put back.
    rig.tree.unbind("1-1:1.0");
    rig.watch->notify({false, Uevent::parse(uevent({"ACTION=unbind", "DEVPATH=/d/1-1:1.0", "SUBSYSTEM=usb"}))});
    rig.settle();
    check(rig.host_row("1-1")["state"] == "hostuse", "driver change pass");
    s.shutdown();
    check(rig.kernel->count("drivers_autoprobe", "1") == 1 && rig.watch->stopped, "shutdown opens the gate");
}
void leftovers_recovery() {
    Rig rig;
    rig.make();
    rig.vms.add(vm_a, "alpha", VmState::running, {"xhci-0"});
    rig.tree.add("1-1.2", stick(), true, {{"1-1.2:1.0", "usb-storage"}});
    auto& s = *rig.service;
    s.usb_attach(parse(R"({"vm_id":")" + vm_a + R"(","device":"1-1.2"})"));
    // The VMM keeps its claim past the release wait.
    rig.control.sticky = true;
    s.usb_detach(parse(R"({"vm_id":")" + vm_a + R"(","device":"1-1.2"})"));
    check(rig.tree.driver("1-1.2:1.0") == "usbfs" && rig.logged("still claimed through usbfs"), "left unbound");
    rig.kernel->clear();
    // The VM's exit retries exactly what it left behind.
    rig.control.release_claims();
    rig.vms.set_state(vm_a, VmState::stopped);
    s.on_vm_state(vm_a, VmState::stopped);
    rig.settle();
    check(rig.kernel->count("drivers_probe", "1-1.2:1.0") == 1 && rig.logged("Recovered 1 USB interface(s) left unbound earlier (VM alpha stopped): 1-1.2:1.0"), "recovered on VM exit");
    // A claim seen gone by any scan is recovered too.
    rig.vms.set_state(vm_a, VmState::running);
    rig.control.sticky = true;
    rig.tree.unbind("1-1.2:1.0");
    s.usb_attach(parse(R"({"vm_id":")" + vm_a + R"(","device":"1-1.2"})"));
    s.usb_detach(parse(R"({"vm_id":")" + vm_a + R"(","device":"1-1.2"})"));
    rig.control.release_claims();
    rig.kernel->clear();
    s.usb_host_list({});
    rig.settle();
    check(rig.kernel->count("drivers_probe", "1-1.2:1.0") == 1 && rig.logged("(claim gone)"), "recovered on scan");
}
void start_recovery() {
    Rig rig;
    // A killed daemon left the gate shut with the switch off, an idle device,
    // a driverless root hub and an older build's authorized=0.
    rig.tree.add("usb2", {"1d6b", "0003", "09", "", 2, 1, {{"2-0:1.0", "09"}}}, false);
    rig.tree.add("1-1.1", keyboard(), true, {});
    rig.tree.add("1-1.5", {"abcd", "0005", "00", "", 1, 8, {{"1-1.5:1.0", "03"}}}, true);
    write_file(rig.tree.dir("1-1.5") / "authorized", "0\n");
    write_file(rig.tree.files / RulesFile::name, R"({"version":1,"enabled":false})");
    rig.make();
    rig.service->start();
    rig.settle();
    check(rig.kernel->count("drivers_autoprobe", "1") == 1, "switch off: gate opened at start");
    check(rig.kernel->count("1-1.5/authorized", "1") == 1 || rig.kernel->count("devices/1-1.5/authorized", "1") == 1, "authorized migration");
    check(rig.kernel->count("drivers_probe", "usb2") == 1 && rig.kernel->count("drivers_probe", "2-0:1.0") == 1, "root hub given its driver");
    check(rig.host_row("1-1.1")["state"] == "hostuse", "idle device recovered at start");
    // With the switch off no later trigger acts.
    rig.tree.unbind("1-1.1:1.0");
    rig.watch->notify({});
    rig.settle();
    check(rig.host_row("1-1.1")["interfaces"][0]["driver"] == "", "switch off: later passes do nothing");
    rig.service->shutdown();
}
}

int main(int argc, char** argv) {
    if (argc > 1) scratch = argv[1];
    return test::run({{"java_values", java_values},
                      {"rules_parse", rules_parse},
                      {"engine_decisions", engine_decisions},
                      {"inventory_scan", inventory_scan},
                      {"pure_helpers", pure_helpers},
                      {"rules_file", rules_file},
                      {"handler_messages", handler_messages},
                      {"attach_detach_flow", attach_detach_flow},
                      {"set_target_flow", set_target_flow},
                      {"checked_target", checked_target},
                      {"checked_rules", checked_rules},
                      {"readonly_rules_preview", readonly_rules_preview},
                      {"rules_persistence_state", rules_persistence_state},
                      {"rules_passes_and_hooks", rules_passes_and_hooks},
                      {"uevent_plug_and_unplug", uevent_plug_and_unplug},
                      {"leftovers_recovery", leftovers_recovery},
                      {"start_recovery", start_recovery}});
}
