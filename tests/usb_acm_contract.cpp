// SPDX-License-Identifier: GPL-3.0-or-later
// Host contract for the native USB CDC-ACM pool (vm/usb_acm). Runs over a fake
// configfs gadget in a scratch directory with a modelled kernel behind the
// gadget writer and a fake clock; never touches the real /config.
#include "contracts.h"
#include "vm/usb_acm.h"
#include "services/context.h"
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>

namespace fs = std::filesystem;
using namespace droidvm;
using namespace droidvm::vm;
using droidvm::test::check;

namespace {
std::string scratch = "/data/local/tmp";
void expect(const std::string& actual, const std::string& wanted) {
    if (actual != wanted) throw std::runtime_error("got \"" + actual + "\", wanted \"" + wanted + "\"");
}
void expect(const std::vector<std::string>& actual, const std::vector<std::string>& wanted) {
    auto join = [](const std::vector<std::string>& items) { std::string text; for (const auto& item : items) text += (text.empty() ? "" : " ") + item; return text; };
    expect(join(actual), join(wanted));
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
std::string trim(std::string text) {
    while (!text.empty() && static_cast<unsigned char>(text.back()) <= 0x20) text.pop_back();
    while (!text.empty() && static_cast<unsigned char>(text.front()) <= 0x20) text.erase(0, 1);
    return text;
}
Json::Value app(bool enable, Json::Value ports = Json::Value()) {
    Json::Value config(Json::objectValue);
    config[acm_enable_key] = enable;
    if (!ports.isNull()) config[acm_ports_key] = ports;
    return config;
}
template <typename E, typename F> std::string error_of(F&& fn) {
    try { fn(); } catch (const E& error) { return error.what(); }
    throw std::runtime_error("expected an error");
}

// configfs plus u_serial: functions get the lowest free ttyGS index at mkdir,
// config links need the UDC unbound, and tty nodes exist only while bound.
struct Kernel : GadgetFs {
    fs::path root, gadget, functions, config, udc, udc_class, dev;
    std::vector<std::string> events;
    int refuse_unbind = 0;  // unbind writes the HAL wins, UDC keeps its value
    bool bind_raced = false; // the HAL binds first: our bind fails with EBUSY
    bool bind_lost = false;  // our bind fails and the UDC stays unbound
    bool no_nodes = false;   // tty nodes never appear
    bool unbind_error_after_effect = false;
    Kernel() {
        auto pattern = scratch + "/droidvm-acm-XXXXXX";
        std::vector<char> name(pattern.begin(), pattern.end());
        name.push_back('\0');
        check(mkdtemp(name.data()) != nullptr, "mkdtemp");
        root = name.data();
        gadget = root / "config/usb_gadget/g1";
        functions = gadget / "functions";
        config = gadget / "configs/b.1";
        udc = gadget / "UDC";
        udc_class = root / "sys/class/udc";
        dev = root / "dev";
        fs::create_directories(functions);
        fs::create_directories(config);
        fs::create_directories(udc_class / "a600000.dwc3");
        fs::create_directories(dev);
        write_file(udc, "a600000.dwc3\n");
        // The framework's own functions, already bound.
        add_function("ffs.adb", false);
        fs::create_directory_symlink(functions / "ffs.adb", config / "f1");
    }
    ~Kernel() override { std::error_code ignored; fs::remove_all(root, ignored); }
    bool bound() const { return !trim(read_file(udc)).empty(); }
    // A pre-existing function with the next ttyGS index when it is a serial one.
    void add_function(const std::string& name, bool serial = true) {
        fs::create_directory(functions / name);
        if (serial) write_file(functions / name / "port_num", std::to_string(next_port()) + "\n");
    }
    int next_port() const {
        std::set<int> used;
        std::error_code missing;
        for (const auto& entry : fs::directory_iterator(functions, missing))
            if (fs::exists(entry.path() / "port_num")) used.insert(std::atoi(read_file(entry.path() / "port_num").c_str()));
        int port = 0;
        while (used.contains(port)) ++port;
        return port;
    }
    void nodes(bool present) {
        for (const auto& entry : fs::directory_iterator(dev)) fs::remove(entry.path());
        if (!present || no_nodes) return;
        for (const auto& entry : fs::directory_iterator(config)) {
            std::error_code dangling;
            const auto port = fs::canonical(entry.path(), dangling) / "port_num";
            if (!dangling && fs::exists(port)) write_file(dev / ("ttyGS" + trim(read_file(port))), "");
        }
    }
    std::string relative(const std::string& path) const { return fs::path(path).lexically_relative(gadget).generic_string(); }
    int write(const std::string& path, std::string_view text) override {
        if (path != udc.string()) return GadgetFs::write(path, text);
        const auto value = trim(std::string(text));
        if (value.empty()) {
            events.push_back("unbind");
            if (refuse_unbind > 0) { --refuse_unbind; return EBUSY; }
            nodes(false);
            const auto result = GadgetFs::write(path, text);
            return unbind_error_after_effect ? EIO : result;
        }
        events.push_back("bind:" + value);
        if (bind_lost) return EBUSY;
        GadgetFs::write(path, value + "\n");
        nodes(true);
        return bind_raced ? EBUSY : 0;
    }
    int make_directory(const std::string& path) override {
        const int port = next_port();
        if (const int error = GadgetFs::make_directory(path)) return error;
        events.push_back("mkdir:" + relative(path));
        write_file(fs::path(path) / "port_num", std::to_string(port) + "\n");
        return 0;
    }
    bool tty_node(const std::string& path) const override { return fs::is_regular_file(path); }
    int symlink(const std::string& target, const std::string& link) override {
        if (bound()) return EINVAL;
        events.push_back("link:" + relative(link));
        return GadgetFs::symlink(target, link);
    }
    int remove(const std::string& path) override {
        const fs::path item(path);
        if (fs::is_symlink(item)) {
            if (bound()) return EINVAL;
            events.push_back("unlink:" + relative(path));
            return GadgetFs::remove(path);
        }
        if (!fs::exists(fs::symlink_status(item))) return ENOENT;
        std::error_code ignored;
        for (const auto& entry : fs::directory_iterator(config))
            if (fs::equivalent(entry.path(), item, ignored)) return EBUSY;
        events.push_back("rmdir:" + relative(path));
        fs::remove(item / "port_num");
        return GadgetFs::remove(path);
    }
};

struct Fixture {
    std::shared_ptr<Kernel> kernel = std::make_shared<Kernel>();
    std::chrono::steady_clock::time_point clock{};
    std::chrono::milliseconds slept{0};
    std::string boot = "1";
    std::vector<std::string> logs;
    std::unique_ptr<AcmPool> pool;
    Fixture() {
        AcmOptions options;
        options.gadget = kernel->gadget.string();
        options.udc_class = kernel->udc_class.string();
        options.dev = kernel->dev.string();
        options.fs = kernel;
        options.property = [this](const char* name) { return std::string(name) == "sys.boot_completed" ? boot : std::string(); };
        options.now = [this] { return clock; };
        options.sleep = [this](std::chrono::milliseconds delay) { clock += delay; slept += delay; };
        options.log = [this](const char* level, const std::string& text) { logs.push_back(std::string(level) + " " + text); };
        pool = std::make_unique<AcmPool>(std::move(options));
    }
    std::vector<std::string> take() { auto out = std::move(kernel->events); kernel->events.clear(); return out; }
    std::string dev(int port) const { return (kernel->dev / ("ttyGS" + std::to_string(port))).string(); }
    bool linked(int slot) const { return fs::exists(kernel->config / ("acm.dvmpool" + std::to_string(slot))); }
    bool member(int slot) const { return fs::is_directory(kernel->functions / ("acm.dvmpool" + std::to_string(slot))); }
    bool logged(const std::string& text) const {
        for (const auto& line : logs) if (line.find(text) != std::string::npos) return true;
        return false;
    }
};

void config_values() {
    Json::Value empty(Json::objectValue);
    check(!acm_enabled(empty) && acm_ports(empty) == 4, "defaults");
    check(acm_enabled(app(true)), "enable");
    Json::Value text(Json::objectValue);
    text[acm_enable_key] = "true";
    text[acm_ports_key] = "3";
    check(!acm_enabled(text) && acm_ports(text) == 4, "optBoolean/optLong are type-strict");
    check(acm_ports(app(true, 0)) == 1 && acm_ports(app(true, -5)) == 1, "clamped to one");
    check(acm_ports(app(true, 3)) == 3 && acm_ports(app(true, 6)) == 6 && acm_ports(app(true, 99)) == 6, "clamped to max");
    check(acm_ports(app(true, Json::Int64(4294967298LL))) == 2, "(int) narrowing of optLong");
}
void managed_authority_and_live() {
    Fixture f;
    f.pool->transaction([&](AcmTransaction& tx) {
        tx.bind(std::nullopt);
        check(tx.live({true, 2})["available"].asBool(), "initial gadget observation available");
    });
    check(f.take().empty(), "binding an uninitialized owner never edits gadget");
    error_of<AcmSlotUnavailable>([&] { f.pool->acquire(0, "vm-a/serial1", app(true, 2)); });
    f.pool->transaction([&](AcmTransaction& tx) { tx.admit({true, 2}); tx.bind(AcmDesired{true, 2}); tx.apply(); });
    f.take();
    expect(f.pool->acquire(0, "vm-a/serial1", app(false, 1)), f.dev(0));
    const auto owners = f.pool->owners();
    f.pool->apply_config(app(false, 1));
    check(f.take().empty() && f.pool->owners() == owners, "stale App config cannot rebind authoritative pool");
    bool rejected = false;
    try { f.pool->transaction([](AcmTransaction& tx) { tx.admit({true, 3}); }); }
    catch (const ServiceError& error) { rejected = error.code() == ErrorCode::conflict; }
    check(rejected && f.take().empty() && f.pool->owners() == owners, "active slot forbids even expansion rebind");
    f.pool->transaction([&](AcmTransaction& tx) {
        const auto live = tx.live({true, 2});
        check(live["applied"].asBool() && live["udcBound"].asBool() && live["ports"] == 2 &&
            live["owners"][0]["slot"] == 0 && live["owners"][0]["vmId"] == "vm-a", "strict live observation wrong");
    });
    check(f.take().empty(), "GET mutated gadget");
    f.pool->release("vm-a/serial1");
    fs::remove(f.kernel->config / "acm.dvmpool1");
    fs::create_symlink(f.kernel->functions / "ffs.adb", f.kernel->config / "acm.dvmpool1");
    f.pool->transaction([&](AcmTransaction& tx) {
        const auto live = tx.live({true, 2});
        check(!live["available"].asBool() && !live["applied"].asBool() && live["ports"].isNull(), "wrong-target link was trusted");
        error_of<ServiceError>([&] { tx.apply(); });
    });
    check(f.take().empty(), "unsafe link silently rewritten");
    fs::remove(f.kernel->config / "acm.dvmpool1");
    fs::create_symlink(f.kernel->functions / "acm.dvmpool1", f.kernel->config / "acm.dvmpool1");
    write_file(f.kernel->functions / "acm.dvmpool1/port_num", "-1\n");
    f.pool->transaction([&](AcmTransaction& tx) {
        const auto live = tx.live({true, 2});
        check(!live["available"].asBool() && live["ports"].isNull(), "invalid port produced a partial count");
    });
}
void managed_udc_error_restores_without_retry() {
    Fixture f; f.kernel->unbind_error_after_effect = true;
    f.pool->transaction([&](AcmTransaction& tx) {
        tx.bind(AcmDesired{true, 1});
        error_of<std::runtime_error>([&] { tx.apply(); });
    });
    const auto events = f.take();
    check(std::count(events.begin(), events.end(), "unbind") == 1 &&
        std::count(events.begin(), events.end(), "bind:a600000.dwc3") == 1 && f.kernel->bound(), "ambiguous unbind failed to restore or retried");
    f.pool->transaction([&](AcmTransaction& tx) {
        const auto live = tx.live({true, 1});
        check(live["available"].asBool() && live["udcBound"].asBool() && !live["applied"].asBool(), "restored partial composition not reported");
    });
    check(f.take().empty(), "observing partial failure retried mutation");
}
void pool_build_and_teardown() {
    Fixture f;
    f.pool->apply_config(app(true, 3));
    expect(f.take(), {"mkdir:functions/acm.dvmpool0", "mkdir:functions/acm.dvmpool1", "mkdir:functions/acm.dvmpool2", "unbind",
                      "link:configs/b.1/acm.dvmpool0", "link:configs/b.1/acm.dvmpool1", "link:configs/b.1/acm.dvmpool2", "bind:a600000.dwc3"});
    check(f.kernel->bound() && fs::exists(f.kernel->config / "f1"), "framework functions kept and gadget rebound");
    check(f.logged("USB ACM pool reconciled to 3 members"), "reconcile logged");
    f.pool->apply_config(app(true, 3));
    check(f.take().empty(), "an up-to-date pool never rebinds");
    f.pool->apply_config(app(false, 3));
    auto events = f.take();
    check(events.size() == 8 && events.front() == "unbind" && events.back() == "bind:a600000.dwc3", "teardown is one window");
    for (int i = 0; i < 3; ++i) check(!f.member(i) && !f.linked(i), "teardown removes members");
    // Every unlink precedes its rmdir.
    for (int i = 0; i < 3; ++i) {
        const auto name = "acm.dvmpool" + std::to_string(i);
        const auto unlink = std::find(events.begin(), events.end(), "unlink:configs/b.1/" + name);
        const auto rmdir = std::find(events.begin(), events.end(), "rmdir:functions/" + name);
        check(unlink != events.end() && rmdir != events.end() && unlink < rmdir, "unlink before rmdir");
    }
    f.pool->apply_config(app(false, 3));
    check(f.take().empty(), "a disabled empty pool never rebinds");
    f.pool->apply_config(Json::Value(Json::objectValue));
    check(f.take().empty(), "disabled by default");
}
void port_count_changes() {
    Fixture f;
    f.pool->apply_config(app(true, 3));
    f.take();
    f.pool->apply_config(app(true, 2));
    expect(f.take(), {"unbind", "unlink:configs/b.1/acm.dvmpool2", "rmdir:functions/acm.dvmpool2", "bind:a600000.dwc3"});
    f.pool->apply_config(app(true, 4));
    expect(f.take(), {"mkdir:functions/acm.dvmpool2", "mkdir:functions/acm.dvmpool3", "unbind",
                      "link:configs/b.1/acm.dvmpool2", "link:configs/b.1/acm.dvmpool3", "bind:a600000.dwc3"});
    f.pool->apply_config(app(true, 99));
    check(f.member(5) && !f.member(6), "pool clamped to six");
    // A member the framework unlinked (USB mode switch) is relinked.
    f.take();
    fs::remove(f.kernel->config / "acm.dvmpool1");
    f.pool->apply_config(app(true, 6));
    expect(f.take(), {"unbind", "link:configs/b.1/acm.dvmpool1", "bind:a600000.dwc3"});
}
void acquire_and_release() {
    Fixture f;
    const auto on = app(true, 3);
    expect(error_of<AcmSlotUnavailable>([&] { f.pool->acquire(0, "vm/serial1", app(false, 3)); }),
           "USB serial (ACM) is disabled; enable it in the app settings first");
    expect(error_of<AcmSlotUnavailable>([&] { f.pool->acquire(3, "vm/serial1", on); }),
           "USB serial slot 3 is outside the pool (size 3); raise the USB serial ports setting or pick a lower slot");
    expect(error_of<AcmSlotUnavailable>([&] { f.pool->acquire(-1, "vm/serial1", on); }),
           "USB serial slot -1 is outside the pool (size 3); raise the USB serial ports setting or pick a lower slot");
    check(f.take().empty(), "refusals touch nothing");
    // The first acquire builds the pool; the slot is the config's, not first-free.
    expect(f.pool->acquire(1, "a/serial1", on), f.dev(1));
    check(f.take().size() == 8, "first acquire builds the pool");
    expect(f.pool->acquire(2, "a/vcon3", on), f.dev(2));
    check(f.take().empty(), "attach never rebinds");
    expect(error_of<AcmSlotUnavailable>([&] { f.pool->acquire(1, "b/serial1", on); }), "USB serial slot 1 is busy (held by a/serial1)");
    expect(error_of<AcmSlotUnavailable>([&] { f.pool->acquire(1, "a/serial1", on); }), "USB serial slot 1 is busy (held by a/serial1)");
    check(f.pool->owners() == std::map<std::string, std::string>{{"dvmpool1", "a/serial1"}, {"dvmpool2", "a/vcon3"}}, "owners");
    check(f.logged("acm slot 1 (" + f.dev(1) + ") -> a/serial1"), "attach logged");
    f.pool->release("nobody");
    check(f.pool->owners().size() == 2, "releasing a stranger is a no-op");
    f.pool->release("a/serial1");
    check(f.pool->owners() == std::map<std::string, std::string>{{"dvmpool2", "a/vcon3"}}, "release by owner");
    expect(f.pool->acquire(1, "b/serial1", on), f.dev(1));
    check(f.take().empty(), "release and reattach never rebind");
    // Shrinking or disabling keeps held members: their crosvm fd stays open.
    f.pool->apply_config(app(true, 1));
    check(f.take().empty(), "a shrink over held members changes nothing");
    check(f.member(1) && f.member(2) && f.linked(1) && f.linked(2), "held members survive a shrink");
    f.pool->release("b/serial1");
    f.pool->apply_config(app(false));
    auto events = f.take();
    check(!f.member(0) && !f.member(1) && f.member(2) && f.linked(2), "disable removes only unheld members");
    check(std::count(events.begin(), events.end(), "unbind") == 1, "one window");
    f.pool->release("a/vcon3");
    f.pool->apply_config(app(false));
    check(!f.member(2), "released member removed on the next reconcile");
    // A pool the framework wiped is rebuilt by the next acquire.
    f.pool->apply_config(app(true, 2));
    fs::remove(f.kernel->config / "acm.dvmpool0");
    fs::remove(f.kernel->config / "acm.dvmpool1");
    f.take();
    expect(f.pool->acquire(0, "c/serial1", on), f.dev(0));
    expect(f.take(), {"mkdir:functions/acm.dvmpool2", "unbind", "link:configs/b.1/acm.dvmpool0", "link:configs/b.1/acm.dvmpool1",
                      "link:configs/b.1/acm.dvmpool2", "bind:a600000.dwc3"});
}
void foreign_functions() {
    Fixture f;
    // The vendor's serial functions hold the low ttyGS indexes.
    f.kernel->add_function("gser.gs0");
    f.kernel->add_function("acm.usb0");
    fs::create_directory_symlink(f.kernel->functions / "acm.usb0", f.kernel->config / "f2");
    // Lookalikes: a non-numeric suffix is never ours; a stale high member is.
    f.kernel->add_function("acm.dvmpoolx");
    f.kernel->add_function("acm.dvmpool9");
    f.kernel->add_function("gser.dvmpool5");
    expect(f.pool->acquire(0, "a/serial1", app(true, 2)), f.dev(5));
    expect(f.pool->acquire(1, "a/serial2", app(true, 2)), f.dev(6));
    expect(f.take(), {"mkdir:functions/acm.dvmpool0", "mkdir:functions/acm.dvmpool1", "unbind",
                      "link:configs/b.1/acm.dvmpool0", "link:configs/b.1/acm.dvmpool1",
                      "rmdir:functions/acm.dvmpool9", "bind:a600000.dwc3"});
    check(fs::is_directory(f.kernel->functions / "gser.gs0") && fs::is_directory(f.kernel->functions / "acm.usb0") &&
          fs::is_directory(f.kernel->functions / "acm.dvmpoolx") && fs::is_directory(f.kernel->functions / "gser.dvmpool5") &&
          fs::exists(f.kernel->config / "f2"), "foreign functions untouched");
    // The index comes from port_num, never from the instance name.
    write_file(f.kernel->functions / "acm.dvmpool1/port_num", " 7 \n");
    write_file(f.kernel->dev / "ttyGS7", "");
    f.pool->release("a/serial2");
    expect(f.pool->acquire(1, "b/serial2", app(true, 2)), f.dev(7));
}
void udc_window() {
    // Not booted yet: the settle wait gives up after its timeout, then edits anyway.
    {
        Fixture f;
        f.boot = "0";
        f.pool->apply_config(app(true, 1));
        check(f.slept >= std::chrono::milliseconds(15000) && f.slept < std::chrono::milliseconds(16000), "settle timeout");
        check(f.logged("USB stack did not settle in time; attempting the gadget edit anyway"), "settle warning");
        check(f.linked(0) && f.kernel->bound(), "edit attempted anyway");
    }
    // Settled: one probe interval, no polling.
    {
        Fixture f;
        f.pool->apply_config(app(true, 1));
        check(f.slept == std::chrono::milliseconds(300), "one settle probe");
    }
    // An unbound UDC is not settled; the window binds the first UDC of the class.
    {
        Fixture f;
        write_file(f.kernel->udc, "\n");
        f.pool->apply_config(app(true, 1));
        expect(f.take(), {"mkdir:functions/acm.dvmpool0", "unbind", "link:configs/b.1/acm.dvmpool0", "bind:a600000.dwc3"});
        check(f.slept >= std::chrono::milliseconds(15000), "unbound UDC never settles");
    }
    // The HAL wins the first unbind: the attempt is lost and retried.
    {
        Fixture f;
        f.kernel->refuse_unbind = 1;
        expect(f.pool->acquire(0, "a/serial1", app(true, 1)), f.dev(0));
        expect(f.take(), {"mkdir:functions/acm.dvmpool0", "unbind", "unbind", "link:configs/b.1/acm.dvmpool0", "bind:a600000.dwc3"});
        check(f.logged("gadget reconcile attempt 1/3 lost the UDC race: gadget did not unbind (UDC still a600000.dwc3)"), "lost round logged");
    }
    // The HAL binds before us: our bind fails but the edits landed.
    {
        Fixture f;
        f.kernel->bind_raced = true;
        expect(f.pool->acquire(0, "a/serial1", app(true, 1)), f.dev(0));
        check(std::count(f.kernel->events.begin(), f.kernel->events.end(), "unbind") == 1, "a raced bind is not a failure");
    }
}
void failures() {
    {
        Fixture f;
        f.kernel->refuse_unbind = 3;
        f.pool->apply_config(app(true, 1)); // only logs
        check(f.logged("USB ACM pool reconcile failed: gadget did not unbind (UDC still a600000.dwc3)"), "apply_config logs");
        check(f.logged("gadget reconcile attempt 3/3 lost the UDC race"), "three attempts");
        f.kernel->refuse_unbind = 3;
        const auto text = error_of<std::runtime_error>([&] {
            try { f.pool->acquire(0, "a/serial1", app(true, 1)); }
            catch (const AcmSlotUnavailable&) { throw std::logic_error("a gadget failure must degrade, not refuse"); }
        });
        expect(text, "gadget did not unbind (UDC still a600000.dwc3)");
        check(f.pool->owners().empty(), "failed acquire holds nothing");
    }
    {
        Fixture f;
        write_file(f.kernel->udc, "");
        fs::remove(f.kernel->udc_class / "a600000.dwc3");
        f.boot = "0";
        expect(error_of<std::runtime_error>([&] { f.pool->acquire(0, "a/serial1", app(true, 1)); }), "no UDC available");
    }
    {
        Fixture f;
        f.kernel->bind_lost = true;
        const auto text = error_of<std::runtime_error>([&] { f.pool->acquire(0, "a/serial1", app(true, 1)); });
        check(text.starts_with(f.kernel->udc.string() + ": "), "a bind left unbound fails");
        check(std::count(f.kernel->events.begin(), f.kernel->events.end(), "bind:a600000.dwc3") == 3, "bind always attempted, every round");
    }
    {
        Fixture f;
        f.kernel->no_nodes = true;
        expect(error_of<std::runtime_error>([&] { f.pool->acquire(0, "a/serial1", app(true, 1)); }), f.dev(0) + " did not appear after bind");
        check(f.pool->owners().empty(), "no node, no owner");
        // waitForNode counts its polls: 3000 ms in 50 ms steps after the settle probe.
        check(f.slept == std::chrono::milliseconds(300 + 3000), "node wait");
    }
    {
        Fixture f;
        f.pool->apply_config(app(true, 1));
        write_file(f.kernel->functions / "acm.dvmpool0/port_num", "x\n");
        expect(error_of<std::runtime_error>([&] { f.pool->acquire(0, "a/serial1", app(true, 1)); }), "cannot parse acm port_num");
        fs::remove(f.kernel->functions / "acm.dvmpool0/port_num");
        const auto text = error_of<std::runtime_error>([&] { f.pool->acquire(0, "a/serial1", app(true, 1)); });
        check(text.starts_with((f.kernel->functions / "acm.dvmpool0/port_num").string() + " ("), "unreadable port_num");
    }
    {
        Fixture f;
        fs::remove_all(f.kernel->functions);
        const auto text = error_of<std::runtime_error>([&] { f.pool->acquire(0, "a/serial1", app(true, 1)); });
        expect(text, "cannot create " + (f.kernel->functions / "acm.dvmpool0").string());
        f.pool->apply_config(app(true, 1));
        check(f.logged("USB ACM pool reconcile failed: cannot create "), "mkdir failure logged");
    }
    {
        // A link the edit cannot make fails the round inside the window; the bind still runs.
        Fixture f;
        f.pool->apply_config(app(true, 1));
        fs::remove(f.kernel->config / "acm.dvmpool0");
        fs::create_symlink(f.kernel->root / "missing", f.kernel->config / "acm.dvmpool0");
        f.take();
        const auto text = error_of<std::runtime_error>([&] { f.pool->acquire(0, "a/serial1", app(true, 1)); });
        check(text.starts_with("symlink failed: "), "symlink failure text");
        check(f.kernel->bound(), "gadget never stranded unbound");
    }
}
}

int main(int argc, char** argv) {
    if (argc > 1) scratch = argv[1];
    return test::run({{"config_values", config_values},
                      {"managed_authority_and_live", managed_authority_and_live},
                      {"managed_udc_error_restores_without_retry", managed_udc_error_restores_without_retry},
                      {"pool_build_and_teardown", pool_build_and_teardown},
                      {"port_count_changes", port_count_changes},
                      {"acquire_and_release", acquire_and_release},
                      {"foreign_functions", foreign_functions},
                      {"udc_window", udc_window},
                      {"failures", failures}});
}
