// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// The pure helpers of daemon/usb: UsbUevent, UsbLeftovers, UsbProbe and
// UsbRulePassTiming, plus the sysfs writer every bind/unbind goes through.
namespace droidvm::usb {
// UsbUevent.parse: nullopt for anything that is not SUBSYSTEM=usb.
struct Uevent {
    std::string action, name, devtype, driver;
    bool driver_change() const { return action == "bind" || action == "unbind"; }
    std::string text() const; // toString
    static std::optional<Uevent> parse(std::string_view message);
};

// UsbLeftovers: interfaces a restore had to leave unbound, by the VM holding them.
class Leftovers {
public:
    struct Scan { std::vector<std::string> free; std::vector<std::pair<std::string, std::string>> reclaimed; };
    bool empty() const { return order_.empty(); }
    size_t size() const { return order_.size(); }
    void leave(const std::string& iface, const std::string& vm);
    bool contains(const std::string& iface) const;
    std::vector<std::string> left_by(const std::string& vm) const;
    // Takes [ifaces] off the record, in argument order, with their VMs.
    std::vector<std::pair<std::string, std::string>> take(const std::vector<std::string>& ifaces);
    Scan scan(const std::map<std::string, std::string>& drivers);
    std::vector<std::string> forget_device(const std::string& sysfs);
    static std::string device_of(const std::string& iface);
private:
    std::vector<std::pair<std::string, std::string>> order_; // LinkedHashMap
};

// Every sysfs write the service makes; tests substitute a kernel model.
class SysfsWriter {
public:
    virtual ~SysfsWriter() = default;
    // Returns "" on success, else the error text for the log.
    virtual std::string write(const std::string& path, std::string_view text);
};

// UsbProbe over <devices>; [probe] is one drivers_probe write.
class Probe {
public:
    Probe(std::string devices, std::function<void(const std::string&)> probe,
          std::chrono::milliseconds timeout, std::chrono::milliseconds poll, std::function<bool()> interrupted);
    bool is_configured(const std::string& sysfs) const;
    std::vector<std::string> interfaces_of(const std::string& sysfs) const;
    std::string driver_of(const std::string& name) const;
    bool probe_device(const std::string& sysfs);
    void probe_interface(const std::string& iface) { probe_(iface); }
    int probe_interfaces(const std::string& sysfs);
    int give_to_host(const std::string& sysfs);
    bool configure_for_vm(const std::string& sysfs);
    bool await_interfaces(const std::string& sysfs, std::chrono::steady_clock::time_point deadline);
    std::chrono::milliseconds timeout() const { return timeout_; }
private:
    std::string devices_;
    std::function<void(const std::string&)> probe_;
    std::chrono::milliseconds timeout_, poll_;
    std::function<bool()> interrupted_;
};

// UsbRulePassTiming over a scheduler.
using Scheduler = std::function<void(std::function<void()> task, std::chrono::milliseconds delay)>;
struct Wait {
    std::function<bool()> wanted, ready;
    std::function<void()> then, abandoned, gave_up;
};
void when_ready(const Scheduler& scheduler, std::shared_ptr<Wait> wait, std::chrono::milliseconds poll, int max_polls);
void retry(const Scheduler& scheduler, std::function<bool()> attempt, std::chrono::milliseconds delay, int max_attempts);
}
