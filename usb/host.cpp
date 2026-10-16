// SPDX-License-Identifier: GPL-3.0-or-later
#include "usb/host.h"
#include "usb/device.h"
#include "common/fd.h"
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <thread>

namespace droidvm::usb {
std::optional<Uevent> Uevent::parse(std::string_view message) {
    std::string action, devpath, devtype, driver, subsystem;
    size_t start = 0;
    for (size_t i = 0; i <= message.size(); ++i) {
        if (i != message.size() && message[i] != '\0') continue;
        if (i > start) {
            const auto field = std::string(message.substr(start, i - start));
            const auto value = [&] { return field.substr(field.find('=') + 1); };
            if (field.starts_with("ACTION=")) action = value();
            else if (field.starts_with("DEVPATH=")) devpath = value();
            else if (field.starts_with("DEVTYPE=")) devtype = value();
            else if (field.starts_with("DRIVER=")) driver = value();
            else if (field.starts_with("SUBSYSTEM=")) subsystem = value();
        }
        start = i + 1;
    }
    // The "<action>@<devpath>" header repeats ACTION and DEVPATH; not read.
    if (subsystem != "usb" || action.empty() || devpath.empty()) return std::nullopt;
    const auto slash = devpath.rfind('/');
    return Uevent{action, slash == std::string::npos ? devpath : devpath.substr(slash + 1), devtype, driver};
}
std::string Uevent::text() const { return driver.empty() ? action + " " + name : action + " " + name + " (" + driver + ")"; }

void Leftovers::leave(const std::string& iface, const std::string& vm) {
    for (auto& entry : order_) if (entry.first == iface) { entry.second = vm; return; }
    order_.emplace_back(iface, vm);
}
bool Leftovers::contains(const std::string& iface) const {
    return std::any_of(order_.begin(), order_.end(), [&](const auto& entry) { return entry.first == iface; });
}
std::vector<std::string> Leftovers::left_by(const std::string& vm) const {
    std::vector<std::string> result;
    for (const auto& [iface, owner] : order_) if (owner == vm) result.push_back(iface);
    return result;
}
std::vector<std::pair<std::string, std::string>> Leftovers::take(const std::vector<std::string>& ifaces) {
    std::vector<std::pair<std::string, std::string>> result;
    for (const auto& iface : ifaces) {
        auto it = std::find_if(order_.begin(), order_.end(), [&](const auto& entry) { return entry.first == iface; });
        if (it == order_.end()) continue;
        // LinkedHashMap.put of a key already taken keeps its first slot.
        if (std::none_of(result.begin(), result.end(), [&](const auto& entry) { return entry.first == iface; })) result.emplace_back(*it);
        order_.erase(it);
    }
    return result;
}
Leftovers::Scan Leftovers::scan(const std::map<std::string, std::string>& drivers) {
    Scan result;
    for (auto it = order_.begin(); it != order_.end();) {
        auto driver = drivers.find(it->first);
        if (driver == drivers.end() || driver->second == "usbfs") { ++it; continue; }
        if (driver->second.empty()) { result.free.push_back(it->first); ++it; continue; }
        result.reclaimed.emplace_back(it->first, driver->second);
        it = order_.erase(it);
    }
    return result;
}
std::vector<std::string> Leftovers::forget_device(const std::string& sysfs) {
    std::vector<std::string> dropped;
    for (auto it = order_.begin(); it != order_.end();) {
        if (device_of(it->first) != sysfs) { ++it; continue; }
        dropped.push_back(it->first);
        it = order_.erase(it);
    }
    return dropped;
}
std::string Leftovers::device_of(const std::string& iface) {
    const auto colon = iface.find(':');
    return colon == std::string::npos ? iface : iface.substr(0, colon);
}

std::string SysfsWriter::write(const std::string& path, std::string_view text) {
    Fd file(open(path.c_str(), O_WRONLY | O_CLOEXEC));
    if (file.get() < 0) return std::strerror(errno);
    while (!text.empty()) {
        const auto count = ::write(file.get(), text.data(), text.size());
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return count < 0 ? std::strerror(errno) : "short write";
        text.remove_prefix(static_cast<size_t>(count));
    }
    return {};
}

Probe::Probe(std::string devices, std::function<void(const std::string&)> probe,
             std::chrono::milliseconds timeout, std::chrono::milliseconds poll, std::function<bool()> interrupted)
    : devices_(std::move(devices)), probe_(std::move(probe)), timeout_(timeout), poll_(poll), interrupted_(std::move(interrupted)) {}
bool Probe::is_configured(const std::string& sysfs) const { return !read_attribute(devices_ + "/" + sysfs, "bConfigurationValue").empty(); }
std::vector<std::string> Probe::interfaces_of(const std::string& sysfs) const {
    std::vector<std::string> names;
    const auto prefix = interface_prefix(sysfs);
    for (auto& name : list_directory(devices_)) if (name.starts_with(prefix)) names.push_back(std::move(name));
    std::sort(names.begin(), names.end());
    return names;
}
std::string Probe::driver_of(const std::string& name) const { return read_driver(devices_ + "/" + name); }
bool Probe::probe_device(const std::string& sysfs) {
    if (is_configured(sysfs)) return false;
    probe_(sysfs);
    return true;
}
int Probe::probe_interfaces(const std::string& sysfs) {
    int probed = 0;
    for (const auto& name : interfaces_of(sysfs)) {
        if (!driver_of(name).empty()) continue;
        probe_interface(name);
        ++probed;
    }
    return probed;
}
int Probe::give_to_host(const std::string& sysfs) {
    int probed = 0;
    if (probe_device(sysfs)) {
        ++probed;
        await_interfaces(sysfs, std::chrono::steady_clock::now() + timeout_);
    }
    return probed + probe_interfaces(sysfs);
}
bool Probe::configure_for_vm(const std::string& sysfs) {
    if (!interfaces_of(sysfs).empty()) return true;
    probe_device(sysfs);
    return await_interfaces(sysfs, std::chrono::steady_clock::now() + timeout_);
}
bool Probe::await_interfaces(const std::string& sysfs, std::chrono::steady_clock::time_point deadline) {
    while (interfaces_of(sysfs).empty()) {
        if (!is_directory(devices_ + "/" + sysfs)) return false;
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(poll_);
        if (interrupted_ && interrupted_()) return false;
    }
    return true;
}

namespace {
void probe_ready(const Scheduler& scheduler, std::shared_ptr<Wait> wait, std::chrono::milliseconds poll, int max_polls, int attempt) {
    if (!wait->wanted()) { wait->abandoned(); return; }
    if (wait->ready()) { wait->then(); return; }
    if (attempt >= max_polls) { wait->gave_up(); return; }
    scheduler([=] { probe_ready(scheduler, wait, poll, max_polls, attempt + 1); }, poll);
}
}
void when_ready(const Scheduler& scheduler, std::shared_ptr<Wait> wait, std::chrono::milliseconds poll, int max_polls) {
    scheduler([=] { probe_ready(scheduler, wait, poll, max_polls, 1); }, std::chrono::milliseconds(0));
}
void retry(const Scheduler& scheduler, std::function<bool()> attempt, std::chrono::milliseconds delay, int max_attempts) {
    if (max_attempts <= 0) return;
    scheduler([=] { if (!attempt()) retry(scheduler, attempt, delay, max_attempts - 1); }, delay);
}
}
