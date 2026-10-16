// SPDX-License-Identifier: GPL-3.0-or-later
#include "usb/device.h"
#include "common/fd.h"
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <map>
#include <stdexcept>

namespace droidvm::usb {
namespace {
bool digits(std::string_view text) {
    if (text.empty()) return false;
    for (char c : text) if (c < '0' || c > '9') return false;
    return true;
}
std::optional<std::string> read_bytes(const std::string& path) {
    Fd file(open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (file.get() < 0) return std::nullopt;
    std::string bytes;
    char buffer[4096];
    while (true) {
        const auto count = ::read(file.get(), buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return std::nullopt;
        if (count == 0) break;
        bytes.append(buffer, static_cast<size_t>(count));
        if (bytes.size() > (1u << 20)) return std::nullopt;
    }
    return bytes;
}
std::string base(const std::string& path) {
    const auto slash = path.rfind('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}
std::string required(const std::string& directory, const char* name) {
    const auto path = directory + "/" + name;
    auto bytes = read_bytes(path);
    if (!bytes) throw std::runtime_error(path);
    return trim(utf8_lossy(*bytes));
}
int required_int(const std::string& directory, const char* name) {
    const auto raw = required(directory, name);
    const auto value = parse_int(raw);
    if (!value) throw std::runtime_error(base(directory) + "/" + name + " is not a number: " + raw);
    return *value;
}
// StringUtils.pathJoin
std::string path_join(std::string root, const std::string& child) {
    if (!root.empty() && root.back() == '/') root.pop_back();
    return root + "/" + (child.empty() || child.front() != '/' ? child : child.substr(1));
}
std::string three(int value) {
    char buffer[16];
    std::snprintf(buffer, sizeof(buffer), "%03d", value);
    return buffer;
}
// ^<prefix>\d+\.\d+$
bool interface_name(const std::string& name, const std::string& prefix) {
    if (!name.starts_with(prefix)) return false;
    const auto rest = std::string_view(name).substr(prefix.size());
    const auto dot = rest.find('.');
    return dot != std::string_view::npos && digits(rest.substr(0, dot)) && digits(rest.substr(dot + 1));
}
// ^(\d+-[\d.]+|usb\d+)$
bool device_name(const std::string& name) {
    if (is_root_hub_name(name)) return true;
    const auto dash = name.find('-');
    if (dash == std::string::npos || !digits(std::string_view(name).substr(0, dash)) || dash + 1 >= name.size()) return false;
    for (size_t i = dash + 1; i < name.size(); ++i) if (!(name[i] == '.' || (name[i] >= '0' && name[i] <= '9'))) return false;
    return true;
}
bool same_drivers(const HostDevice& was, const HostDevice& now) {
    if (was.interfaces.size() != now.interfaces.size()) return false;
    for (size_t i = 0; i < was.interfaces.size(); ++i) {
        if (was.interfaces[i].name != now.interfaces[i].name) return false;
        if (was.interfaces[i].driver != now.interfaces[i].driver) return false;
    }
    return true;
}
std::string instance_key(const HostDevice& device) { return device.sysfs + "#" + std::to_string(device.devnum); }
}
bool is_directory(const std::string& path) {
    struct stat info{};
    return stat(path.c_str(), &info) == 0 && S_ISDIR(info.st_mode);
}
std::vector<std::string> list_directory(const std::string& path) {
    std::vector<std::string> names;
    DIR* dir = opendir(path.c_str());
    if (!dir) return names;
    while (auto* entry = readdir(dir)) {
        std::string name = entry->d_name;
        if (name != "." && name != "..") names.push_back(std::move(name));
    }
    closedir(dir);
    return names;
}
std::string read_attribute(const std::string& directory, const char* name) {
    try { return required(directory, name); } catch (const std::exception&) { return {}; }
}
std::string read_driver(const std::string& directory) {
    char target[4096];
    const auto path = directory + "/driver";
    const auto count = readlink(path.c_str(), target, sizeof(target) - 1);
    if (count <= 0) return {};
    std::string link(target, static_cast<size_t>(count));
    while (link.size() > 1 && link.back() == '/') link.pop_back();
    if (link == "/") return {};
    return base(link);
}
std::optional<std::string> child_name(const std::string& child) {
    std::string name;
    for (char c : child) {
        if (c == '/' && (name.empty() || name.back() == '/')) continue;
        name += c;
    }
    while (!name.empty() && name.back() == '/') name.pop_back();
    if (name.empty() || name.find('/') != std::string::npos) return std::nullopt;
    return name;
}
std::string derive_id(const std::string& vid, const std::string& pid, const std::string& serial) {
    auto id = lower(vid) + ":" + lower(pid);
    return serial.empty() ? id : id + ":" + serial;
}
std::string derive_port(const std::string& sysfs) {
    const auto dash = sysfs.find('-');
    return dash == std::string::npos ? sysfs : sysfs.substr(dash + 1);
}
bool is_hub_class(const std::string& device_class) { return lower(trim(device_class)) == "09"; }
bool is_root_hub_name(const std::string& sysfs) { return sysfs.size() > 3 && sysfs.starts_with("usb") && digits(std::string_view(sysfs).substr(3)); }
std::string interface_prefix(const std::string& sysfs) {
    return is_root_hub_name(sysfs) ? sysfs.substr(3) + "-0:" : sysfs + ":";
}
HostDevice read_device(const std::string& directory, const std::string& dev_root) {
    HostDevice device;
    device.sysfs = base(directory);
    device.vid = lower(required(directory, "idVendor"));
    device.pid = lower(required(directory, "idProduct"));
    device.busnum = required_int(directory, "busnum");
    device.devnum = required_int(directory, "devnum");
    device.device_class = lower(required(directory, "bDeviceClass"));
    device.node = path_join(path_join(dev_root, three(device.busnum)), three(device.devnum));
    const auto prefix = interface_prefix(device.sysfs);
    for (const auto& name : list_directory(directory)) {
        const auto path = directory + "/" + name;
        if (!is_directory(path) || !interface_name(name, prefix)) continue;
        device.interfaces.push_back({name, lower(read_attribute(path, "bInterfaceClass")), lower(read_attribute(path, "bInterfaceSubClass")),
            lower(read_attribute(path, "bInterfaceProtocol")), read_driver(path)});
    }
    std::sort(device.interfaces.begin(), device.interfaces.end(), [](const auto& a, const auto& b) { return a.name < b.name; });
    device.manufacturer = read_attribute(directory, "manufacturer");
    device.product = read_attribute(directory, "product");
    device.serial = read_attribute(directory, "serial");
    device.speed = read_attribute(directory, "speed");
    device.authorized = read_attribute(directory, "authorized") != "0";
    device.id = derive_id(device.vid, device.pid, device.serial);
    device.port = derive_port(device.sysfs);
    return device;
}
bool HostDevice::is_hub() const {
    if (is_hub_class(device_class)) return true;
    for (const auto& iface : interfaces) if (iface.cls == "09") return true;
    return false;
}
DeviceState HostDevice::state() const {
    bool claimed = false, bound = false;
    for (const auto& iface : interfaces) {
        if (iface.driver.empty()) continue;
        if (iface.driver == "usbfs") claimed = true; else bound = true;
    }
    if (claimed) return DeviceState::vmuse;
    return bound ? DeviceState::hostuse : DeviceState::idle;
}
Json::Value HostDevice::to_json() const {
    Json::Value obj(Json::objectValue);
    obj["sysfs"] = sysfs; obj["id"] = id; obj["port"] = port;
    obj["busnum"] = busnum; obj["devnum"] = devnum; obj["node"] = node;
    obj["vid"] = vid; obj["pid"] = pid; obj["manufacturer"] = manufacturer; obj["product"] = product;
    obj["serial"] = serial; obj["speed"] = speed; obj["device_class"] = device_class;
    obj["state"] = state_key(state());
    Json::Value list(Json::arrayValue);
    for (const auto& iface : interfaces) {
        Json::Value item(Json::objectValue);
        item["name"] = iface.name; item["class"] = iface.cls; item["subclass"] = iface.subcls;
        item["protocol"] = iface.proto; item["driver"] = iface.driver;
        list.append(std::move(item));
    }
    obj["interfaces"] = std::move(list);
    return obj;
}
std::vector<HostDevice> scan_devices(const std::string& sysfs_root, const std::string& dev_root, const std::function<void(const std::string&)>& warn) {
    std::vector<HostDevice> devices;
    if (!is_directory(sysfs_root)) {
        if (warn) warn("Cannot list " + sysfs_root);
        return devices;
    }
    for (const auto& name : list_directory(sysfs_root)) {
        if (!device_name(name)) continue;
        try {
            devices.push_back(read_device(sysfs_root + "/" + name, dev_root));
        } catch (const std::exception& error) {
            // Disconnected mid-scan: its files are already gone.
            if (warn) warn("Skipping USB device " + name + ": " + error.what());
        }
    }
    std::sort(devices.begin(), devices.end(), [](const auto& a, const auto& b) { return a.sysfs < b.sysfs; });
    return devices;
}
Diff Diff::between(const std::vector<HostDevice>& previous, const std::vector<HostDevice>& now) {
    std::map<std::string, const HostDevice*> before, after;
    for (const auto& device : previous) before[instance_key(device)] = &device;
    for (const auto& device : now) after[instance_key(device)] = &device;
    Diff diff;
    diff.all = now;
    for (const auto& device : now) {
        auto was = before.find(instance_key(device));
        if (was == before.end()) diff.added.push_back(device);
        else if (!same_drivers(*was->second, device)) diff.changed.push_back(device);
    }
    for (const auto& device : previous) if (!after.contains(instance_key(device))) diff.removed.push_back(device);
    return diff;
}
}
