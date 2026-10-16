// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "usb/engine.h"
#include <json/json.h>
#include <functional>
#include <optional>
#include <string>
#include <vector>

// Port of daemon/usb/UsbHostDevice and the scan/diff half of UsbHostInventory.
namespace droidvm::usb {
struct Interface { std::string name, cls, subcls, proto, driver; };
struct HostDevice {
    std::string sysfs, id, port;
    int busnum = 0, devnum = 0;
    std::string node, vid, pid, manufacturer, product, serial, speed, device_class;
    bool authorized = true;
    std::vector<Interface> interfaces; // sorted by name
    bool is_hub() const;
    DeviceState state() const;
    EngineDevice engine() const { return {sysfs, id, port, devnum, state()}; }
    Json::Value to_json() const; // the wire fields of UsbHostDevice.toMap
};
// UsbHostDevice.fromSysfs; throws std::runtime_error for a device whose
// required files are missing (one torn down mid-scan).
HostDevice read_device(const std::string& directory, const std::string& dev_root);
std::string derive_id(const std::string& vid, const std::string& pid, const std::string& serial);
std::string derive_port(const std::string& sysfs);
bool is_hub_class(const std::string& device_class);
bool is_root_hub_name(const std::string& sysfs);
std::string interface_prefix(const std::string& sysfs);
// Basename of <directory>/driver, "" when nothing holds it.
std::string read_driver(const std::string& directory);
// One sysfs attribute, trimmed; "" when missing or unreadable.
std::string read_attribute(const std::string& directory, const char* name);
bool is_directory(const std::string& path);
std::vector<std::string> list_directory(const std::string& path); // names, unsorted; empty on error
// new File(root, child) normalised; nullopt unless its parent is root.
std::optional<std::string> child_name(const std::string& child);

// UsbHostInventory.scan: every device directory, sorted by name. [warn]
// receives the skip/list messages.
std::vector<HostDevice> scan_devices(const std::string& sysfs_root, const std::string& dev_root,
    const std::function<void(const std::string&)>& warn = {});
struct Diff {
    std::vector<HostDevice> all, added, removed, changed;
    bool empty() const { return added.empty() && removed.empty() && changed.empty(); }
    const char* reason() const { return !added.empty() ? "plug" : !removed.empty() ? "unplug" : "drivers"; }
    static Diff between(const std::vector<HostDevice>& previous, const std::vector<HostDevice>& now);
};
}
