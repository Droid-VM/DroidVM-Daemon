// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "usb/host.h"
#include "common/fd.h"
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

// The inventory's event sources (UsbHostInventory's FileObserver watch on
// /dev/bus/usb and its NETLINK_KOBJECT_UEVENT reader). They decide nothing:
// every event only asks for a debounced rescan.
namespace droidvm::usb {
struct WatchEvent {
    bool buses_changed = false;   // a bus directory under dev_root came or went
    std::optional<Uevent> uevent; // set for a USB uevent
};
class UsbWatch {
public:
    virtual ~UsbWatch() = default;
    // [notify] runs on the watch's own thread.
    virtual void start(std::function<void(const WatchEvent&)> notify) = 0;
    virtual void stop() = 0;
};
// inotify on dev_root and every bus directory, plus the kernel uevent socket.
// Both are best effort, as in the legacy daemon; [warn] gets the reasons.
class HostUsbWatch : public UsbWatch {
public:
    HostUsbWatch(std::string dev_root, std::function<void(const std::string&)> log = {});
    ~HostUsbWatch() override;
    void start(std::function<void(const WatchEvent&)> notify) override;
    void stop() override;
private:
    std::string dev_root_;
    std::function<void(const std::string&)> log_;
    std::function<void(const WatchEvent&)> notify_;
    Fd inotify_, uevent_, wake_read_, wake_write_;
    int root_watch_ = -1;
    std::map<int, std::string> buses_; // wd -> bus name
    std::thread thread_;
    std::mutex mutex_;
    bool refresh_buses();
    void run();
};
}
