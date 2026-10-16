// SPDX-License-Identifier: GPL-3.0-or-later
#include "usb/watch.h"
#include "usb/device.h"
#include <linux/netlink.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <set>

namespace droidvm::usb {
namespace {
constexpr uint32_t root_mask = IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM;
constexpr uint32_t bus_mask = IN_CREATE | IN_DELETE;
constexpr uint32_t lost_events = IN_Q_OVERFLOW | IN_UNMOUNT;
bool bus_name(const std::string& name) {
    if (name.empty()) return false;
    for (char c : name) if (c < '0' || c > '9') return false;
    return true;
}
}
HostUsbWatch::HostUsbWatch(std::string dev_root, std::function<void(const std::string&)> log)
    : dev_root_(std::move(dev_root)), log_(std::move(log)) {}
HostUsbWatch::~HostUsbWatch() { stop(); }
void HostUsbWatch::start(std::function<void(const WatchEvent&)> notify) {
    if (thread_.joinable()) return;
    notify_ = std::move(notify);
    inotify_ = Fd(inotify_init1(IN_CLOEXEC | IN_NONBLOCK));
    if (inotify_.get() >= 0) {
        root_watch_ = inotify_add_watch(inotify_.get(), dev_root_.c_str(), root_mask);
        if (root_watch_ < 0 && log_) log_("Cannot watch " + dev_root_ + ": " + std::strerror(errno));
        refresh_buses();
    } else if (log_) {
        log_(std::string("No inotify instance: ") + std::strerror(errno));
    }
    uevent_ = Fd(socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT));
    sockaddr_nl address{};
    address.nl_family = AF_NETLINK;
    address.nl_groups = 1;
    if (uevent_.get() < 0 || bind(uevent_.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        if (log_) log_("No uevent socket; a driver unbound by hand will not be noticed");
        uevent_ = Fd();
    }
    int wake[2];
    if (pipe2(wake, O_CLOEXEC) != 0) {
        if (log_) log_("No pipe for the USB watch; nothing will be noticed");
        return;
    }
    wake_read_ = Fd(wake[0]);
    wake_write_ = Fd(wake[1]);
    thread_ = std::thread([this] { run(); });
}
void HostUsbWatch::stop() {
    if (wake_write_.get() >= 0) {
        const char byte = 1;
        while (::write(wake_write_.get(), &byte, 1) < 0 && errno == EINTR) {}
    }
    if (thread_.joinable()) thread_.join();
    wake_write_ = Fd(); wake_read_ = Fd(); uevent_ = Fd(); inotify_ = Fd();
    root_watch_ = -1;
    buses_.clear();
}
bool HostUsbWatch::refresh_buses() {
    std::lock_guard lock(mutex_);
    if (inotify_.get() < 0 || root_watch_ < 0) return false;
    std::set<std::string> present;
    for (const auto& name : list_directory(dev_root_)) if (bus_name(name) && is_directory(dev_root_ + "/" + name)) present.insert(name);
    std::set<std::string> watched;
    for (const auto& [wd, name] : buses_) watched.insert(name);
    const bool changed = present != watched;
    for (const auto& name : present) {
        if (watched.contains(name)) continue;
        const int wd = inotify_add_watch(inotify_.get(), (dev_root_ + "/" + name).c_str(), bus_mask);
        if (wd >= 0) buses_[wd] = name;
    }
    for (auto it = buses_.begin(); it != buses_.end();) {
        if (present.contains(it->second)) { ++it; continue; }
        inotify_rm_watch(inotify_.get(), it->first);
        it = buses_.erase(it);
    }
    return changed;
}
void HostUsbWatch::run() {
    alignas(inotify_event) char buffer[8192];
    while (true) {
        pollfd fds[3] = {{wake_read_.get(), POLLIN, 0}, {inotify_.get(), POLLIN, 0}, {uevent_.get(), POLLIN, 0}};
        const int ready = poll(fds, 3, -1);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || fds[0].revents) return;
        if (fds[1].revents & POLLIN) {
            const auto count = ::read(inotify_.get(), buffer, sizeof(buffer));
            WatchEvent event;
            bool wanted = false;
            for (ssize_t offset = 0; count > 0 && offset < count;) {
                const auto* raw = reinterpret_cast<const inotify_event*>(buffer + offset);
                offset += static_cast<ssize_t>(sizeof(inotify_event) + raw->len);
                const bool root = raw->wd == root_watch_;
                const bool lost = (raw->mask & lost_events) != 0;
                if ((raw->mask & ((root ? root_mask : bus_mask) | lost_events)) == 0) continue;
                // Dropped events or a bus directory moving: rebuild the bus watches first.
                if ((root || lost) && refresh_buses()) event.buses_changed = true;
                wanted = true;
            }
            if (wanted && notify_) notify_(event);
        }
        if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) inotify_ = Fd();
        if (fds[2].revents & (POLLIN | POLLERR)) {
            const auto count = recv(uevent_.get(), buffer, sizeof(buffer), 0);
            if (count < 0 && errno == ENOBUFS) {
                // The socket overflowed: whatever was missed is a rescan.
                if (notify_) notify_({});
            } else if (count > 0) {
                auto parsed = Uevent::parse(std::string_view(buffer, static_cast<size_t>(count)));
                if (parsed && notify_) notify_({false, std::move(parsed)});
            } else if (count == 0 || (errno != EAGAIN && errno != EINTR)) {
                uevent_ = Fd();
            }
        }
        if (fds[2].revents & (POLLHUP | POLLNVAL)) uevent_ = Fd();
    }
}
}
