// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "services/system.h"
#include "services/tasks.h"
#include "services/network_config.h"
#include "services/network_host.h"
#include "services/network.h"
#include "services/vm.h"
#include "services/legacy_events.h"
#include "network/host_watch.h"
#include "input/keyboard_grab.h"
#include "usb/service.h"

namespace droidvm {
struct ClientSession {
    Caller caller;
    std::string subscription;
    uint64_t cursor = 0;
};
// Existing system/legacy shapes stay in their adapter; new task commands expose
// structured errors and decimal cursors without changing old command results.
class RequestDispatcher {
public:
    RequestDispatcher(SystemService& system, TaskService& tasks, NetworkConfigService* networks = nullptr,
                      NetworkHostService* host_network = nullptr, NetworkService* runtime = nullptr,
                      network::HostIpv4Watch* host_ipv4 = nullptr, VmService* vms = nullptr, LegacyEvents* events = nullptr,
                      input::KeyboardGrab* keyboard = nullptr)
        : system_(system), tasks_(tasks), networks_(networks), host_network_(host_network), runtime_(runtime), host_ipv4_(host_ipv4), vms_(vms), events_(events),
          keyboard_(keyboard) {}
    LegacyEvents* legacy_events() const { return events_; }
    bool has_maintenance() const { return runtime_ != nullptr || host_ipv4_ != nullptr || (vms_ && !vms_swept_); }
    void maintenance() {
        if (runtime_) runtime_->schedule_reconcile(tasks_);
        if (host_ipv4_) host_ipv4_->schedule(tasks_);
        // Server.run: VMs come up behind the socket, after the network auto-up.
        if (vms_ && !vms_swept_ && (!runtime_ || runtime_->autostart_settled())) { vms_swept_ = true; vms_->auto_up_async(); }
    }
    // NativeDisplayBinder.attach, where the platform Binder services exist.
    void set_display_attach(std::function<void(const std::string& nonce)> attach) { display_attach_ = std::move(attach); }
    void set_usb(usb::UsbService* service) { usb_ = service; }
    bool background(const std::string& command) const;
    Json::Value execute_background(const CallContext& caller, const std::string& command, const Json::Value& request);
    TaskService& workers() { return tasks_; }
    Json::Value execute(ClientSession& session, const std::string& command, const Json::Value& request);
    std::optional<Json::Value> events(ClientSession& session);
    void disconnected(ClientSession& session) noexcept;
private:
    SystemService& system_;
    TaskService& tasks_;
    NetworkConfigService* networks_;
    NetworkHostService* host_network_;
    NetworkService* runtime_;
    network::HostIpv4Watch* host_ipv4_;
    VmService* vms_;
    LegacyEvents* events_;
    input::KeyboardGrab* keyboard_;
    std::function<void(const std::string&)> display_attach_;
    usb::UsbService* usb_ = nullptr;
    bool vms_swept_ = false;
    Json::Value execute_vm(const CallContext& caller, const std::string& command, const Json::Value& request);
    Json::Value execute_keyboard(const CallContext& caller, const std::string& command, const Json::Value& request);
};
}
