// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "services/system.h"
#include "services/tasks.h"
#include "services/network_config.h"
#include "services/network_host.h"
#include "services/network.h"
#include "services/vm.h"
#include "services/vm_config_upload.h"
#include "services/configuration.h"
#include "services/disk_config.h"
#include "services/legacy_events.h"
#include "network/host_watch.h"
#include "input/keyboard_grab.h"
#include "usb/service.h"
#include "pkg/service.h"

namespace droidvm {
struct ClientSession {
    Caller caller;
    std::string subscription;
    uint64_t cursor = 0;
    bool resource_events = false;
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
          keyboard_(keyboard) {
        if (networks_) vm_uploads_ = std::make_unique<ConfigUploads>(nullptr, networks_);
    }
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
    void set_packages(pkg::PkgService* service) { packages_ = service; }
    void set_disk_config(DiskConfigService* service) {
        if (!service || service->events() != &tasks_ || (disk_config_ && disk_config_ != service))
            throw std::invalid_argument("Disk registry adapter participants do not match");
        disk_config_ = service;
        if (!vm_uploads_) vm_uploads_ = std::make_unique<ConfigUploads>(vm_config_, networks_);
        vm_uploads_->bind_disks(service);
    }
    // Startup binding only; service outlives dispatcher and in-flight workers.
    void set_vm_config(VmConfigService* service) {
        if (configuration_ && service != &configuration_->vms()) throw std::invalid_argument("Cannot replace coordinated VM configuration");
        if (configuration_) return;
        if (vm_config_ == service && vm_uploads_) return;
        vm_uploads_ = service || networks_ || disk_config_ ? std::make_unique<ConfigUploads>(service, networks_,
            [] { return ConfigUploads::Clock::now(); }, ConfigUploads::DeleteNetwork{}, disk_config_) : nullptr;
        vm_config_ = service;
    }
    // Startup only. One staging manager shares all configuration upload quotas.
    void set_configuration(ConfigurationService* service) {
        if (!service || configuration_ || networks_ != &service->networks() || vms_ != &service->inventory() || &tasks_ != &service->events())
            throw std::invalid_argument("Configuration adapter participants do not match");
        if (service->disks() && disk_config_ && service->disks() != disk_config_)
            throw std::invalid_argument("Coordinated disk participant does not match");
        set_vm_config(&service->vms());
        if (service->disks()) set_disk_config(service->disks());
        vm_uploads_ = std::make_unique<ConfigUploads>(vm_config_, networks_, [] { return ConfigUploads::Clock::now(); },
            [service, lifecycle = runtime_](const CallContext& caller, const std::string& revision, const Json::Value& expected) {
                return service->remove_network(caller, revision, expected, lifecycle);
            }, disk_config_);
        if (service->disks()) vm_uploads_->bind_vm_disks(
            [service](const CallContext& caller, const std::string& vm_revision, const std::string& disk_revision,
                    Json::Value vms, Json::Value disks) {
                const auto result = service->replace_vm_disks(caller, vm_revision, disk_revision, std::move(vms), std::move(disks));
                return ConfigUploads::VmDisks{result.vms, result.disks};
            });
        configuration_ = service;
    }
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
    pkg::PkgService* packages_ = nullptr;
    VmConfigService* vm_config_ = nullptr;
    DiskConfigService* disk_config_ = nullptr;
    ConfigurationService* configuration_ = nullptr;
    std::unique_ptr<VmConfigUploads> vm_uploads_;
    bool vms_swept_ = false;
    Json::Value execute_vm(const CallContext& caller, const std::string& command, const Json::Value& request);
    Json::Value execute_keyboard(const CallContext& caller, const std::string& command, const Json::Value& request);
};
}
