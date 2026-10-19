// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_listener.h"
#include "listen_plan.h"

namespace droidvm::web {
struct WebSettings {
    bool enabled = false;
    uint16_t port = 8080;
    ListenScope scope = ListenScope::lan;
    std::vector<std::string> public_origins;
    bool lan_auto_login = false;
    Json::Value json() const;
    static WebSettings parse(const Json::Value& value);
    bool operator==(const WebSettings&) const = default;
};
bool ipv6_available();

// Trusted local IPC owns pairing and recovery. Browser administration queues
// configuration changes through HttpApi. Maintenance posts scans to existing
// workers; no polling thread or second service. Stop before shared workers die.
class WebService {
public:
    using Discover = std::function<network::HostNetworkSnapshot()>;
    using Save = std::function<void(const Json::Value&)>;
    using Load = std::function<WebSettings()>;
    WebService(TaskService& workers, WebSettings settings, Discover discover,
               HttpApi::ListVms list_vms, Save save, Load load, WebBuild build, std::function<bool()> ipv6 = ipv6_available,
               VmOperations vms = {}, VmLogs logs = {}, ConfigOperations config = {}, ResourceCatalogs resources = {}, UsbOperations usb = {}, ConfigOperations usb_rules = {}, SessionPersistence persistence = {});
    ~WebService();
    WebService(const WebService&) = delete;
    WebService& operator=(const WebService&) = delete;
    Json::Value execute(const CallContext& caller, const std::string& command, const Json::Value& request);
    void schedule(); // Nonblocking, called by the existing daemon maintenance loop.
    void stop();
private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
};
}
