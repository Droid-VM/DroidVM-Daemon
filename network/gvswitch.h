// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "backend.h"
#include "runtime/managed_process.h"
#include "control_http.h"
#include "switch_runtime.h"
#include <map>
#include <vector>

namespace droidvm::network {
class Netbox;
class OwnedLinks;
// One real gvswitch data path (GvisorBridgeBackend). VM NICs are owned TAPs
// that gvswitch takes over through AF_XDP, with their static leases and
// expanded local forwards; a relaunch re-posts the ports of retained TAPs.
class Gvswitch final : public Backend {
public:
    Gvswitch(std::string executable, SwitchRuntime& runtime, const Netbox* netbox = nullptr, OwnedLinks* links = nullptr);
    ~Gvswitch() override;
    void start(const Json::Value& config) override;
    bool healthy() const override;
    void refresh() override;
    void recover(const Json::Value& config) override;
    void stop() override;
    Json::Value tools() const override;
    Json::Value tool_log(const std::string& key) const override;
    void attach(const Json::Value& nic, const std::string& tap) override;
    void detach(const Json::Value& nic, const std::string& tap) override;
    Json::Value forward_failures() const override;
    void live_details(Json::Value& data) const override;
    Json::Value dhcp_leases() const override;
    ProcessStatus status() const { return process_.status(); }
    std::deque<ProcessLine> log() const { return process_.log(); }
    // Administrative lifecycle control uses held pidfd, never a raw PID.
    bool signal(int number) { return process_.signal(number); }
private:
    std::string executable_;
    SwitchRuntime& runtime_;
    SwitchRuntime::Allocation allocation_;
    ManagedProcess process_;
    std::unique_ptr<ControlHttp> client_;
    bool ready_ = false;
    const Netbox* netbox_;
    OwnedLinks* links_;
    Json::Value config_;
    std::map<std::string, Json::Value> attached_; // tap -> NIC
    std::map<std::string, std::vector<std::string>> installed_, failures_; // tap -> "vlan/id" refs, failure texts
    bool retain_taps_ = false;
    std::string socket_; // control socket, as appendInfo gvswitch_socket
    void remove_directory();
    std::string tap_owner(const std::string& tap) const;
    ControlResponse call(HttpMethod method, const std::string& path, const Json::Value* body = nullptr, ControlOptions options = {std::chrono::seconds(5), {}}) const;
    void post_port(const Json::Value& nic, const std::string& tap);
    void apply_leases(const Json::Value& nic, const std::string& tap);
    void remove_leases(const Json::Value& nic, const std::string& tap);
    void install_forwards(Json::Value nic, const std::string& tap);
    void remove_forwards(const std::string& tap);
    void release_tap(const std::string& tap);
};
}
