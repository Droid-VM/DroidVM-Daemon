// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "helper_config.h"
#include "control_http.h"
#include "switch_runtime.h"
#include "runtime/managed_process.h"
#include "pd_state.h"

namespace droidvm::network {
// Serialized by the Linux backend's worker. Caller owns the bridge topology
// and stops this helper before releasing links or its configuration lease.
class BridgeDhcp {
public:
    BridgeDhcp(std::string executable, SwitchRuntime& runtime, int state_directory);
    ~BridgeDhcp();
    // uplinks: resolved PD uplink per VLAN. The caller registers each with
    // PdOwnership first; an unresolved PD VLAN runs without a PD client.
    bool start(Json::Value network, std::map<int, DhcpStatics> statics = {}, std::map<int, std::string> uplinks = {});
    void restart(); // reuses persistent leases; caller enforces recovery backoff
    void stop(); // temporary resources only; lease state survives normal stop
    bool healthy() const { return ready_ && process_.status().running; }
    Json::Value status() const;
    Json::Value leases(int vlan, bool ipv6) const;
    // Single mailbox consumer; force=true provides the watcher's periodic
    // status backstop even if no stdout event arrived. Do not mix with raw
    // take_output consumption. Logs remain available through tool_log().
    PdSnapshot poll_pd(bool force = false);
    void set_statics(int vlan, DhcpStatics statics);
    Json::Value tools() const;
    Json::Value tool_log() const;
    ProcessStatus process_status() const { return process_.status(); }
    ProcessOutput take_output() { return process_.take_output(); }
    bool signal(int number) { return process_.signal(number); }
    static std::string state_file(const Json::Value& network);
private:
    std::string executable_;
    SwitchRuntime& runtime_;
    Fd state_directory_;
    SwitchRuntime::Allocation allocation_;
    ManagedProcess process_;
    std::unique_ptr<ControlHttp> client_;
    Json::Value network_;
    std::map<int, DhcpStatics> statics_;
    std::map<int, std::string> uplinks_;
    std::map<int, std::string> devices_;
    PdState pd_;
    bool ready_ = false;
    std::string endpoint(int vlan) const;
    Json::Value request(HttpMethod method, const std::string& path,
                        std::optional<std::string_view> body = {}) const;
};
}
