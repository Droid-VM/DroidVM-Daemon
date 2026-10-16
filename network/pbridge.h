// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "netbox.h"
#include "switch_runtime.h"
#include "runtime/managed_process.h"
#include "store/json_file.h"
#include <mutex>

namespace droidvm::network {
// Host state a pseudo-bridge-rs (pbridge) fwd-mode process creates and only
// removes on a clean exit: its fwd0/fwd1 veth pair (fwd1 inside our bridge),
// magic-metric guest proxy addresses on the uplink, and the shared
// "iif lo lookup 200" vmroute rules. TCX eBPF links die with the process
// (kernel >= 6.6); legacy netlink tc filters on older kernels are not covered.
class PbridgeOwnership {
public:
    static constexpr uint32_t vmroute_table = 200, vmroute_priority = 11000;
    PbridgeOwnership(int directory, uid_t uid, const Netbox& netbox);
    // Durable before the helper starts; the veth names must not exist yet.
    void acquire(const std::string& owner, const std::string& uplink, const std::string& fwd0, const std::string& fwd1);
    // Only after the owner's helper exited. Deletes its veth pair; the last
    // user of an uplink removes all its proxy addresses, and the last user
    // overall removes the shared rules, which remaining users get reasserted.
    void release(const std::string& owner);
    Json::Value recover_all(); // after helper recovery, before port/link recovery
    Json::Value inventory() const;
private:
    const Netbox& netbox_;
    config::JsonFile file_;
    mutable std::mutex mutex_;
    Json::Value document_;
    void save(Json::Value next);
    void release_locked(const std::string* owner);
    std::string kind(const std::string& link) const; // empty when absent
};
// One fwd-mode pbridge process with a recoverable helper identity.
class Pbridge {
public:
    Pbridge(std::string executable, SwitchRuntime& runtime);
    ~Pbridge();
    // Ready once fwd1 is a port of the bridge (hooks are live by then).
    void start(const std::string& owner, const std::string& uplink, const std::string& bridge,
               const std::string& fwd0, const std::string& fwd1);
    void stop(); // throws while the process may still be alive
    bool healthy() const { return ready_ && process_.status().running; }
    Json::Value tools() const;
    Json::Value tool_log() const;
    bool signal(int number) { return process_.signal(number); }
private:
    std::string executable_;
    SwitchRuntime& runtime_;
    SwitchRuntime::Allocation allocation_;
    ManagedProcess process_;
    bool ready_ = false;
};
}
