// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "store/json_file.h"
#include <functional>
#include <mutex>
#include <set>

namespace droidvm::network {
// Host state a bridgedhcp PD client changes on its own: IPv6 from/to rules
// and routes in its dedicated table, and the uplink accept_ra (1 -> 2) and
// forwarding (0 -> 1) sysctls. The helper restores them only on a clean stop
// and only per process, so the daemon keeps a durable record and finishes
// cleanup after any helper exit. Shared across all Linux networks.
class PdOwnership {
public:
    using Observer = std::function<void(const char*)>;
    PdOwnership(int directory, uid_t uid, Observer observer = {},
                std::string sysctl_root = "/proc/sys/net/ipv6/conf");
    // Before starting a helper for this delegation. A table referenced by any
    // rule or route is foreign and rejected; the helper would flush it.
    void acquire(const std::string& owner, int vlan, uint32_t table, const std::string& uplink);
    // Only after the owner's helper exited. Flushes its tables, then restores
    // uplink sysctls still holding the helper's value, or reasserts them while
    // another network uses the same uplink. Failures keep the record.
    void release(const std::string& owner);
    Json::Value recover_all(); // after helper recovery, before link recovery
    std::set<uint32_t> tables() const; // never reflect return routes into these
    Json::Value inventory() const;
private:
    config::JsonFile file_;
    Observer observer_;
    std::string sysctl_root_;
    mutable std::mutex mutex_;
    Json::Value document_;
    void save(Json::Value next);
    void release_locked(const std::string* owner);
    std::string sysctl(const std::string& uplink, const char* key) const;
    void write_sysctl(const std::string& uplink, const char* key, const std::string& value) const;
    void point(const char* stage) { if (observer_) observer_(stage); }
};
// Table users visible to the kernel: rules of both families and routes.
size_t pd_table_users(uint32_t table);
void flush_pd_table(uint32_t table); // IPv6 rules and routes, as ip ... flush
}
