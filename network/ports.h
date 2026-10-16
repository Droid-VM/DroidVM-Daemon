// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "netbox.h"
#include "store/json_file.h"
#include <mutex>

namespace droidvm::network {
// Foreign host interfaces (L2 uplinks) enslaved into an owned bridge. The
// link itself is never ours: release only detaches it, and only while it is
// still the recorded device attached to the recorded bridge.
class OwnedPorts {
public:
    OwnedPorts(int directory, uid_t uid, const Netbox& netbox, std::string sysfs = "/sys/class/net");
    // Durable before the kernel change; rejects a port already in a bridge.
    void attach(const std::string& owner, const std::string& port, const std::string& bridge);
    bool attached(const std::string& owner) const; // every record still enslaved
    void release(const std::string& owner); // before releasing the bridge
    Json::Value recover_all(); // before OwnedLinks::recover_all at startup
    Json::Value inventory() const;
private:
    const Netbox& netbox_;
    config::JsonFile file_;
    std::string sysfs_;
    mutable std::mutex mutex_;
    Json::Value document_;
    void save(Json::Value next);
    void release_locked(const std::string* owner);
    uint32_t index(const std::string& port) const; // 0 when absent
    std::string master(const std::string& port) const; // empty when none
};
}
