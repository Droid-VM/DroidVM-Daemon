// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "netbox.h"
#include "store/json_file.h"
#include <mutex>

namespace droidvm::network {
// A durable inventory of links created by this daemon. The caller holds the
// daemon instance lock for this object's lifetime and serializes each network's
// operations. No destructor side effects: cleanup failures must be reported.
// Never adopt a link merely because its name matches a configuration.
class OwnedLinks {
public:
    using Observer = std::function<void(const char*)>;
    OwnedLinks(int directory, uid_t uid, const Netbox& netbox, Observer observer = {},
               config::JsonFile::Observer file_observer = {});
    void bridge(const std::string& owner, const std::string& name);
    void tap(const std::string& owner, const std::string& name);
    void vlan(const std::string& owner, const std::string& parent, const std::string& name, int vid);
    void require_owned(const std::string& owner, const std::string& name) const;
    void remove(const std::string& owner, const std::string& name);
    // Reverse creation order; attempt every independent record even on error.
    // Failures remain in inventory, rather than falsely reporting STOPPED.
    Json::Value cleanup(const std::string& owner);
    Json::Value inventory() const;
    static std::string vlan_code(int vid);
    static std::string vlan_device(const std::string& bridge, int vid);
    static std::string vlan_leg(const std::string& bridge, int vid);
private:
    const Netbox& netbox_;
    config::JsonFile file_;
    Observer observer_;
    mutable std::mutex mutex_;
    Json::Value document_;
    std::string boot_;
    uint64_t namespace_device_, namespace_inode_;
    void save(Json::Value next);
    void create(const std::string& owner, const std::string& name, const char* kind,
                const std::string& parent = {}, int vid = 0);
    Json::ArrayIndex find(const std::string& owner, const std::string& name) const;
    bool matches(const Json::Value& record, bool allow_pending) const;
    void remove_at(Json::ArrayIndex index);
    void point(const char* stage) { if (observer_) observer_(stage); }
};
}
