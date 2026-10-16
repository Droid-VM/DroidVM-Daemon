// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "store/json_file.h"

namespace droidvm::network {
// One inventory per private run directory, protected by the daemon Instance
// lock. Allocation/save is serialized; helper shutdown never holds the
// inventory mutex (the Instance lock still protects the whole lifetime).
// Owners serialize operations on one entry and drain workers before recovery.
class SwitchRuntime {
public:
    enum class Kind { gvswitch, bridgedhcp, pbridge, monitor, vm };
    struct Allocation { std::string name; Fd directory; };
    using Observer = std::function<void(const char*)>;
    SwitchRuntime(int directory, uid_t owner, Observer observer = {}, config::JsonFile::Observer file_observer = {});
    // The caller retains allocation even on exception, so stop can retry any
    // reservation installed before a failed fsync or directory operation.
    void allocate(const std::string& network_id, Allocation& allocation, Kind kind = Kind::gvswitch);
    void cleanup(const std::string& name);
    Json::Value recover_all(); // every failed entry retained; independent entries continue
    Json::Value inventory() const;
    uid_t owner() const { return owner_; }
private:
    Fd directory_;
    uid_t owner_;
    config::JsonFile file_;
    Observer observer_;
    mutable std::mutex mutex_;
    Json::Value document_;
    void save(Json::Value next);
    void erase(const std::string& name);
    Json::ArrayIndex find(const std::string& name) const;
    void point(const char* stage) { if (observer_) observer_(stage); }
};
}
