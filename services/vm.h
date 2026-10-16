// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "context.h"
#include <json/json.h>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace droidvm {
enum class VmState { stopped, starting, running, suspended, stopping, rebooting };
const char* vm_state_name(VmState state);
// In-memory VM inventory with VMInstanceStore semantics. vms.json is read
// once at startup and never written: the app owns it and re-sends a config
// (vm_create/vm_modify) before every start. Every rebuilt entry is migrated.
class VmService {
public:
    // A file that fails to load as a whole starts empty, as DataStore.load.
    explicit VmService(int files_directory);
    VmService() = default;
    Json::Value list(const CallContext& caller) const;
    Json::Value get(const CallContext& caller, const std::string& id) const;
    bool exists(const CallContext& caller, const std::string& id) const;
    VmState state(const CallContext& caller, const std::string& id) const;
    std::string create(const CallContext& caller, Json::Value config);
    // Rejects a VM that is not stopped. A rejected rename keeps the old entry.
    std::string modify(const CallContext& caller, Json::Value config);
    bool remove(const CallContext& caller, const std::string& id); // false when unknown
    size_t loaded() const { return loaded_; }
    const std::string& load_error() const { return load_error_; }
private:
    struct Entry { std::string id; Json::Value config; VmState state = VmState::stopped; };
    mutable std::mutex mutex_;
    std::vector<Entry> entries_;
    size_t loaded_ = 0;
    std::string load_error_;
    static std::optional<std::string> canonical(const std::string& id);
    const Entry* find(const std::string& id) const;
    void add(Entry entry); // DataStore.add: name required, id/name unique
};
}
