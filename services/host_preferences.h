// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "tasks.h"
#include <functional>
#include <memory>
#include <optional>

namespace droidvm {
struct HostPreferencesLoaded {
    Json::Value document;
    bool recovered = false;
};
enum class HostPreferencesSave { saved, not_saved, installed_uncertain };
enum class HostPreferenceDomain { vm_start, disk_operations };
void validate_host_preference_values(const Json::Value& values, bool complete,
    HostPreferenceDomain domain = HostPreferenceDomain::vm_start);
struct HostPreferencesOptions {
    // Trusted composition; load runs synchronously before any runtime sees values.
    std::function<std::optional<HostPreferencesLoaded>()> load;
    std::function<HostPreferencesSave(const Json::Value&)> save;
    HostPreferenceDomain domain = HostPreferenceDomain::vm_start;
};
// Single persistent owner shared by App IPC, Web and VM startup. Join TaskService
// before destroying it. A store exception with unknown installation is latched:
// no automatic retries/imports until the next authoritative startup load.
class HostPreferencesService {
public:
    static constexpr const char* capability = "host-preferences-v1";
    static constexpr const char* disk_defaults_capability = "disk-defaults-v1";
    HostPreferencesService(TaskService&, HostPreferencesOptions);
    ~HostPreferencesService();
    Json::Value snapshot(const CallContext&) const;
    Json::Value values() const; // Trusted runtime read; never an App cache.
    Json::Value sync_legacy(const CallContext&, const Json::Value& config);
    TaskView start(const CallContext&, const Json::Value& request);
    TaskView status(const CallContext&, const std::string& request_id);
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
