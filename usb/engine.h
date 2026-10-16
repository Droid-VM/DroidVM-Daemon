// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "usb/rules.h"
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

// Port of daemon/usb/UsbRuleEngine. Pure; every call is made under the
// service lock.
namespace droidvm::usb {
enum class DeviceState { hostuse, vmuse, idle };
const char* state_key(DeviceState state);
enum class VmState { stopped, starting, running, suspended, stopping, rebooting };

struct EngineDevice {
    std::string sysfs, id, port;
    int devnum = 0;
    DeviceState state = DeviceState::idle;
};
struct Decision {
    EngineDevice device;
    std::optional<Layer> layer; // null for the fifth zone's rule
    int index = -1;
    Target target = Target::host;
    std::optional<std::string> vm, controller;
    std::string where() const; // "device[0]" or "the default rule"
};
enum class SaveOwes { nothing, release, pass };
// VM state by id, nullopt when there is no such VM.
using StateOf = std::function<std::optional<VmState>(const std::string& vm)>;
using HasController = std::function<bool(const std::string& vm, const std::optional<std::string>& controller)>;

class RuleEngine {
public:
    const Rules& rules() const { return rules_; }
    void set_rules(Rules rules) { rules_ = std::move(rules); }
    bool rules_enabled() const { return rules_.enabled(); }
    bool recovers_idle_devices(bool daemon_start) const { return rules_enabled() || daemon_start; }
    SaveOwes save_owes(const Rules& next) const;
    bool is_locked(const std::string& sysfs, int devnum) const;
    void lock(const std::string& sysfs, int devnum);
    void unlock(const std::string& sysfs);
    void mark_failed(const std::string& sysfs, const std::string& vm);
    void forget_failures_for(const std::string& vm);
    void forget(const std::string& sysfs);
    void clear_locks();
    bool is_candidate(const EngineDevice& device) const;
    std::vector<Decision> plan(const std::vector<EngineDevice>& plugged, const StateOf& state_of, const HasController& has_controller) const;
    std::optional<Decision> decide(const EngineDevice& device, const StateOf& state_of, const HasController& has_controller) const;
private:
    struct Flags { std::optional<int> locked_for; std::optional<std::string> failed_for; };
    Rules rules_ = Rules::empty();
    std::map<std::string, Flags> flags_;
};
}
