// SPDX-License-Identifier: GPL-3.0-or-later
#include "usb/engine.h"

namespace droidvm::usb {
const char* state_key(DeviceState state) {
    switch (state) {
    case DeviceState::hostuse: return "hostuse";
    case DeviceState::vmuse: return "vmuse";
    case DeviceState::idle: return "idle";
    }
    return "idle";
}
std::string Decision::where() const {
    return layer ? std::string(layer_key(*layer)) + "[" + std::to_string(index) + "]" : "the default rule";
}
SaveOwes RuleEngine::save_owes(const Rules& next) const {
    if (rules_.enabled() && !next.enabled()) return SaveOwes::release;
    return next.enabled() ? SaveOwes::pass : SaveOwes::nothing;
}
bool RuleEngine::is_locked(const std::string& sysfs, int devnum) const {
    auto it = flags_.find(sysfs);
    return it != flags_.end() && it->second.locked_for && *it->second.locked_for == devnum;
}
void RuleEngine::lock(const std::string& sysfs, int devnum) { flags_[sysfs].locked_for = devnum; }
void RuleEngine::unlock(const std::string& sysfs) {
    auto it = flags_.find(sysfs);
    if (it == flags_.end()) return;
    it->second.locked_for.reset();
    if (!it->second.failed_for) flags_.erase(it);
}
void RuleEngine::mark_failed(const std::string& sysfs, const std::string& vm) { flags_[sysfs].failed_for = vm; }
void RuleEngine::forget_failures_for(const std::string& vm) {
    for (auto it = flags_.begin(); it != flags_.end();) {
        if (it->second.failed_for != vm) { ++it; continue; }
        it->second.failed_for.reset();
        if (!it->second.locked_for) it = flags_.erase(it); else ++it;
    }
}
void RuleEngine::forget(const std::string& sysfs) { flags_.erase(sysfs); }
void RuleEngine::clear_locks() {
    for (auto it = flags_.begin(); it != flags_.end();) {
        it->second.locked_for.reset();
        if (!it->second.failed_for) it = flags_.erase(it); else ++it;
    }
}
bool RuleEngine::is_candidate(const EngineDevice& device) const {
    return device.state != DeviceState::vmuse && !is_locked(device.sysfs, device.devnum);
}
std::vector<Decision> RuleEngine::plan(const std::vector<EngineDevice>& plugged, const StateOf& state_of, const HasController& has_controller) const {
    std::vector<Decision> decisions;
    if (!rules_.enabled()) return decisions;
    for (const auto& device : plugged) {
        if (!is_candidate(device)) continue;
        if (auto decision = decide(device, state_of, has_controller)) decisions.push_back(std::move(*decision));
    }
    return decisions;
}
std::optional<Decision> RuleEngine::decide(const EngineDevice& device, const StateOf& state_of, const HasController& has_controller) const {
    if (!rules_.enabled()) return std::nullopt;
    auto f = flags_.find(device.sysfs);
    const std::optional<std::string> failed_for = f == flags_.end() ? std::nullopt : f->second.failed_for;
    for (auto layer : layers) {
        const auto& list = rules_.layer(layer);
        for (size_t index = 0; index < list.size(); ++index) {
            const auto& rule = list[index];
            if (!rule.matches(device.id, device.port)) continue;
            if (rule.target != Target::vm)
                return Decision{device, layer, static_cast<int>(index), rule.target, std::nullopt, std::nullopt};
            if (state_of(*rule.vm) != VmState::running) continue;
            if (!has_controller(*rule.vm, rule.controller)) continue;
            if (failed_for == rule.vm) continue;
            return Decision{device, layer, static_cast<int>(index), Target::vm, rule.vm, rule.controller};
        }
    }
    return Decision{device, std::nullopt, -1, Target::host, std::nullopt, std::nullopt};
}
}
