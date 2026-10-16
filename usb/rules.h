// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "usb/java.h"
#include <json/json.h>
#include <array>
#include <functional>
#include <optional>
#include <string>
#include <vector>

// Port of daemon/usb/UsbRules: one global rule set, four ordered layers, and
// the master switch. Immutable once built and validated on the way in.
namespace droidvm::usb {
enum class Layer { exact, port, device, any };
inline constexpr std::array<Layer, 4> layers{Layer::exact, Layer::port, Layer::device, Layer::any};
const char* layer_key(Layer layer);
std::optional<Layer> layer_from_key(const std::string& key);
enum class Target { host, vm, sink };
const char* target_key(Target target);
std::optional<Target> target_from_key(const std::string& key);

struct Rule {
    std::optional<std::string> id, port, vm, controller;
    Target target = Target::host;
    // UsbRules.Rule.matches
    bool matches(const std::string& device_id, const std::string& device_port) const;
};
// (vm, controller) -> whether the rule's target is one the daemon can act on.
using TargetExists = std::function<bool(const std::string& vm, const std::optional<std::string>& controller)>;

class Rules {
public:
    static constexpr int version = 1;
    static Rules empty();
    // UsbRules.build; throws RequestError naming the layer, index and fault.
    // A null target check is the start-up read (rules for deleted VMs stay).
    static Rules build(bool enabled, const std::array<std::vector<Rule>, 4>& layers, const TargetExists& exists);
    // UsbRules.fromJson. Unknown keys are refused. Keys are visited in
    // jsoncpp (sorted) order where org.json used document order.
    static Rules from_json(const Json::Value& object, const TargetExists& exists);
    Json::Value to_json() const;
    bool enabled() const { return enabled_; }
    const std::vector<Rule>& layer(Layer layer) const { return layers_[static_cast<size_t>(layer)]; }
    bool is_empty() const;
private:
    bool enabled_ = true;
    std::array<std::vector<Rule>, 4> layers_;
};
// UsbRules.ID_PATTERN / PORT_PATTERN (String.matches).
bool valid_rule_id(const std::string& id);
bool valid_rule_port(const std::string& port);
}
