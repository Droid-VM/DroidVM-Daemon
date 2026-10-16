// SPDX-License-Identifier: GPL-3.0-or-later
#include "usb/rules.h"
#include <unicode/uchar.h>
#include <unicode/utf8.h>

namespace droidvm::usb {
namespace {
bool hex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
// Android's (ICU) '.' stops at \n, \v, \f, \r, U+0085, U+2028 and U+2029.
bool line_terminator_free(std::string_view text) {
    for (size_t i = 0; i < text.size(); ++i) {
        const auto c = static_cast<unsigned char>(text[i]);
        if (c == '\n' || c == '\v' || c == '\f' || c == '\r') return false;
        if (c == 0xc2 && i + 1 < text.size() && static_cast<unsigned char>(text[i + 1]) == 0x85) return false;
        if (c == 0xe2 && i + 2 < text.size() && static_cast<unsigned char>(text[i + 1]) == 0x80 &&
            (static_cast<unsigned char>(text[i + 2]) == 0xa8 || static_cast<unsigned char>(text[i + 2]) == 0xa9)) return false;
    }
    return true;
}
std::string where(Layer layer, size_t index) { return std::string(layer_key(layer)) + "[" + std::to_string(index) + "]"; }
[[noreturn]] void refuse(const std::string& message) { throw RequestError(message); }
Rule validate(Layer layer, size_t index, const Rule& rule, const TargetExists& exists) {
    const auto at = where(layer, index);
    const bool wants_id = layer == Layer::exact || layer == Layer::device;
    const bool wants_port = layer == Layer::exact || layer == Layer::port;
    const std::string key = layer_key(layer);
    if (wants_id && !rule.id) refuse(at + ": missing id");
    if (!wants_id && rule.id) refuse(at + ": a " + key + " rule takes no id");
    if (wants_port && !rule.port) refuse(at + ": missing port");
    if (!wants_port && rule.port) refuse(at + ": a " + key + " rule takes no port");
    if (rule.target == Target::sink && rule.vm) refuse(at + ": a sink rule takes no vm");
    if (rule.target == Target::vm && !rule.vm) refuse(at + ": a vm rule needs a vm");
    if (rule.target == Target::host && rule.vm) refuse(at + ": a host rule takes no vm");
    if (rule.controller) {
        if (!rule.vm) refuse(at + ": controller needs a vm");
        if (rule.controller->empty()) refuse(at + ": controller must be a controller id or null");
    }
    Rule out = rule;
    if (rule.id) {
        if (!valid_rule_id(*rule.id)) refuse(at + ": bad id " + *rule.id + " (want vid:pid or vid:pid:serial)");
        // vid:pid is hex and lowercased; the serial is compared as reported.
        out.id = lower(rule.id->substr(0, 9)) + rule.id->substr(9);
    }
    if (rule.port && !valid_rule_port(*rule.port)) refuse(at + ": bad port " + *rule.port + " (want a port chain such as 1.2.2)");
    if (rule.vm) {
        if (rule.vm->empty()) refuse(at + ": vm must be a VM id or null");
        if (exists && !exists(*rule.vm, rule.controller))
            refuse(!rule.controller ? at + ": VM not found: " + *rule.vm : at + ": VM " + *rule.vm + " has no USB controller " + *rule.controller);
    }
    return out;
}
// A string field where an absent key and a JSON null both read as null.
std::optional<std::string> opt_text(const Json::Value& item, const char* key) {
    if (!present(item, key)) return std::nullopt;
    if (!item[key].isString()) refuse(std::string(key) + " must be a string or null");
    return item[key].asString();
}
Rule rule_from_json(const std::string& layer, size_t index, const Json::Value& item) {
    const auto at = layer + "[" + std::to_string(index) + "]";
    for (const auto& key : item.getMemberNames())
        if (key != "id" && key != "port" && key != "vm" && key != "controller" && key != "target")
            refuse(at + ": unknown field " + key);
    Rule rule;
    rule.vm = opt_text(item, "vm");
    const auto wanted = opt_text(item, "target");
    // No target: written before targets existed; the vm field says it all.
    std::optional<Target> target = !wanted ? (rule.vm ? Target::vm : Target::host) : target_from_key(*wanted);
    if (!target) refuse(at + ": unknown target " + *wanted);
    rule.target = *target;
    rule.id = opt_text(item, "id");
    rule.port = opt_text(item, "port");
    rule.controller = opt_text(item, "controller");
    return rule;
}
}
const char* layer_key(Layer layer) {
    switch (layer) {
    case Layer::exact: return "exact";
    case Layer::port: return "port";
    case Layer::device: return "device";
    case Layer::any: return "any";
    }
    return "any";
}
std::optional<Layer> layer_from_key(const std::string& key) {
    for (auto layer : layers) if (key == layer_key(layer)) return layer;
    return std::nullopt;
}
const char* target_key(Target target) {
    switch (target) {
    case Target::host: return "host";
    case Target::vm: return "vm";
    case Target::sink: return "sink";
    }
    return "host";
}
std::optional<Target> target_from_key(const std::string& key) {
    for (auto target : {Target::host, Target::vm, Target::sink}) if (key == target_key(target)) return target;
    return std::nullopt;
}
bool Rule::matches(const std::string& device_id, const std::string& device_port) const {
    if (id && *id != device_id) return false;
    return !port || *port == device_port;
}
bool valid_rule_id(const std::string& id) {
    if (id.size() < 9 || id[4] != ':') return false;
    for (size_t i : {0, 1, 2, 3, 5, 6, 7, 8}) if (!hex(id[i])) return false;
    if (id.size() == 9) return true;
    return id[9] == ':' && id.size() > 10 && line_terminator_free(std::string_view(id).substr(10));
}
bool valid_rule_port(const std::string& port) {
    // ^\d+(\.\d+)*$ under ICU: \d is any Unicode decimal digit (Nd).
    bool digit = false;
    int32_t offset = 0;
    const auto length = static_cast<int32_t>(port.size());
    while (offset < length) {
        UChar32 c;
        U8_NEXT(port.data(), offset, length, c);
        if (c >= 0 && u_isdigit(c)) { digit = true; continue; }
        if (c != '.' || !digit) return false;
        digit = false;
    }
    return digit;
}
Rules Rules::empty() { return build(true, {}, nullptr); }
Rules Rules::build(bool enabled, const std::array<std::vector<Rule>, 4>& input, const TargetExists& exists) {
    Rules result;
    result.enabled_ = enabled;
    for (auto layer : layers) {
        const auto& rules = input[static_cast<size_t>(layer)];
        auto& checked = result.layers_[static_cast<size_t>(layer)];
        for (size_t i = 0; i < rules.size(); ++i) checked.push_back(validate(layer, i, rules[i], exists));
    }
    return result;
}
Rules Rules::from_json(const Json::Value& object, const TargetExists& exists) {
    std::array<std::vector<Rule>, 4> parsed;
    // Absent reads as on; anything but a boolean is refused.
    bool enabled = true;
    if (present(object, "enabled")) {
        if (!object["enabled"].isBool()) refuse("enabled must be true or false");
        enabled = object["enabled"].asBool();
    }
    for (const auto& key : object.getMemberNames()) {
        if (key == "enabled") continue;
        const auto& value = object[key];
        if (key == "version") {
            if (!value.isNumeric() || int_value(value) != version) refuse("unsupported rules version " + java_string(value));
            continue;
        }
        const auto layer = layer_from_key(key);
        if (!layer) refuse("unknown rules key: " + key);
        if (!value.isArray()) {
            if (value.isNull()) continue;
            refuse(key + " must be a list");
        }
        std::vector<Rule> rules;
        for (Json::ArrayIndex i = 0; i < value.size(); ++i) {
            if (!value[i].isObject()) refuse(key + "[" + std::to_string(i) + "] must be an object");
            rules.push_back(rule_from_json(key, i, value[i]));
        }
        parsed[static_cast<size_t>(*layer)] = std::move(rules);
    }
    return build(enabled, parsed, exists);
}
Json::Value Rules::to_json() const {
    Json::Value object(Json::objectValue);
    object["version"] = version;
    object["enabled"] = enabled_;
    for (auto layer : layers) {
        Json::Value array(Json::arrayValue);
        for (const auto& rule : this->layer(layer)) {
            Json::Value item(Json::objectValue);
            if (rule.id) item["id"] = *rule.id;
            if (rule.port) item["port"] = *rule.port;
            item["target"] = target_key(rule.target);
            if (rule.vm) item["vm"] = *rule.vm;
            if (rule.controller) item["controller"] = *rule.controller;
            array.append(std::move(item));
        }
        object[layer_key(layer)] = std::move(array);
    }
    return object;
}
bool Rules::is_empty() const {
    for (auto layer : layers) if (!this->layer(layer).empty()) return false;
    return true;
}
}
