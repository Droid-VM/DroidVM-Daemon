// SPDX-License-Identifier: GPL-3.0-or-later
// Port of lib/store/network/{NetworkConfig,VlanConfig,NetworkConfigValidator}.
#include "network_config.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <unicode/uchar.h>
#include <unicode/utf8.h>
#include <algorithm>
#include <bit>
#include <cmath>
#include <cstdlib>
#include <limits>
#include <regex>
#include <set>
#include <stdexcept>
#include <vector>

namespace droidvm::config {
const Json::Value& member(const Json::Value& value, const char* key) {
    static const Json::Value empty;
    return value.isObject() ? value[key] : empty;
}
std::string string(const Json::Value& value, const char* key, std::string fallback) {
    const auto& field = member(value, key);
    return field.isString() ? field.asString() : std::move(fallback);
}
bool boolean(const Json::Value& value, const char* key, bool fallback) {
    const auto& field = member(value, key);
    return field.isBool() ? field.asBool() : fallback;
}
int64_t integer(const Json::Value& value, const char* key, int64_t fallback) {
    const auto& field = member(value, key);
    return (field.type() == Json::intValue || field.type() == Json::uintValue) && field.isInt64()
        ? field.asInt64() : fallback;
}
namespace {
[[noreturn]] void invalid(const std::string& text) { throw std::invalid_argument(text); }
std::string trim(std::string text) {
    size_t first = 0, last = text.size();
    while (first < last && static_cast<unsigned char>(text[first]) <= 0x20) ++first;
    while (last > first && static_cast<unsigned char>(text[last - 1]) <= 0x20) --last;
    return text.substr(first, last - first);
}
int narrow(int64_t value) { return std::bit_cast<int32_t>(static_cast<uint32_t>(value)); }
int double_int(double value) {
    if (std::isnan(value)) return 0;
    if (value >= INT32_MAX) return INT32_MAX;
    if (value <= INT32_MIN) return INT32_MIN;
    return static_cast<int>(value);
}
Json::Value& section(Json::Value& value, const char* key) {
    if (!value[key].isObject()) value[key] = Json::Value(Json::objectValue);
    return value[key];
}
std::vector<std::string> strings(const Json::Value& value, const char* key) {
    std::vector<std::string> result;
    const auto& array = member(value, key);
    if (array.isArray()) for (const auto& entry : array)
        if (entry.isString() && !entry.asString().empty()) result.push_back(entry.asString());
    return result;
}
Json::Value array(const std::vector<std::string>& values, size_t begin = 0) {
    Json::Value result(Json::arrayValue);
    for (size_t i = begin; i < values.size(); ++i) result.append(values[i]);
    return result;
}
int64_t java_integer(std::string_view value, int radix, uint64_t maximum) {
    bool negative = !value.empty() && value.front() == '-';
    if (!value.empty() && (value.front() == '+' || value.front() == '-')) value.remove_prefix(1);
    if (value.empty() || value.size() > INT32_MAX) invalid("invalid integer");
    uint64_t result = 0, limit = maximum + unsigned(negative);
    int32_t offset = 0, length = static_cast<int32_t>(value.size());
    while (offset < length) {
        UChar32 character;
        U8_NEXT(value.data(), offset, length, character);
        // Java's parseInt/parseLong iterate UTF-16 char values, not code points.
        int digit = character >= 0 && character <= 0xffff ? u_digit(character, static_cast<int8_t>(radix)) : -1;
        if (digit < 0 || result > (limit - static_cast<unsigned>(digit)) / static_cast<unsigned>(radix)) invalid("invalid integer");
        result = result * static_cast<unsigned>(radix) + static_cast<unsigned>(digit);
    }
    if (negative && result == uint64_t(INT64_MAX) + 1) return INT64_MIN;
    return negative ? -static_cast<int64_t>(result) : static_cast<int64_t>(result);
}
int decimal(std::string_view value) { return static_cast<int>(java_integer(value, 10, INT32_MAX)); }
}
int64_t java_long(std::string_view text) { return java_integer(text, 10, INT64_MAX); }
namespace {
uint32_t ipv4(std::string_view text) {
    uint32_t result = 0;
    for (int part = 0; part < 4; ++part) {
        auto dot = text.find('.');
        if ((part < 3) != (dot != std::string_view::npos)) invalid("invalid IPv4 address");
        int octet = decimal(text.substr(0, dot));
        if (octet < 0 || octet > 255) invalid("invalid IPv4 octet");
        result = (result << 8) | static_cast<uint32_t>(octet);
        if (dot != std::string_view::npos) text.remove_prefix(dot + 1);
    }
    return result;
}
struct V4 { uint32_t address, base; int prefix; uint64_t count; };
V4 network4(const std::string& cidr) {
    auto slash = cidr.find('/');
    if (slash == std::string::npos) invalid("invalid IPv4 CIDR");
    auto address = ipv4(std::string_view(cidr).substr(0, slash));
    int prefix = decimal(std::string_view(cidr).substr(slash + 1));
    if (prefix < 0 || prefix > 32) invalid("invalid IPv4 prefix");
    uint32_t mask = prefix ? UINT32_MAX << (32 - prefix) : 0;
    return {address, address & mask, prefix, uint64_t(1) << (32 - prefix)};
}
struct V6 { in6_addr address; int prefix; };
V6 network6(const std::string& cidr) {
    auto slash = cidr.rfind('/');
    if (slash == std::string::npos) invalid("invalid IPv6 CIDR");
    auto address = cidr.substr(0, slash);
    auto scope = address.find('%');
    if (scope != std::string::npos) address.resize(scope);
    if (address.size() >= 2 && address.front() == '[' && address.back() == ']')
        address = address.substr(1, address.size() - 2);
    in6_addr bytes{};
    if (address.empty() || address.find('\0') != std::string::npos) invalid("invalid IPv6 address");
    if (inet_pton(AF_INET6, address.c_str(), &bytes) != 1) {
        // The existing Java InetAddress API also accepts hostnames. Keep that
        // behavior; callers must run validation on a worker, never epoll.
        addrinfo hints{}, *resolved = nullptr;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(address.c_str(), nullptr, &hints, &resolved) != 0 || !resolved) invalid("invalid IPv6 address");
        bool valid = resolved->ai_family == AF_INET6;
        if (valid) bytes = reinterpret_cast<sockaddr_in6*>(resolved->ai_addr)->sin6_addr;
        freeaddrinfo(resolved);
        if (!valid) invalid("invalid IPv6 address");
    }
    if (IN6_IS_ADDR_V4MAPPED(&bytes)) invalid("invalid IPv6 address");
    int prefix = decimal(std::string_view(cidr).substr(slash + 1));
    if (prefix < 0 || prefix > 128) invalid("invalid IPv6 prefix");
    return {bytes, prefix};
}
std::string mode(const Json::Value& value) { return string(value, "uplink_mode") == "l2" ? "l2" : "l3"; }
std::string bridge(const Json::Value& value) { return string(value, "bridge_type") == "gvisor" ? "gvisor" : "linux"; }
std::string source(const Json::Value& value) { return string(value, "source") == "dhcp_pd" ? "dhcp_pd" : "static"; }
Json::Value nullable(const std::string& text) { return text.empty() ? Json::Value() : Json::Value(text); }
void offsets(const Json::Value& dhcp, const std::string& label, const std::string& protocol, uint64_t maximum = 0) {
    auto start = integer(dhcp, "offset_start", 128), end = integer(dhcp, "offset_end", 192);
    if (start <= 0 || end < start)
        invalid("VLAN " + label + ": invalid " + protocol + " pool offsets " + std::to_string(start) + "-" + std::to_string(end));
    if (maximum && static_cast<uint64_t>(end) >= maximum)
        invalid("VLAN " + label + ": " + protocol + " pool offset " + std::to_string(end) + " exceeds the network size");
}
void validate_vlan(Json::Value& vlan, bool gvisor) {
    auto id = narrow(integer(vlan, "vlan_id"));
    auto label = id == 0 ? "untagged" : std::to_string(id);
    auto& v4 = section(vlan, "ipv4");
    auto cidr4 = string(v4, "cidr");
    std::optional<V4> net4;
    if (!cidr4.empty()) {
        try { net4 = network4(cidr4); } catch (...) { invalid("VLAN " + label + ": invalid IPv4 CIDR: " + cidr4); }
        if (net4->prefix > 30) invalid("VLAN " + label + ": IPv4 prefix /" + std::to_string(net4->prefix) + " too small for a gateway network");
        if (net4->address == net4->base || net4->address == net4->base + net4->count - 1) {
            auto address = net4->address;
            std::string text;
            for (int shift = 24; shift >= 0; shift -= 8) { if (!text.empty()) text += '.'; text += std::to_string((address >> shift) & 255); }
            invalid("VLAN " + label + ": IPv4 gateway address must be a host address, not " + text);
        }
        if (boolean(member(v4, "dhcp"), "enabled")) offsets(member(v4, "dhcp"), label, "DHCPv4", net4->count - 1);
    }
    auto& v6 = section(vlan, "ipv6");
    auto cidr6 = string(v6, "cidr");
    const bool pd = source(v6) == "dhcp_pd";
    if (pd) {
        if (gvisor) invalid("VLAN " + label + ": DHCP-PD is only available on Linux bridges");
        const auto& config = member(v6, "pd");
        if (trim(string(config, "uplink")).empty()) invalid("VLAN " + label + ": DHCP-PD requires an uplink interface");
        auto duid = string(config, "duid");
        if (!duid.empty() && !std::regex_match(duid, std::regex("([0-9a-fA-F]{2}:)*[0-9a-fA-F]{2}")))
            invalid("VLAN " + label + ": invalid DUID");
    } else if (!cidr6.empty()) {
        int prefix;
        try { prefix = network6(cidr6).prefix; } catch (...) { invalid("VLAN " + label + ": invalid IPv6 CIDR: " + cidr6); }
        if (prefix > 126) invalid("VLAN " + label + ": IPv6 prefix /" + std::to_string(prefix) + " too small");
        if (boolean(member(v6, "slaac"), "enabled") && prefix != 64) invalid("VLAN " + label + ": SLAAC requires a /64 network");
    }
    if ((pd || !cidr6.empty()) && boolean(member(v6, "dhcp"), "enabled")) offsets(member(v6, "dhcp"), label, "DHCPv6");
    auto secondary4 = strings(vlan, "ipv4_secondary"), secondary6 = strings(vlan, "ipv6_secondary");
    if (gvisor && (!secondary4.empty() || !secondary6.empty())) invalid("VLAN " + label + ": secondary networks are not supported on gVisor bridges");
    for (const auto& cidr : secondary4)
        try { network4(cidr); } catch (...) { invalid("VLAN " + label + ": invalid secondary IPv4 CIDR: " + cidr); }
    for (const auto& cidr : secondary6)
        try { network6(cidr); } catch (...) { invalid("VLAN " + label + ": invalid secondary IPv6 CIDR: " + cidr); }
}
}
int schema(const Json::Value& object) {
    const auto& value = member(object, "schema");
    if (value.type() == Json::intValue || value.type() == Json::uintValue)
        return value.isInt64() ? narrow(value.asInt64()) : double_int(value.asDouble());
    if (value.isDouble()) return double_int(value.asDouble());
    if (value.isString()) {
        auto text = trim(value.asString());
        char* end = nullptr;
        double parsed = std::strtod(text.c_str(), &end);
        if (!text.empty() && end == text.c_str() + text.size()) return double_int(parsed);
    }
    return 0;
}
std::string uuid(const Json::Value& object) {
    auto text = string(object, "id");
    int32_t offset = 0, length = static_cast<int32_t>(text.size()), characters = 0;
    while (offset < length) {
        UChar32 character;
        U8_NEXT(text.data(), offset, length, character);
        if (character < 0) invalid("Invalid UUID string");
        characters += character > 0xffff ? 2 : 1;
        if (characters > 36) invalid("Invalid UUID string");
    }
    std::string output;
    constexpr int lengths[] = {8, 4, 4, 4, 12};
    std::string_view rest(text);
    for (int i = 0; i < 5; ++i) {
        auto dash = rest.find('-');
        if ((i < 4) != (dash != std::string_view::npos)) invalid("Invalid UUID string");
        auto part = rest.substr(0, dash);
        uint64_t number = 0;
        try { number = static_cast<uint64_t>(java_integer(part, 16, INT64_MAX)); }
        catch (const std::invalid_argument&) { invalid("Invalid UUID string"); }
        std::string field(lengths[i], '0');
        for (int pos = lengths[i] - 1; pos >= 0; --pos) { field[pos] = "0123456789abcdef"[number & 15]; number >>= 4; }
        if (i) output += '-';
        output += field;
        if (dash != std::string_view::npos) rest.remove_prefix(dash + 1);
    }
    return output;
}
Json::Value default_vlan(int id) {
    Json::Value value(Json::objectValue);
    value["vlan_id"] = id;
    for (const auto* family : {"ipv4", "ipv6"}) {
        auto& ip = value[family];
        ip["cidr"] = Json::Value();
        ip["snat"] = std::string_view(family) == "ipv4";
        ip["dhcp"]["enabled"] = true;
        ip["dhcp"]["offset_start"] = 128;
        ip["dhcp"]["offset_end"] = 192;
    }
    value["ipv6"]["source"] = "static";
    value["ipv6"]["slaac"]["enabled"] = true;
    for (const auto* key : {"dns_servers", "ipv4_secondary", "ipv6_secondary"}) value[key] = Json::Value(Json::arrayValue);
    return value;
}
std::optional<Json::Value> migrate_network(const Json::Value& original) {
    if (!original.isObject()) invalid("network config must be an object");
    int version = schema(original);
    if (version == 2) return original;
    if (version > 2) return std::nullopt;
    // Preserve fields a newer writer may understand, including legacy keys.
    Json::Value result = original;
    result["schema"] = 2;
    for (const char* key : {"id", "name", "bridge_name"}) {
        auto value = string(original, key);
        if (!value.empty()) result[key] = value;
        else result.removeMember(key);
    }
    result["bridge_type"] = "linux";
    result["uplink_mode"] = "l3";
    result["stp"] = boolean(original, "stp");
    result["auto_up"] = boolean(original, "auto_up");
    section(result, "l2");
    auto& l3 = section(result, "l3");
    auto mac = string(original, "mac_address");
    if (!mac.empty()) l3["mac_address"] = mac;
    auto addresses4 = strings(original, "ipv4_addresses"), addresses6 = strings(original, "ipv6_addresses");
    auto vlan = default_vlan(0);
    auto& v4 = vlan["ipv4"];
    v4["cidr"] = addresses4.empty() ? Json::Value() : Json::Value(addresses4.front());
    v4["snat"] = boolean(original, "nat");
    v4["dhcp"]["enabled"] = boolean(original, "dhcp_enabled") && !addresses4.empty();
    auto start = string(original, "dhcp_range_start"), end = string(original, "dhcp_range_end");
    if (!addresses4.empty() && !start.empty() && !end.empty()) {
        try {
            auto net = network4(addresses4.front());
            auto first = static_cast<int64_t>(ipv4(start)) - net.base;
            auto last = static_cast<int64_t>(ipv4(end)) - net.base;
            v4["dhcp"]["offset_start"] = Json::Int64(first);
            v4["dhcp"]["offset_end"] = Json::Int64(last);
        } catch (const std::invalid_argument&) { /* Existing 128..192 default. */ }
    }
    auto& v6 = vlan["ipv6"];
    v6["cidr"] = addresses6.empty() ? Json::Value() : Json::Value(addresses6.front());
    v6["dhcp"]["enabled"] = false;
    v6["slaac"]["enabled"] = false;
    vlan["ipv4_secondary"] = array(addresses4, 1);
    vlan["ipv6_secondary"] = array(addresses6, 1);
    l3["vlans"] = Json::Value(Json::arrayValue);
    l3["vlans"].append(std::move(vlan));
    return result;
}
void validate_network(Json::Value& value) {
    if (!value.isObject()) invalid("network config must be an object");
    if (schema(value) != 2) invalid("Unsupported network config schema (expected 2)");
    if (trim(string(value, "name")).empty()) invalid("Network name must not be empty");
    const auto& raw_bridge = member(value, "bridge_name");
    auto name = string(value, "bridge_name");
    if (!std::regex_match(name, std::regex("[a-zA-Z][a-zA-Z0-9_-]*")))
        invalid("Invalid bridge name: " + (raw_bridge.isString() ? name : "null"));
    if (name.size() > 12) invalid("Bridge name longer than 12 characters");
    bool gvisor = bridge(value) == "gvisor";
    if (mode(value) == "l2") {
        if (gvisor) invalid("L2 bridging requires a Linux bridge");
        if (trim(string(section(value, "l2"), "uplink")).empty()) invalid("L2 bridging requires an uplink interface");
        return;
    }
    auto& l3 = section(value, "l3");
    auto mac = string(l3, "mac_address");
    if (!mac.empty() && !std::regex_match(mac, std::regex("([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"))) invalid("Invalid MAC address: " + mac);
    if (!l3.isMember("vlans")) return;
    auto& vlans = l3["vlans"];
    std::set<int> seen;
    if (vlans.isArray()) for (auto& vlan : vlans) if (vlan.isObject()) {
        int id = narrow(integer(vlan, "vlan_id"));
        if (id < 0 || id > 4094) invalid("Invalid VLAN id: " + std::to_string(id));
        if (!seen.insert(id).second) invalid("Duplicate VLAN id: " + std::to_string(id));
        validate_vlan(vlan, gvisor);
    }
}
Json::Value network_view(Json::Value& value) {
    Json::Value view(Json::objectValue);
    view["id"] = uuid(value);
    view["name"] = member(value, "name").isString() ? member(value, "name") : Json::Value();
    view["bridge_type"] = bridge(value);
    view["uplink_mode"] = mode(value);
    view["stp"] = boolean(value, "stp");
    view["auto_up"] = boolean(value, "auto_up");
    view["bridge_mac"] = mode(value) == "l3" ? nullable(string(section(value, "l3"), "mac_address")) : Json::Value();
    return view;
}
NetworkPrefix NetworkPrefix::parse(const std::string& cidr, bool ipv6) {
    NetworkPrefix result;
    result.ipv6_ = ipv6;
    if (ipv6) {
        const auto parsed = network6(cidr);
        std::copy(std::begin(parsed.address.s6_addr), std::end(parsed.address.s6_addr), result.bytes_.begin());
        result.prefix_ = parsed.prefix;
    } else {
        const auto parsed = network4(cidr);
        for (int i = 0; i < 4; ++i) result.bytes_[i] = (parsed.address >> (24 - i * 8)) & 255;
        result.prefix_ = parsed.prefix;
    }
    return result;
}
std::array<uint8_t, 16> NetworkPrefix::base() const {
    auto bytes = bytes_;
    const int size = ipv6_ ? 16 : 4;
    for (int i = 0; i < size; ++i) {
        const int bits = std::clamp(prefix_ - i * 8, 0, 8);
        bytes[i] &= static_cast<uint8_t>(0xffu << (8 - bits));
    }
    return bytes;
}
std::string NetworkPrefix::format(const std::array<uint8_t, 16>& bytes) const {
    char text[INET6_ADDRSTRLEN];
    if (!inet_ntop(ipv6_ ? AF_INET6 : AF_INET, bytes.data(), text, sizeof(text))) invalid("IP formatting failed");
    return text;
}
std::string NetworkPrefix::address() const { return format(bytes_); }
std::string NetworkPrefix::network() const { return format(base()) + "/" + std::to_string(prefix_); }
std::string NetworkPrefix::address_at(int64_t offset) const {
    const auto host_bits = (ipv6_ ? 128 : 32) - prefix_;
    const auto value = static_cast<uint64_t>(offset);
    if (offset <= 0 || (host_bits < 64 && value >= (uint64_t(1) << host_bits) - unsigned(!ipv6_))) {
        std::string error = "Offset " + std::to_string(offset) + " out of range for /" + std::to_string(prefix_) + " network";
        if (!ipv6_) error += " (1.." + std::to_string((int64_t(1) << host_bits) - 2) + ")";
        invalid(error);
    }
    auto bytes = base();
    uint64_t carry = value;
    for (int i = (ipv6_ ? 16 : 4) - 1; i >= 0; --i) {
        const auto part = unsigned(bytes[i]) + unsigned(carry & 255);
        bytes[i] = part & 255;
        carry = (carry >> 8) + (part >> 8);
    }
    return format(bytes);
}
}
