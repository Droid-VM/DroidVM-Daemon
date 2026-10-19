// SPDX-License-Identifier: GPL-3.0-or-later
#include "host_network.h"
#include "common/wire.h"
#include "services/context.h"
#include <set>
#include <tuple>

namespace droidvm::web {
namespace {
[[noreturn]] void invalid() { throw ServiceError(ErrorCode::unavailable, "Invalid host network observation"); }
void rows(const Json::Value& value, size_t maximum) {
    if (!value.isArray()) invalid();
    if (value.size() > maximum)
        throw ServiceError(ErrorCode::resource_exhausted, "Host network observation too large");
}
std::string text(const Json::Value& row, const char* key, size_t maximum, bool empty = false) {
    if (!row.isObject() || !row[key].isString()) invalid();
    const auto result = row[key].asString();
    if ((!empty && result.empty()) || result.find('\0') != std::string::npos) invalid();
    if (result.size() > maximum)
        throw ServiceError(ErrorCode::resource_exhausted, "Host network field too large");
    return result;
}
bool bridgeable(const Json::Value& row) {
    if (!row.isObject() || !row["bridgeable"].isBool()) invalid();
    return row["bridgeable"].asBool();
}
}
Json::Value host_network_catalog(const Json::Value& interfaces,
    const Json::Value& uplinks, const Json::Value& addresses) {
    rows(interfaces, 4096); rows(addresses, 16384);
    if (!uplinks.isObject()) invalid();
    rows(uplinks["identifiers"], 3); rows(uplinks["devices"], 4096);
    Json::Value result;
    result["interfaces"] = Json::Value(Json::arrayValue);
    result["addresses"] = Json::Value(Json::arrayValue);
    result["uplinks"]["identifiers"] = Json::Value(Json::arrayValue);
    result["uplinks"]["devices"] = Json::Value(Json::arrayValue);
    std::set<std::string> seen_interfaces, seen_identifiers, seen_devices;
    for (const auto& row : interfaces) {
        Json::Value item;
        const auto name = text(row, "name", 15);
        if (!seen_interfaces.insert(name).second) invalid();
        item["name"] = name;
        item["state"] = text(row, "state", 32);
        item["master"] = text(row, "master", 15, true);
        result["interfaces"].append(std::move(item));
    }
    for (const auto& row : uplinks["identifiers"]) {
        Json::Value item;
        const auto id = text(row, "id", 16);
        if ((id != "WiFi" && id != "Ethernet" && id != "Tethering") || !seen_identifiers.insert(id).second) invalid();
        item["id"] = id;
        item["name"] = text(row, "name", 15, true);
        item["bridgeable"] = bridgeable(row);
        result["uplinks"]["identifiers"].append(std::move(item));
    }
    for (const auto& row : uplinks["devices"]) {
        Json::Value item;
        const auto name = text(row, "name", 15);
        if (!seen_devices.insert(name).second) invalid();
        item["name"] = name;
        item["bridgeable"] = bridgeable(row);
        result["uplinks"]["devices"].append(std::move(item));
    }
    std::set<std::tuple<std::string, std::string, int>> seen_addresses;
    for (const auto& row : addresses) {
        const auto address = text(row, "addr", 64), name = text(row, "ifname", 15);
        if (!row["family"].isInt() || (row["family"].asInt() != 4 && row["family"].asInt() != 6)) invalid();
        const auto family = row["family"].asInt();
        // Kernel observations may repeat an address under distinct flags.
        if (!seen_addresses.emplace(name, address, family).second) continue;
        Json::Value item;
        item["address"] = address; item["interfaceName"] = name; item["family"] = family;
        result["addresses"].append(std::move(item));
    }
    try { (void)wire::stringify_bounded(result, 2u << 20); }
    catch (const std::length_error&) {
        throw ServiceError(ErrorCode::resource_exhausted, "Host network observation too large");
    }
    return result;
}
}
