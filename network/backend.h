// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "store/network_config.h"
#include <json/json.h>
#include <cstdio>
#include <ctime>
#include <string>
#include <stdexcept>
#include <vector>

namespace droidvm::network {
// Called serially on a worker for one network. start/recover return only after
// the data path is ready; stop throws if any owned resource remains unresolved.
class Backend {
public:
    virtual ~Backend() = default;
    virtual void start(const Json::Value& config) = 0;
    virtual bool healthy() const = 0;
    // Bounded periodic I/O on the same worker/operation lease as start/stop.
    // Refresh live routing/PD state or verify the helper control plane here.
    // A throw retains the backend and its config lease for retry. Mark the
    // backend unhealthy only if recovery must rebuild it, rather than retrying
    // a transient reconciliation failure against the existing data path.
    virtual void refresh() {}
    virtual void recover(const Json::Value& config) = 0;
    virtual void stop() = 0;
    virtual Json::Value tools() const { return Json::Value(Json::arrayValue); }
    // VM NIC attachment of a sanitized, validated NIC config. A throw leaves
    // no TAP behind; per-forward failures are recorded, never thrown.
    virtual void attach(const Json::Value&, const std::string&) { throw std::runtime_error("VM attachment is not supported by this network"); }
    virtual void detach(const Json::Value&, const std::string&) {}
    virtual Json::Value forward_failures() const { return Json::Value(Json::objectValue); }
    virtual Json::Value tool_log(const std::string&) const { return {}; }
    // Actual helper leases, never configured reservations. Worker-only I/O;
    // null means unsupported/unavailable rather than an empty observed set.
    virtual Json::Value dhcp_leases() const { return {}; }
    // network_info of a running network: the InfoHandler live lists and the
    // backend's appendInfo fields. Read failures leave a list empty.
    virtual void live_details(Json::Value& data) const {
        for (const char* key : {"live_addresses", "pd", "live_interfaces", "neighbors", "dhcp_leases"}) data[key] = Json::Value(Json::arrayValue);
    }
    // BridgeBackend.renewPd/releasePd: false when unsupported or refused.
    virtual bool pd_action(int, bool) { return false; }
    // network_add/remove_address and _interface: Linux bridges only. A manual
    // port is an owned record released with the network, never a foreign one.
    virtual bool manual_address(const std::string&, bool) { return false; }
    virtual bool manual_port(const std::string&, bool) { return false; }
};
// NetworkConfig.getVlans: L3 networks only, object rows.
inline std::vector<const Json::Value*> l3_vlans(const Json::Value& network) {
    std::vector<const Json::Value*> result;
    if (config::string(network, "uplink_mode") == "l2") return result;
    const auto& rows = config::member(config::member(network, "l3"), "vlans");
    if (rows.isArray()) for (const auto& row : rows) if (row.isObject()) result.push_back(&row);
    return result;
}
// VlanConfig.getIpv6Source: anything but dhcp_pd is STATIC.
inline bool static_ipv6(const Json::Value& vlan) { return config::string(config::member(vlan, "ipv6"), "source") != "dhcp_pd"; }
// BridgeBackend.addressEntry.
inline Json::Value address_entry(const std::string& cidr, int vlan, bool bound, const char* source) {
    Json::Value row;
    row["addr"] = cidr;
    row["family"] = cidr.find(':') != std::string::npos ? 6 : 4;
    row["vlan"] = vlan;
    row["bound"] = bound;
    row["source"] = source;
    return row;
}
// OffsetDateTime.parse(...).toEpochSecond(), 0 when unparseable.
inline int64_t rfc3339_seconds(const std::string& text) {
    std::tm tm{};
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0, used = 0;
    if (std::sscanf(text.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d%n", &year, &month, &day, &hour, &minute, &second, &used) != 6 || used != 19) return 0;
    size_t at = 19;
    if (at < text.size() && text[at] == '.') { ++at; while (at < text.size() && text[at] >= '0' && text[at] <= '9') ++at; }
    int64_t offset = 0;
    if (at < text.size() && (text[at] == 'Z' || text[at] == 'z') && at + 1 == text.size()) offset = 0;
    else if (at + 6 == text.size() && (text[at] == '+' || text[at] == '-') && text[at + 3] == ':') {
        int oh = 0, om = 0;
        if (std::sscanf(text.c_str() + at + 1, "%2d:%2d", &oh, &om) != 2 || oh > 18 || om > 59) return 0;
        offset = (text[at] == '-' ? -1 : 1) * (oh * 3600 + om * 60);
    } else return 0;
    if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) return 0;
    tm.tm_year = year - 1900; tm.tm_mon = month - 1; tm.tm_mday = day; tm.tm_hour = hour; tm.tm_min = minute; tm.tm_sec = second;
    return static_cast<int64_t>(timegm(&tm)) - offset;
}
}
