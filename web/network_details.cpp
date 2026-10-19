// SPDX-License-Identifier: GPL-3.0-or-later
#include "network_details.h"
#include "resource_catalog.h"
#include "common/wire.h"
#include "services/context.h"
#include <chrono>
#include <set>

namespace droidvm::web {
namespace {
constexpr size_t maximum_bytes = 2u << 20;
constexpr Json::ArrayIndex maximum_rows = 4096;
[[noreturn]] void invalid() {
    throw ServiceError(ErrorCode::unavailable, "Invalid network observation");
}
[[noreturn]] void too_large() {
    throw ServiceError(ErrorCode::resource_exhausted, "Network observation too large");
}
const Json::Value& member(const Json::Value& value, const char* key) {
    static const Json::Value absent;
    return value.isObject() ? value[key] : absent;
}
std::string text(const Json::Value& row, const char* key, size_t maximum = 4096) {
    const auto& value = member(row, key);
    if (value.isNull()) return {};
    if (!value.isString()) invalid();
    auto result = value.asString();
    if (result.size() > maximum) too_large();
    return result;
}
Json::Value optional_text(const Json::Value& row, const char* key, size_t maximum = 4096) {
    const auto result = text(row, key, maximum);
    return result.empty() ? Json::Value() : Json::Value(result);
}
bool flag(const Json::Value& row, const char* key) {
    const auto& value = member(row, key);
    if (value.isNull()) return false;
    if (!value.isBool()) invalid();
    return value.asBool();
}
Json::Value vlan(const Json::Value& row, const char* key, bool trunk = false) {
    const auto& value = member(row, key);
    if (value.isNull()) return {};
    if ((value.type() != Json::intValue && value.type() != Json::uintValue) ||
        !value.isInt64() || value.asInt64() < 0 || value.asInt64() > (trunk ? 4095 : 4094)) invalid();
    return value;
}
const Json::Value& rows(const Json::Value& value) {
    if (!value.isArray()) invalid();
    if (value.size() > maximum_rows) too_large();
    return value;
}
void append(Json::Value& target, Json::Value row, size_t& bytes) {
    if (target.size() >= maximum_rows) too_large();
    try {
        bytes += wire::stringify_bounded(row, maximum_bytes - bytes).size() + 1;
        if (bytes > maximum_bytes) too_large();
    } catch (const std::length_error&) { too_large(); }
    target.append(std::move(row));
}
void object(const Json::Value& value) { if (!value.isObject()) invalid(); }
void observation(const NetworkObservation& value, const std::string& id) {
    if (value.id != id || (value.state != "STOPPED" && value.state != "STARTING" &&
        value.state != "RUNNING" && value.state != "RECOVERING" && value.state != "STOPPING" &&
        value.state != "FAILED")) invalid();
}
}

Json::Value network_detail(const Json::Value& config, const VmConfigSnapshot& vms,
    const NetworkObservation& before, const NetworkObservation& after, const Json::Value& live,
    const std::string& configuration_revision) {
    object(config);
    const auto id = text(config, "id", 128);
    if (id.empty()) invalid();
    observation(before, id); observation(after, id);
    Json::Value source(Json::arrayValue); source.append(config);
    Json::Value result;
    result["network"] = network_catalog(source)["items"][0];
    result["network"]["bridgeName"] = text(config, "bridge_name", 128);
    result["network"]["autoUp"] = flag(config, "auto_up");
    result["network"]["stp"] = flag(config, "stp");
    result["runtime"]["state"] = after.state;
    result["runtime"]["generation"] = std::to_string(after.generation);
    result["runtime"]["desiredRunning"] = after.desired_running;
    if (configuration_revision.empty() || configuration_revision.size() > 128) invalid();
    result["configurationRevision"] = configuration_revision;
    result["vmRevision"] = vms.revision;
    if (vms.revision.empty() || vms.revision.size() > 128) invalid();
    result["attachments"] = Json::Value(Json::arrayValue);
    size_t bytes = 16384, scanned = 0;
    std::set<std::string> vm_ids;
    for (const auto& vm : rows(member(vms.document, "vms"))) {
        object(vm);
        const auto vm_id = text(vm, "id", 128);
        if (vm_id.empty() || !vm_ids.insert(vm_id).second) invalid();
        const auto& nics = member(vm, "networks");
        if (nics.isNull()) continue;
        for (Json::ArrayIndex index = 0; index < rows(nics).size(); ++index) {
            if (++scanned > 65536) too_large();
            const auto& nic = nics[index]; object(nic);
            if (text(nic, "network_id", 128) != id) continue;
            Json::Value item;
            item["vmId"] = vm_id; item["vmName"] = text(vm, "name");
            item["slot"] = index; item["mac"] = text(nic, "mac_address", 128);
            item["vlan"] = vlan(nic, "vlan_id", true);
            append(result["attachments"], std::move(item), bytes);
        }
    }
    const bool changed = before.generation != after.generation || before.state != after.state ||
        before.desired_running != after.desired_running;
    const bool inactive = after.state != "RUNNING";
    const bool unavailable = !live.isObject();
    const bool busy = !unavailable && live.empty();
    const bool observed = !changed && !inactive && !unavailable && !busy;
    result["liveState"] = changed ? "changed" : inactive ? "inactive" : unavailable ? "unavailable" : busy ? "busy" : "observed";
    // Both native implementations intentionally swallow individual read errors.
    // Their lists are useful observations, but empty rows do not prove absence.
    result["observationComplete"] = false;
    for (const char* key : {"addresses", "interfaces", "pd", "neighbors", "leases"})
        result[key] = observed ? Json::Value(Json::arrayValue) : Json::Value();
    if (observed) {
        for (const auto& row : rows(member(live, "address_entries"))) {
            object(row); Json::Value item;
            item["address"] = text(row, "addr", 256);
            const auto& family = member(row, "family");
            if (!family.isInt() || (family.asInt() != 4 && family.asInt() != 6)) invalid();
            item["family"] = family; item["vlan"] = vlan(row, "vlan");
            item["bound"] = flag(row, "bound");
            const auto origin = text(row, "source", 128);
            item["source"] = origin == "configured" || origin == "auto" || origin == "pbridge_guest" ? origin : "unknown";
            append(result["addresses"], std::move(item), bytes);
        }
        for (const auto& row : rows(member(live, "live_interfaces"))) {
            object(row); Json::Value item;
            item["name"] = text(row, "name", 128); item["address"] = optional_text(row, "address", 128);
            item["state"] = text(row, "state", 128); item["vlan"] = vlan(row, "vlan", true);
            append(result["interfaces"], std::move(item), bytes);
        }
        for (const auto& row : rows(member(live, "pd"))) {
            object(row); Json::Value item;
            item["vlan"] = vlan(row, "vlan"); item["state"] = text(row, "state", 128);
            item["prefix"] = optional_text(row, "prefix", 256); item["address"] = optional_text(row, "address", 256);
            append(result["pd"], std::move(item), bytes);
        }
        for (const auto& row : rows(member(live, "neighbors"))) {
            object(row); Json::Value item;
            item["address"] = text(row, "dst", 256); item["mac"] = text(row, "lladdr", 128);
            item["interface"] = text(row, "dev", 128); item["states"] = Json::Value(Json::arrayValue);
            const auto& states = member(row, "state");
            if (states.isString()) {
                const auto state = text(row, "state", 128);
                if (!state.empty()) item["states"].append(state);
            } else if (!states.isNull()) {
                if (rows(states).size() > 16) too_large();
                for (const auto& state : states) {
                    if (!state.isString()) invalid();
                    if (state.asString().size() > 128) too_large();
                    item["states"].append(state);
                }
            }
            append(result["neighbors"], std::move(item), bytes);
        }
        for (const auto& row : rows(member(live, "dhcp_leases"))) {
            object(row); Json::Value item;
            item["address"] = text(row, "ip", 256); item["mac"] = text(row, "mac", 128);
            item["hostname"] = text(row, "hostname"); item["vlan"] = vlan(row, "vlan");
            item["expires"] = Json::Value(); item["expiresFormat"] = "unknown";
            const auto& expiry = member(row, "expires");
            if ((expiry.type() == Json::intValue || expiry.type() == Json::uintValue) && expiry.isInt64()) {
                if (expiry.asInt64() > 0) {
                    item["expires"] = std::to_string(expiry.asInt64()); item["expiresFormat"] = "unix-seconds";
                }
            } else if (expiry.isString()) {
                item["expires"] = optional_text(row, "expires", 128);
                if (!item["expires"].isNull()) item["expiresFormat"] = "rfc3339";
            } else if (!expiry.isNull()) invalid();
            append(result["leases"], std::move(item), bytes);
        }
    }
    result["checkedAtMs"] = Json::Int64(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    try { (void)wire::stringify_bounded(result, maximum_bytes); }
    catch (const std::length_error&) { too_large(); }
    return result;
}
}
