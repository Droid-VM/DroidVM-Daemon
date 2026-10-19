// SPDX-License-Identifier: GPL-3.0-or-later
#include "resource_catalog.h"
#include <chrono>
#include <map>
#include "services/context.h"
#include "common/wire.h"
#include "vm/vulkan_blit_probe.h"
#include <algorithm>

namespace droidvm::web {
Json::Value host_device_catalog(const vm::HostDeviceFacts& facts, const Json::Value& system_blit) {
    Json::Value result;
    const auto flag = [](std::optional<bool> value) { return value ? Json::Value(*value) : Json::Value(); };
    result["devices"]["kvm"] = flag(facts.kvm);
    result["devices"]["gunyah"] = flag(facts.gunyah);
    result["devices"]["geniezone"] = flag(facts.geniezone);
    result["devices"]["kgsl"] = flag(facts.kgsl);
    result["devices"]["turnip"] = flag(facts.turnip);
    result["devices"]["systemVulkan"] = flag(facts.system_vulkan);
    if (!system_blit.isObject() || !system_blit["state"].isString())
        throw ServiceError(ErrorCode::unavailable, "Invalid host graphics observation");
    const auto state = system_blit["state"].asString();
    const auto& missing = system_blit["missingExtensions"];
    const auto& checked = system_blit["checkedAtMs"];
    if ((state != "known" && state != "unknown" && state != "pending") ||
        (state == "known" ? !missing.isArray() : !missing.isNull()) ||
        (!checked.isNull() && (!checked.isInt64() || checked.asInt64() < 0 || checked.asInt64() > 9007199254740991LL)) ||
        (state == "known" && checked.isNull()))
        throw ServiceError(ErrorCode::unavailable, "Invalid host graphics state");
    if (missing.isArray()) {
        if (missing.size() > vm::blit_extensions.size()) throw ServiceError(ErrorCode::unavailable, "Invalid graphics extensions");
        std::set<std::string> seen;
        for (const auto& value : missing) {
            if (!value.isString()) throw ServiceError(ErrorCode::unavailable, "Invalid graphics extension");
            const auto name = value.asString();
            if (std::find(vm::blit_extensions.begin(), vm::blit_extensions.end(), name) == vm::blit_extensions.end() || !seen.insert(name).second)
                throw ServiceError(ErrorCode::unavailable, "Invalid graphics extension");
        }
    }
    result["systemBlit"]["state"] = state;
    result["systemBlit"]["missingExtensions"] = missing;
    result["systemBlit"]["checkedAtMs"] = checked;
    return result;
}
Json::Value cpu_catalog(const std::vector<vm::HostCpuCore>& cores) {
    if (cores.empty()) throw ServiceError(ErrorCode::unavailable, "Host CPU view unavailable");
    if (cores.size() > 4096) throw ServiceError(ErrorCode::resource_exhausted, "Host CPU view too large");
    Json::Value result; result["items"] = Json::Value(Json::arrayValue);
    const auto positive = [](int64_t value) {
        return value > 0 && value <= 9007199254740991LL ? Json::Value(Json::Int64(value)) : Json::Value();
    };
    std::set<int> seen;
    for (const auto& core : cores) {
        if (core.index < 0 || !seen.insert(core.index).second)
            throw ServiceError(ErrorCode::unavailable, "Invalid host CPU identity");
        Json::Value item;
        item["id"] = core.index;
        item["maxFrequencyKHz"] = positive(core.max_frequency_khz);
        item["capacity"] = positive(core.capacity);
        item["capacityEstimated"] = core.capacity_estimated && !item["capacity"].isNull();
        item["online"] = core.online ? Json::Value(*core.online) : Json::Value();
        result["items"].append(std::move(item));
    }
    return result;
}
namespace {
std::string text(const Json::Value& row, const char* key, size_t maximum = 4096) {
    if (!row.isObject() || !row[key].isString()) return {};
    auto value = row[key].asString();
    if (value.size() > maximum) throw ServiceError(ErrorCode::resource_exhausted, "Resource field too large");
    return value;
}
void check_rows(const Json::Value& rows) {
    if (!rows.isArray()) throw ServiceError(ErrorCode::unavailable, "Resource view unavailable");
    if (rows.size() > 4096) throw ServiceError(ErrorCode::resource_exhausted, "Resource view too large");
}
void bound(const Json::Value& result) {
    try { (void)wire::stringify_bounded(result, 2u << 20); }
    catch (const std::length_error&) { throw ServiceError(ErrorCode::resource_exhausted, "Resource view too large"); }
}
void append(Json::Value& items, Json::Value row, size_t& bytes) {
    try {
        const auto encoded = wire::stringify_bounded(row, (2u << 20) - bytes);
        bytes += encoded.size() + 1;
        if (bytes > (2u << 20)) throw std::length_error("Resource view too large");
    } catch (const std::length_error&) { throw ServiceError(ErrorCode::resource_exhausted, "Resource view too large"); }
    items.append(std::move(row));
}
const Json::Value& member(const Json::Value& row, const char* key) {
    static const Json::Value absent;
    return row.isObject() ? row[key] : absent;
}
bool flag(const Json::Value& row, const char* key) {
    const auto& value = member(row, key);
    return value.isBool() && value.asBool();
}
int64_t integer(const Json::Value& row, const char* key, int64_t fallback) {
    const auto& value = member(row, key);
    return (value.type() == Json::intValue || value.type() == Json::uintValue) && value.isInt64() ? value.asInt64() : fallback;
}
Json::Value address_family(const Json::Value& row, bool ipv6, bool gvisor) {
    Json::Value result;
    const auto cidr = text(row, "cidr");
    const bool delegated = ipv6 && text(row, "source", 128) == "dhcp_pd";
    const auto& dhcp = member(row, "dhcp");
    result["cidr"] = cidr.empty() ? Json::Value() : Json::Value(cidr);
    result["source"] = delegated ? "dhcp_pd" : "static";
    // Match VMNicConfig/sanitized_nic: a configured DHCP switch alone does not
    // provide a lease without an address family. IPv6 SNAT is gVisor-only.
    result["dhcpEnabled"] = (!cidr.empty() || delegated) && flag(dhcp, "enabled");
    result["snatEnabled"] = (!ipv6 || gvisor) && flag(row, "snat");
    // The same strict integer defaults as the native DHCP pool accessors.
    // Strings preserve int64 offsets in browsers, including IPv6 values >2^53.
    result["poolStart"] = std::to_string(integer(dhcp, "offset_start", 128));
    result["poolEnd"] = std::to_string(integer(dhcp, "offset_end", 192));
    return result;
}
}
Json::Value disk_catalog(const DiskConfigSnapshot& snapshot,
    const std::function<std::string(const Json::Value&)>& path,
    const std::set<std::string>& valid_paths, const std::set<std::string>& backing_paths) {
    const auto& rows = snapshot.document["disks"];
    check_rows(rows);
    Json::Value result;
    result["revision"] = snapshot.revision;
    result["items"] = Json::Value(Json::arrayValue);
    size_t bytes = 1024;
    for (const auto& row : rows) {
        if (!row.isObject()) throw ServiceError(ErrorCode::unavailable, "Invalid disk row");
        Json::Value item;
        item["id"] = text(row, "id", 128); item["name"] = text(row, "name");
        item["path"] = path(row);
        if (item["path"].asString().size() > 8192) throw ServiceError(ErrorCode::resource_exhausted, "Disk path too large");
        const auto parent = text(row, "parent", 128);
        item["parentId"] = parent.empty() ? Json::Value() : Json::Value(parent);
        item["backing"] = backing_paths.contains(item["path"].asString());
        // Snapshot readability is admitted by the native configuration gate.
        // Loaded snapshots may carry a historical durability flag; that is not
        // a ban on referencing their registered disks in a new VM edit.
        item["selectable"] = valid_paths.contains(item["path"].asString());
        append(result["items"], std::move(item), bytes);
    }
    bound(result); return result;
}
Json::Value disk_detail(const Json::Value& catalog, const VmConfigSnapshot& vms,
    const std::string& id, const std::string& state, const Json::Value& image,
    const std::optional<std::string>& effective_compression) {
    const auto& rows = catalog["items"];
    check_rows(rows); check_rows(vms.document["vms"]);
    std::map<std::string, const Json::Value*> by_id;
    for (const auto& row : rows) {
        if (!by_id.emplace(text(row, "id", 128), &row).second)
            throw ServiceError(ErrorCode::unavailable, "Duplicate disk identity");
    }
    const auto found = by_id.find(id);
    if (found == by_id.end()) throw ServiceError(ErrorCode::not_found, "Disk not registered");
    Json::Value result;
    result["revision"] = catalog["revision"]; result["vmRevision"] = vms.revision;
    result["disk"] = *found->second;
    result["chain"] = Json::Value(Json::arrayValue);
    result["children"] = Json::Value(Json::arrayValue);
    result["attachments"] = Json::Value(Json::arrayValue);
    result["chainComplete"] = false;
    size_t bytes = 16384;
    std::set<std::string> visited;
    auto cursor = found->second;
    while (cursor && visited.insert(text(*cursor, "id", 128)).second) {
        if (visited.size() > 64) throw ServiceError(ErrorCode::resource_exhausted, "Disk ancestry too deep");
        append(result["chain"], *cursor, bytes);
        const auto parent = text(*cursor, "parentId", 128);
        if (parent.empty()) { result["chainComplete"] = true; break; }
        const auto next = by_id.find(parent);
        cursor = next == by_id.end() ? nullptr : next->second;
    }
    std::map<std::string, std::string> affected_paths;
    for (const auto& row : rows) {
        if (text(row, "parentId", 128) == id) append(result["children"], row, bytes);
        std::set<std::string> chain;
        auto member_id = text(row, "id", 128);
        while (!member_id.empty() && chain.insert(member_id).second) {
            if (chain.size() > 64) throw ServiceError(ErrorCode::resource_exhausted, "Disk ancestry too deep");
            if (member_id == id) { affected_paths.emplace(text(row, "path", 8192), text(row, "id", 128)); break; }
            const auto next = by_id.find(member_id);
            if (next == by_id.end()) break;
            member_id = text(*next->second, "parentId", 128);
        }
    }
    size_t scanned = 0, direct = 0;
    for (const auto& vm : vms.document["vms"]) {
        const auto& slots = member(vm, "disks");
        if (!slots.isArray()) continue;
        for (Json::ArrayIndex index = 0; index < slots.size(); ++index) {
            if (++scanned > 65536) throw ServiceError(ErrorCode::resource_exhausted, "Too many disk attachments");
            const auto match = affected_paths.find(text(slots[index], "path", 8192));
            if (match == affected_paths.end()) continue;
            if (result["attachments"].size() >= 4096) throw ServiceError(ErrorCode::resource_exhausted, "Too many disk references");
            Json::Value attachment;
            attachment["vmId"] = text(vm, "id", 128); attachment["vmName"] = text(vm, "name");
            const bool directly_attached = text(slots[index], "path", 8192) == text(*found->second, "path", 8192);
            attachment["slot"] = index; attachment["diskId"] = directly_attached ? id : match->second;
            attachment["readOnly"] = flag(slots[index], "readonly");
            if (directly_attached) ++direct;
            append(result["attachments"], std::move(attachment), bytes);
        }
    }
    result["readOnlyRequired"] = flag(*found->second, "backing") || direct > 1;
    auto& inspection = result["inspection"];
    if (state != "ready" && state != "busy" && state != "unavailable" && state != "invalid-chain")
        throw ServiceError(ErrorCode::unavailable, "Invalid disk inspection state");
    inspection["state"] = state;
    inspection["effectiveCompression"] = Json::Value();
    for (const auto key : {"format", "virtualBytes", "allocatedBytes", "clusterBytes", "encrypted", "dirty", "compression"}) inspection[key] = Json::Value();
    const auto count = [&](const char* key) -> Json::Value {
        const auto& value = member(image, key);
        if ((value.type() == Json::uintValue || value.type() == Json::intValue) && value.isUInt64())
            return std::to_string(value.asUInt64());
        return {};
    };
    if (state == "ready") {
        const auto format = text(image, "format", 128);
        const auto size = count("virtual-size");
        if (format.empty() || size.isNull()) inspection["state"] = "unavailable";
        else {
            inspection["format"] = format; inspection["virtualBytes"] = size;
            inspection["allocatedBytes"] = count("actual-size"); inspection["clusterBytes"] = count("cluster-size");
            for (const auto& [source, target] : {std::pair{"encrypted", "encrypted"}, std::pair{"dirty-flag", "dirty"}}) {
                const auto& value = member(image, source);
                if (value.isBool()) inspection[target] = value;
            }
            const auto compression = text(member(member(image, "format-specific"), "data"), "compression-type", 128);
            if (!compression.empty()) inspection["compression"] = compression;
            if (effective_compression && (*effective_compression == "none" ||
                *effective_compression == "deflate" || *effective_compression == "zstd"))
                inspection["effectiveCompression"] = *effective_compression;
        }
    }
    result["checkedAtMs"] = Json::Int64(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    bound(result); return result;
}
Json::Value network_catalog(const Json::Value& active) {
    check_rows(active);
    Json::Value result; result["items"] = Json::Value(Json::arrayValue);
    size_t bytes = 1024;
    for (const auto& row : active) {
        if (!row.isObject()) throw ServiceError(ErrorCode::unavailable, "Invalid network row");
        Json::Value item;
        item["id"] = text(row, "id", 128); item["name"] = text(row, "name");
        // The native network_view defaults, applied to the service's existing
        // migrated snapshot rather than separately rereading each network.
        const bool gvisor = text(row, "bridge_type", 128) == "gvisor";
        const bool l2 = text(row, "uplink_mode", 128) == "l2";
        item["bridgeType"] = gvisor ? "gvisor" : "linux";
        item["uplinkMode"] = l2 ? "l2" : "l3";
        item["vlans"] = Json::Value(Json::arrayValue);
        const auto& vlans = member(member(row, "l3"), "vlans");
        if (!vlans.isNull()) {
            check_rows(vlans);
            size_t vlan_bytes = 1024;
            for (const auto& vlan : vlans) {
                if (!vlan.isObject()) throw ServiceError(ErrorCode::unavailable, "Invalid VLAN row");
                const auto id = integer(vlan, "vlan_id", 0);
                if (id < 0 || id > 4094) throw ServiceError(ErrorCode::unavailable, "Invalid VLAN identifier");
                Json::Value entry;
                entry["id"] = Json::Int64(id);
                entry["ipv4"] = address_family(member(vlan, "ipv4"), false, gvisor);
                entry["ipv6"] = address_family(member(vlan, "ipv6"), true, gvisor);
                append(item["vlans"], std::move(entry), vlan_bytes);
            }
        }
        append(result["items"], std::move(item), bytes);
    }
    bound(result); return result;
}
Json::Value usb_catalog(const Json::Value& snapshot) {
    Json::Value result;
    result["available"] = flag(snapshot, "available");
    result["items"] = Json::Value(Json::arrayValue);
    result["targets"] = Json::Value(Json::arrayValue);
    if (!result["available"].asBool()) return result;
    const auto& devices = member(snapshot, "devices");
    check_rows(devices);
    std::set<std::string> seen;
    size_t bytes = 1024;
    for (const auto& device : devices) {
        const auto sysfs = text(device, "sysfs", 256);
        const auto number = integer(device, "devnum", 0), bus = integer(device, "busnum", 0);
        if (sysfs.empty() || number < 1 || number > 65535 || bus < 1 || bus > 65535)
            throw ServiceError(ErrorCode::unavailable, "Invalid USB identity");
        const auto id = sysfs + "#" + std::to_string(number);
        if (!seen.insert(id).second) throw ServiceError(ErrorCode::unavailable, "Duplicate USB identity");
        Json::Value item;
        item["id"] = id; item["sysfs"] = sysfs;
        item["busNumber"] = Json::Int64(bus); item["deviceNumber"] = Json::Int64(number);
        item["vendorId"] = text(device, "vid", 16); item["productId"] = text(device, "pid", 16);
        item["manufacturer"] = text(device, "manufacturer"); item["product"] = text(device, "product");
        item["serial"] = text(device, "serial"); item["speed"] = text(device, "speed", 128);
        const auto state = text(device, "state", 128);
        item["state"] = state == "hostuse" ? "host" : state == "vmuse" ? "claimed" : state == "idle" ? "idle" : "unknown";
        item["locked"] = flag(device, "lock");
        const auto vm = text(device, "attached_vm", 128);
        item["owner"] = Json::Value();
        if (!vm.empty()) {
            Json::Value owner;
            owner["vmId"] = vm; owner["vmName"] = text(device, "attached_vm_name");
            const auto controller = text(device, "attached_controller", 128);
            owner["controllerId"] = controller.empty() ? Json::Value() : Json::Value(controller);
            const auto port = integer(device, "attached_port", 0);
            owner["port"] = port > 0 && port <= 65535 ? Json::Value(Json::Int64(port)) : Json::Value();
            item["owner"] = std::move(owner);
        }
        append(result["items"], std::move(item), bytes);
    }
    const auto& targets = member(snapshot, "targets");
    if (!targets.isNull()) {
        check_rows(targets);
        for (const auto& target : targets) {
            Json::Value row;
            row["vmId"] = text(target, "vmId", 128); row["vmName"] = text(target, "vmName");
            row["instanceId"] = text(target, "instanceId", 32); row["revision"] = text(target, "revision", 20);
            row["controllerId"] = text(target, "controllerId", 128);
            append(result["targets"], std::move(row), bytes);
        }
    }
    bound(result); return result;
}
Json::Value audio_catalog(const Json::Value& snapshot) {
    Json::Value result;
    result["available"] = flag(snapshot, "available");
    result["items"] = Json::Value(Json::arrayValue);
    if (!result["available"].asBool()) return result;
    const auto& devices = member(snapshot, "devices");
    check_rows(devices);
    if (devices.size() > 1024) throw ServiceError(ErrorCode::resource_exhausted, "Audio catalogue too large");
    std::set<std::string> seen;
    size_t bytes = 1024;
    for (const auto& device : devices) {
        if (!device.isObject()) throw ServiceError(ErrorCode::unavailable, "Invalid audio device");
        if (!flag(device, "selectable")) continue;
        const auto key = text(device, "key");
        if (key.empty() || key.find_first_of("\t\r\n") != std::string::npos || key.find('\0') != std::string::npos)
            throw ServiceError(ErrorCode::unavailable, "Invalid audio device key");
        const bool input = flag(device, "input");
        const auto id = std::string(input ? "in:" : "out:") + key;
        if (!seen.insert(id).second) continue; // Same first stable key as AudioTable.
        const auto kind = integer(device, "kind", 0);
        Json::Value item;
        item["id"] = id; item["key"] = key; item["name"] = text(device, "name");
        item["input"] = input; item["kind"] = Json::Int64(kind >= 0 && kind <= 7 ? kind : 0);
        append(result["items"], std::move(item), bytes);
    }
    bound(result); return result;
}
}
