// SPDX-License-Identifier: GPL-3.0-or-later
#include "host_discovery.h"
#include "netbox.h"
#include "store/network_config.h"
#include "services/context.h"
#include <charconv>
#include <dirent.h>
#include <fcntl.h>
#include <memory>
#include <set>
#include <sys/stat.h>

namespace droidvm::network {
namespace {
[[noreturn]] void io(const char* detail) { throw ServiceError(ErrorCode::io_error, detail); }
bool absent() { return errno == ENOENT || errno == ENODEV; }
std::optional<std::string> read_at(int directory, const char* name) {
    Fd file(openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
    if (file.get() < 0 && absent()) return {};
    if (file.get() < 0) io("Cannot read host interface properties");
    std::string result;
    char buffer[512];
    for (;;) {
        const auto count = read(file.get(), buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && absent()) return {};
        if (count < 0) io("Cannot read host interface properties");
        if (!count) break;
        result.append(buffer, static_cast<size_t>(count));
        if (result.size() > 4096) throw ServiceError(ErrorCode::resource_exhausted, "Host interface property exceeds budget");
    }
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) result.pop_back();
    return result;
}
bool exists_at(int directory, const char* name) {
    struct stat info{};
    if (fstatat(directory, name, &info, 0) == 0) return true;
    if (absent()) return false;
    io("Cannot inspect host interface properties");
}
uint32_t number(const std::optional<std::string>& text) {
    if (!text) return 0;
    uint32_t value = 0;
    const auto parsed = std::from_chars(text->data(), text->data() + text->size(), value);
    return parsed.ec == std::errc{} && parsed.ptr == text->data() + text->size() ? value : 0;
}
bool tether(const std::string& name) {
    for (const auto* prefix : {"ap", "swlan", "softap", "rndis", "usb", "bt-pan"}) if (name.starts_with(prefix)) return true;
    return false;
}
bool candidate(const HostInterface& iface) { return iface.name != "lo" && !iface.bridge && !iface.tun; }
}
const std::vector<std::string>& host_interface_prefixes() {
    static const std::vector<std::string> names{"wlan", "rmnet_data", "tun", "eth", "ap", "swlan", "softap", "rndis", "usb", "bt-pan"};
    return names;
}
Json::Value host_addresses(const Json::Value& links, const Json::Value& addresses) {
    if (!links.isArray() || !addresses.isArray()) io("Invalid host address snapshot");
    std::set<std::string> bridges;
    for (const auto& row : links) if (config::string(row, "kind") == "bridge") bridges.insert(config::string(row, "ifname"));
    Json::Value result(Json::arrayValue);
    for (const auto& row : addresses) {
        const auto address = config::string(row, "local"), name = config::string(row, "ifname");
        if (address.empty() || name.empty() || config::string(row, "scope") != "global" || bridges.contains(name)) continue;
        bool host = false;
        for (const auto& prefix : host_interface_prefixes()) if (name.starts_with(prefix)) { host = true; break; }
        if (!host || config::integer(row, "metric") == pbridge_offload_metric || config::boolean(row, "temporary")) continue;
        const auto family = config::integer(row, "family"), prefix = config::integer(row, "prefixlen");
        if (family != 4 && family != 6) continue;
        if (config::boolean(row, "noprefixroute") && prefix == (family == 4 ? 32 : 128)) continue;
        Json::Value entry; entry["addr"] = address; entry["ifname"] = name; entry["family"] = Json::Int64(family);
        result.append(std::move(entry));
    }
    return result;
}
UplinkSnapshot UplinkSnapshot::scan(const std::string& root) {
    if (root.empty() || root.front() != '/' || root.find('\0') != std::string::npos)
        throw ServiceError(ErrorCode::invalid_argument, "Invalid host interface directory");
    DIR* raw = opendir(root.c_str());
    if (!raw) io("Cannot enumerate host interfaces");
    std::unique_ptr<DIR, int(*)(DIR*)> directory(raw, closedir);
    UplinkSnapshot result;
    for (;;) {
        errno = 0;
        const auto* entry = readdir(directory.get());
        if (!entry) { if (errno) io("Cannot enumerate host interfaces"); break; }
        const std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        if (result.interfaces_.size() >= 4096) throw ServiceError(ErrorCode::resource_exhausted, "Host interface count exceeds budget");
        // /sys/class/net contains kernel symlinks. Hold the resolved directory
        // for this interface's reads; tolerate a device disappearing mid-scan.
        Fd device(openat(dirfd(directory.get()), name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        if (device.get() < 0 && absent()) continue;
        if (device.get() < 0) io("Cannot inspect host interface");
        const auto uevent = read_at(device.get(), "uevent");
        if (!uevent) continue;
        HostInterface row; row.name = name;
        row.index = number(read_at(device.get(), "ifindex"));
        const auto parent = number(read_at(device.get(), "iflink"));
        row.leaf = row.index && parent && row.index == parent;
        row.ethernet = number(read_at(device.get(), "type")) == 1;
        row.up = read_at(device.get(), "operstate") == std::optional<std::string>("up");
        row.wireless = exists_at(device.get(), "phy80211") || exists_at(device.get(), "wireless");
        row.physical = exists_at(device.get(), "device");
        row.bridge = exists_at(device.get(), "bridge"); row.tun = exists_at(device.get(), "tun_flags");
        const auto lines = "\n" + *uevent + "\n";
        row.cellular = lines.find("\nDEVTYPE=wwan\n") != std::string::npos;
        for (const auto* type : {"vlan", "vxlan", "gretap", "erspan"})
            if (lines.find(std::string("\nDEVTYPE=") + type + "\n") != std::string::npos) row.virtual_device = true;
        result.interfaces_.push_back(std::move(row));
    }
    return result;
}
std::optional<std::string> UplinkSnapshot::resolve(const std::string& configured) const {
    auto id = configured;
    for (auto& ch : id) if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
    const bool logical = id == "wifi" || id == "ethernet" || id == "tethering";
    if (!logical) {
        Netbox::interface_name(configured);
        for (const auto& row : interfaces_) if (row.name == configured) return configured;
        return {};
    }
    std::optional<std::string> fallback;
    for (const auto& row : interfaces_) {
        if (!candidate(row)) continue;
        const bool matches = id == "wifi" ? row.wireless && row.leaf && !row.virtual_device && !tether(row.name) :
            id == "ethernet" ? row.real_l2() && !row.wireless && !tether(row.name) : tether(row.name);
        if (!matches) continue;
        if (row.up) return row.name;
        if (!fallback) fallback = row.name;
    }
    return fallback;
}
bool UplinkSnapshot::assume_dont_bridge(const std::string& name) const {
    Netbox::interface_name(name);
    for (const auto& row : interfaces_) if (row.name == name) return row.wireless || !row.ethernet;
    throw ServiceError(ErrorCode::not_found, "Uplink interface disappeared");
}
Json::Value UplinkSnapshot::picker() const {
    Json::Value result;
    result["identifiers"] = Json::Value(Json::arrayValue); result["devices"] = Json::Value(Json::arrayValue);
    for (const auto* id : {"WiFi", "Ethernet", "Tethering"}) {
        Json::Value row; row["id"] = id; row["name"] = resolve(id).value_or(""); row["bridgeable"] = std::string_view(id) != "WiFi";
        result["identifiers"].append(std::move(row));
    }
    for (const auto& iface : interfaces_) if (candidate(iface) && iface.real_l2() && iface.up) {
        Json::Value row; row["name"] = iface.name; row["bridgeable"] = !iface.wireless;
        result["devices"].append(std::move(row));
    }
    return result;
}
}
