// SPDX-License-Identifier: GPL-3.0-or-later
#include "listen_plan.h"
#include <algorithm>
#include <map>
#include <optional>
#include <stdexcept>
#include <tuple>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace droidvm::web {
namespace {
std::optional<PeerPrefix> ip(std::string_view value) {
    if (value.empty() || value.size() > 45 || value.find('\0') != std::string_view::npos) return {};
    const std::string text(value);
    PeerPrefix result;
    if (inet_pton(AF_INET, text.c_str(), result.bytes.data()) == 1) return result;
    if (inet_pton(AF_INET6, text.c_str(), result.bytes.data()) != 1) return {};
    // Kernel IPv4-mapped peers use exactly the IPv4 policy, including loopback.
    if (std::all_of(result.bytes.begin(), result.bytes.begin() + 10, [](auto v) { return v == 0; }) &&
        result.bytes[10] == 255 && result.bytes[11] == 255) {
        std::copy_n(result.bytes.begin() + 12, 4, result.bytes.begin());
        std::fill(result.bytes.begin() + 4, result.bytes.end(), static_cast<unsigned char>(0));
        return result;
    }
    result.family = 6; result.bits = 128; return result;
}
bool loopback(const PeerPrefix& value) {
    if (value.family == 4) return value.bytes[0] == 127;
    return value.bytes[15] == 1 && std::all_of(value.bytes.begin(), value.bytes.begin() + 15, [](auto v) { return !v; });
}
bool unicast(const PeerPrefix& value) {
    if (value.family == 4) return value.bytes[0] && value.bytes[0] < 224;
    return value.bytes[0] != 255 && std::any_of(value.bytes.begin(), value.bytes.end(), [](auto v) { return v != 0; });
}
bool matches(const PeerPrefix& prefix, const PeerPrefix& value) {
    if (prefix.family != value.family || prefix.bits > (prefix.family == 4 ? 32u : 128u)) return false;
    const unsigned whole = prefix.bits / 8, tail = prefix.bits % 8;
    if (!std::equal(prefix.bytes.begin(), prefix.bytes.begin() + whole, value.bytes.begin())) return false;
    const auto mask = static_cast<unsigned char>(0xffu << (8 - tail));
    return !tail || (prefix.bytes[whole] & mask) == (value.bytes[whole] & mask);
}
bool flag(const Json::Value& row, const char* name) {
    if (!row.isMember(name) || row[name].isNull()) return false;
    // Malformed optional flags deny eligibility instead of becoming false.
    return !row[name].isBool() || row[name].asBool();
}
std::string canonical(const PeerPrefix& value) {
    char text[INET6_ADDRSTRLEN]{};
    if (!inet_ntop(value.family == 4 ? AF_INET : AF_INET6, value.bytes.data(), text, sizeof(text)))
        throw std::runtime_error("Cannot format listener address");
    return text;
}
}
ListenScope listen_scope(std::string_view value) {
    if (value == "lan") return ListenScope::lan;
    if (value == "all") return ListenScope::all;
    throw std::invalid_argument("Unknown WebUI listen scope");
}
bool PeerPrefix::contains(std::string_view peer) const {
    const auto value = ip(peer); return value && unicast(*value) && matches(*this, *value);
}
bool ListenEndpoint::allows(std::string_view peer) const {
    const auto value = ip(peer);
    if (!value || !unicast(*value)) return false;
    if (unrestricted) return true;
    return std::any_of(sources.begin(), sources.end(), [&](const auto& prefix) { return matches(prefix, *value); });
}
bool direct_lan_peer(const ListenPlan& plan, std::string_view peer, std::string_view local) {
    const auto source = ip(peer), destination = ip(local);
    if (plan.scope != ListenScope::lan || !source || !destination || !unicast(*source) ||
            !unicast(*destination) || loopback(*source) || loopback(*destination)) return false;
    const auto address = canonical(*destination);
    return std::any_of(plan.endpoints.begin(), plan.endpoints.end(), [&](const auto& endpoint) {
        return !endpoint.unrestricted && !endpoint.interface_name.empty() && endpoint.address == address && endpoint.allows(peer);
    });
}
ListenPlan make_listen_plan(const network::HostNetworkSnapshot& snapshot, ListenScope scope, bool ipv6) {
    if (scope != ListenScope::lan && scope != ListenScope::all) throw std::invalid_argument("Unknown WebUI listen scope");
    ListenPlan plan; plan.scope = scope;
    plan.access_addresses.push_back("127.0.0.1");
    if (ipv6) plan.access_addresses.push_back("::1");
    if (scope == ListenScope::all) {
        if (!snapshot.addresses.isArray() || snapshot.addresses.size() > 8192)
            throw std::invalid_argument("Invalid host address snapshot");
        for (const auto& row : snapshot.addresses) {
            if (!row.isObject() || !row["local"].isString() || flag(row, "tentative") || flag(row, "dadfailed") ||
                flag(row, "temporary") || flag(row, "deprecated")) continue;
            const auto value = ip(row["local"].asString());
            if (!value || !unicast(*value) || loopback(*value) || (!ipv6 && value->family == 6)) continue;
            if (value->family == 6 && value->bytes[0] == 0xfe && (value->bytes[1] & 0xc0) == 0x80) continue;
            const auto address = canonical(*value);
            if (std::find(plan.access_addresses.begin(), plan.access_addresses.end(), address) == plan.access_addresses.end())
                plan.access_addresses.push_back(address);
            if (plan.access_addresses.size() > 56) throw std::invalid_argument("Too many host addresses");
        }
        std::sort(plan.access_addresses.begin(), plan.access_addresses.end());
        plan.endpoints.push_back({"0.0.0.0", {}, {}, true});
        if (ipv6) plan.endpoints.push_back({"::", {}, {}, true});
        return plan;
    }
    if (!snapshot.links.isArray() || !snapshot.addresses.isArray() || snapshot.interfaces.size() > 4096 ||
        snapshot.links.size() > 4096 || snapshot.addresses.size() > 8192)
        throw std::invalid_argument("Invalid host network snapshot");
    auto v4local = *ip("127.0.0.1"); v4local.bits = 8;
    const auto v6local = *ip("::1");
    std::vector<PeerPrefix> local{v4local}; if (ipv6) local.push_back(v6local);
    plan.endpoints.push_back({"127.0.0.1", {}, {v4local}, false});
    if (ipv6) plan.endpoints.push_back({"::1", {}, {v6local}, false});
    std::map<std::string, const network::HostInterface*> eligible;
    for (const auto& iface : snapshot.interfaces) {
        if (!iface.index || !iface.up || !iface.ethernet || !iface.leaf || iface.virtual_device || iface.bridge ||
            iface.tun || iface.cellular || (!iface.wireless && !iface.physical)) continue;
        // Require matching link metadata. A slave/bridge/tunnel must not be
        // accepted merely because it has a physical Ethernet-like address.
        const Json::Value* link = nullptr;
        for (const auto& row : snapshot.links) if (row.isObject() && row["ifname"] == iface.name) {
            if (link) throw std::invalid_argument("Duplicate host link");
            link = &row;
        }
        if (!link || !(*link)["kind"].isString() || !(*link)["master"].isString() || !(*link)["master"].asString().empty()) continue;
        const auto kind = (*link)["kind"].asString();
        if (!kind.empty() && kind != "ether" && kind != "wireless" && kind != "wlan") continue;
        if (!eligible.emplace(iface.name, &iface).second) throw std::invalid_argument("Duplicate host interface");
    }
    std::map<std::string, size_t> bound;
    for (const auto& row : snapshot.addresses) {
        if (!row.isObject() || !row["ifname"].isString() || !row["local"].isString() || row["scope"] != "global" ||
            !row["family"].isUInt() || !row["prefixlen"].isUInt()) continue;
        const auto iface = row["ifname"].asString();
        if (!eligible.contains(iface) || flag(row, "temporary") || flag(row, "tentative") || flag(row, "dadfailed") ||
            flag(row, "deprecated") || flag(row, "noprefixroute")) continue;
        if (row.isMember("metric") && !row["metric"].isNull() &&
            (!row["metric"].isUInt() || row["metric"].asUInt() == network::pbridge_offload_metric)) continue;
        auto address = ip(row["local"].asString());
        const unsigned family = row["family"].asUInt(), bits = row["prefixlen"].asUInt();
        if (!address || address->family != family || (!ipv6 && family == 6) || !unicast(*address) || loopback(*address) ||
            !bits || bits > (family == 4 ? 32u : 128u)) continue;
        // Scoped link-local URLs need an interface-zone aware transport. Until
        // that adapter exists only global/ULA IPv6 addresses are advertised.
        if (family == 6 && address->bytes[0] == 0xfe && (address->bytes[1] & 0xc0) == 0x80) continue;
        address->bits = bits;
        const auto key = canonical(*address);
        if (const auto found = bound.find(key); found != bound.end()) {
            auto& endpoint = plan.endpoints[found->second];
            if (endpoint.interface_name != iface) throw std::invalid_argument("Ambiguous LAN address");
            endpoint.sources.push_back(*address);
        } else {
            if (plan.endpoints.size() >= 64) throw std::invalid_argument("Too many LAN listeners");
            auto sources = local; sources.push_back(*address);
            bound.emplace(key, plan.endpoints.size());
            plan.endpoints.push_back({key, iface, std::move(sources), false});
        }
    }
    for (size_t i = ipv6 ? 2 : 1; i < plan.endpoints.size(); ++i) plan.access_addresses.push_back(plan.endpoints[i].address);
    for (auto& endpoint : plan.endpoints) {
        std::sort(endpoint.sources.begin(), endpoint.sources.end(), [](const auto& a, const auto& b) {
            return std::tie(a.family, a.bits, a.bytes) < std::tie(b.family, b.bits, b.bytes);
        });
        endpoint.sources.erase(std::unique(endpoint.sources.begin(), endpoint.sources.end()), endpoint.sources.end());
    }
    std::sort(plan.endpoints.begin(), plan.endpoints.end(), [](const auto& a, const auto& b) { return a.address < b.address; });
    std::sort(plan.access_addresses.begin(), plan.access_addresses.end());
    return plan;
}
}
