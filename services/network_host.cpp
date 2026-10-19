// SPDX-License-Identifier: GPL-3.0-or-later
#include "network_host.h"
#include <algorithm>

namespace droidvm {
namespace {
void access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || caller.principal.empty())
        throw ServiceError(ErrorCode::permission_denied, "Administrator permission required");
}
}
Json::Value NetworkHostService::uplinks(const CallContext& caller) const {
    access(caller); return network::UplinkSnapshot::scan().picker();
}
Json::Value NetworkHostService::addresses(const CallContext& caller) const {
    access(caller);
    const auto links = netbox_.links();
    return network::host_addresses(links, netbox_.addresses());
}
network::HostNetworkSnapshot NetworkHostService::snapshot(const CallContext& caller) const {
    access(caller);
    network::HostNetworkSnapshot result;
    result.interfaces = network::UplinkSnapshot::scan().interfaces();
    result.links = netbox_.links();
    result.addresses = netbox_.addresses();
    auto after = network::UplinkSnapshot::scan().interfaces();
    const auto by_name = [](const auto& left, const auto& right) { return left.name < right.name; };
    std::sort(result.interfaces.begin(), result.interfaces.end(), by_name);
    std::sort(after.begin(), after.end(), by_name);
    if (result.interfaces != after)
        throw ServiceError(ErrorCode::unavailable, "Host interfaces changed during discovery");
    return result;
}
Json::Value NetworkHostService::available_interfaces(const CallContext& caller) const {
    access(caller);
    Json::Value result(Json::arrayValue);
    // Preserve LinuxNetwork.listAvailableInterfaces' legacy fields/filtering.
    // A failed discovery is an error, not a successful empty interface list.
    for (const auto& link : netbox_.links()) {
        if (!link["ifname"].isString() || !link["kind"].isString() || !link["operstate"].isString() || !link["master"].isString())
            throw ServiceError(ErrorCode::io_error, "netbox returned an invalid link description");
        const auto name = link["ifname"].asString();
        if (name == "lo" || link["kind"] == "bridge") continue;
        auto state = link["operstate"].asString();
        for (auto& ch : state) if (ch >= 'a' && ch <= 'z') ch -= 'a' - 'A';
        Json::Value row;
        row["name"] = name; row["state"] = state; row["master"] = link["master"];
        result.append(std::move(row));
    }
    return result;
}
}
