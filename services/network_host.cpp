// SPDX-License-Identifier: GPL-3.0-or-later
#include "network_host.h"

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
