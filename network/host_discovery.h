// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace droidvm::network {
inline constexpr uint32_t pbridge_offload_metric = 4243672773u;
const std::vector<std::string>& host_interface_prefixes();
// Shared HostAddressScan policy; keep the netlink dump's order and raw address
// strings. Tool failures must be reported before calling this projection.
Json::Value host_addresses(const Json::Value& links, const Json::Value& addresses);
struct HostInterface {
    std::string name;
    uint32_t index = 0;
    bool wireless = false, up = false, ethernet = false, physical = false;
    bool leaf = false, virtual_device = false, bridge = false, tun = false;
    bool real_l2() const { return ethernet && leaf && !virtual_device && (up || physical); }
};
// One fresh snapshot per service operation. Logical identifiers re-resolve on
// each scan; a caller mutating an uplink must separately hold/check its identity.
class UplinkSnapshot {
public:
    static UplinkSnapshot scan(const std::string& root = "/sys/class/net");
    std::optional<std::string> resolve(const std::string& configured) const;
    bool assume_dont_bridge(const std::string& name) const;
    Json::Value picker() const;
    const std::vector<HostInterface>& interfaces() const { return interfaces_; }
private:
    std::vector<HostInterface> interfaces_;
};
}
