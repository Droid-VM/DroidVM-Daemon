// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "context.h"
#include "network/netbox.h"
#include "network/host_discovery.h"

namespace droidvm {
// Host-wide discovery is independent of a network configuration or its runtime.
class NetworkHostService {
public:
    explicit NetworkHostService(std::string executable) : netbox_(std::move(executable)) {}
    Json::Value available_interfaces(const CallContext& caller) const;
    Json::Value uplinks(const CallContext& caller) const;
    Json::Value addresses(const CallContext& caller) const;
private:
    network::Netbox netbox_;
};
}
