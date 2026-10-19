// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "services/config_snapshot.h"
#include <cstdint>

namespace droidvm::web {
// Narrow observation boundary: callers copy NetworkService::get() fields here.
// Native errors, tool metadata and private control socket paths are not exposed.
struct NetworkObservation {
    std::string id;
    // Exact native network_state_name(): STOPPED/STARTING/RUNNING/
    // RECOVERING/STOPPING/FAILED.
    std::string state;
    uint64_t generation = 0;
    bool desired_running = false;
};

// Call get(), live(), get() in that order on the same service instance. A changed
// generation discards live rows rather than associating old data with new state.
// Config/VM data are separate immutable observations, not an atomic cross-store
// snapshot. Attachments describe saved VM NICs, not proof of running attachment.
// An empty native live object means unavailable/busy, never empty live success.
Json::Value network_detail(const Json::Value& config, const VmConfigSnapshot& vms,
    const NetworkObservation& before, const NetworkObservation& after,
    const Json::Value& live, const std::string& configuration_revision);
}
