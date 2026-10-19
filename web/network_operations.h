// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include "services/network_state.h"
#include "services/tasks.h"

namespace droidvm::web {
struct NetworkOperation {
    std::string network_id;
    bool start = false;
    uint64_t generation = 0;
    NetworkState state = NetworkState::stopped;
    std::string configuration_revision;
};
using ExecuteNetworkOperation = std::function<void(const CallContext&, const NetworkOperation&)>;
// The callback binds directly to NetworkService::change_if_matches. Validation,
// task ownership/deduplication and cancellation admission remain shared here.
BackgroundOperations network_operations(TaskService& tasks, ExecuteNetworkOperation execute);
}
