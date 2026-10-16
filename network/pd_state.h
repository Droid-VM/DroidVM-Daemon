// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "linux_routing.h"
#include "runtime/managed_process.h"
#include <functional>

namespace droidvm::network {
struct PdSnapshot { uint64_t generation = 0; PdAddresses addresses; };
// Helper events are invalidation hints, never incremental authority. A worker
// fetches a full status after any PD event, loss, malformed output or restart.
class PdState {
public:
    void reset(std::map<int, std::string> devices);
    PdSnapshot poll(const ProcessOutput& output, const std::function<Json::Value()>& fetch, bool force = false);
private:
    std::map<int, std::string> devices_;
    PdSnapshot snapshot_;
    bool dirty_ = true;
    PdAddresses parse(const Json::Value& status) const;
};
}
