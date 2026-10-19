// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <memory>
#include <string>

namespace droidvm {
// Immutable service views. Task publication does not depend on POSIX file IO.
struct VmConfigSnapshot {
    Json::Value document;
    std::shared_ptr<const std::string> encoded;
    // Opaque, process-local optimistic concurrency token, never a JSON number.
    // Reopening a store invalidates every previously issued token.
    std::string revision;
    bool persisted = false;
    bool recovered = false;
    bool durability_uncertain = false;
};
struct DiskConfigSnapshot {
    Json::Value document;
    std::shared_ptr<const std::string> encoded;
    std::string revision;
    bool persisted = false, recovered = false, durability_uncertain = false;
};
}
