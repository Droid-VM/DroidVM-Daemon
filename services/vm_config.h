// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "context.h"
#include "store/json_file.h"
#include <memory>
#include <mutex>

namespace droidvm {
struct VmConfigSnapshot {
    Json::Value document;
    // Opaque, process-local optimistic concurrency token, never a JSON number.
    // Reopening a store invalidates every previously issued token.
    std::string revision;
    bool persisted = false;
    bool recovered = false;
    bool durability_uncertain = false;
};

// Persistence layer for the single-writer VM migration. The owner must hold
// the daemon Instance lock and coordinate runtime edits before replacing the
// document. Do not instantiate alongside an App that still writes vms.json.
// This service is not yet enabled by the production entry point.
class VmConfigService {
public:
    using Snapshot = std::shared_ptr<const VmConfigSnapshot>;
    static constexpr size_t max_bytes = 16u << 20;
    explicit VmConfigService(int files_directory, uid_t owner, config::JsonFile::Observer observer = {});
    Snapshot snapshot(const CallContext& caller) const;
    // Replace the COMPLETE document obtained from snapshot, preserving opaque
    // fields in that document. No implicit merge, stale overwrite or retry.
    // An installed-but-unsynced commit changes the view/revision and throws
    // COMMIT_UNCERTAIN; clients must re-read before deciding what to do next.
    Snapshot replace(const CallContext& caller, const std::string& expected_revision, Json::Value document);
private:
    config::JsonFile file_;
    mutable std::mutex state_mutex_;
    std::mutex writer_mutex_;
    Snapshot state_;
    Snapshot state() const;
    void publish(Snapshot next);
    static Json::Value normalize(Json::Value document);
};
}
