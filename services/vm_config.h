// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "context.h"
#include "config_gate.h"
#include "store/json_file.h"
#include <memory>
#include <functional>
#include <mutex>

namespace droidvm {
class TaskService;
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

// Persistence layer for the single-writer VM migration. The owner must hold
// the daemon Instance lock and coordinate runtime edits before replacing the
// document. Construction durably claims the shared ownership gate before loading;
// cooperating legacy App writes are then refused, including after daemon exit.
// Older clients without this gate must not run alongside this service.
// This service is not yet enabled by the production entry point.
class VmConfigService {
public:
    // Prepared participants retain their locks until after snapshot publication.
    // All allocation/validation happens in prepare; commit cannot fail after rename.
    struct Commit {
        virtual ~Commit() = default;
        virtual void commit() noexcept = 0;
    };
    using Prepare = std::function<std::unique_ptr<Commit>(const Json::Value&)>;
    using Snapshot = std::shared_ptr<const VmConfigSnapshot>;
    static constexpr size_t max_bytes = 16u << 20;
    explicit VmConfigService(int files_directory, uid_t owner, config::JsonFile::Observer observer = {}, Prepare prepare = {}, TaskService* events = nullptr,
        std::shared_ptr<ConfigurationGate> gate = {});
    bool has_events() const { return events_ != nullptr; }
    Snapshot snapshot(const CallContext& caller) const;
    // Replace the COMPLETE document obtained from snapshot, preserving opaque
    // fields in that document. No implicit merge, stale overwrite or retry.
    // An installed-but-unsynced commit changes the view/revision and throws
    // COMMIT_UNCERTAIN; clients must re-read before deciding what to do next.
    Snapshot replace(const CallContext& caller, const std::string& expected_revision, Json::Value document);
    // Atomic small edits against one observed revision, preserving root extensions
    // and untouched entries. Each operation is create/replace with config, or
    // delete with id. A target may occur once; replacements retain list order.
    Snapshot apply(const CallContext& caller, const std::string& expected_revision, const Json::Value& operations);
private:
    friend class ConfigurationService;
    config::JsonFile file_;
    mutable std::mutex state_mutex_;
    std::mutex writer_mutex_;
    Snapshot state_;
    Prepare prepare_;
    TaskService* events_;
    std::shared_ptr<ConfigurationGate> gate_;
    Snapshot state() const;
    void publish(Snapshot next);
    static Json::Value normalize(Json::Value document);
};
}
