// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "config_gate.h"
#include "config_commit.h"
#include "store/json_file.h"
#include <memory>

namespace droidvm {
struct DiskConfigSnapshot {
    Json::Value document;
    std::shared_ptr<const std::string> encoded;
    std::string revision;
    bool persisted = false, recovered = false, durability_uncertain = false;
};
// Registry persistence only. The caller holds Instance and must coordinate VM
// references, runtime/file leases and qcow2 headers before exposing mutations.
// Never interprets a registry removal as permission to unlink a disk image.
// Not bound to production until those participants and legacy writers migrate.
class DiskConfigService {
public:
    using Snapshot = std::shared_ptr<const DiskConfigSnapshot>;
    // Startup binding; prepares under gate admission and registry writer, before IO.
    // It must not re-enter this service or acquire an exclusive gate transaction.
    // Leases survive publication, including installed-but-uncertain outcomes.
    using Prepare = std::function<std::unique_ptr<ConfigurationCommit>(const Json::Value& before, const Json::Value& after)>;
    static constexpr size_t max_bytes = config::JsonFile::max_bytes;
    DiskConfigService(int directory, uid_t owner, config::JsonFile::Observer observer = {},
        std::shared_ptr<ConfigurationGate> gate = {}, Prepare prepare = {});
    Snapshot snapshot(const CallContext& caller) const;
    // Complete observed document, including root/row extensions. No implicit
    // merge or retry. Exact revision includes edits to unrelated registry rows.
    Snapshot replace(const CallContext& caller, const std::string& revision, Json::Value document);
private:
    friend class ConfigurationService;
    config::JsonFile file_;
    std::shared_ptr<ConfigurationGate> gate_;
    Prepare prepare_;
    mutable std::mutex state_mutex_;
    std::mutex writer_mutex_;
    Snapshot state_;
    Snapshot state() const;
    void publish(Snapshot next);
    static Json::Value normalize(Json::Value document);
};
}
