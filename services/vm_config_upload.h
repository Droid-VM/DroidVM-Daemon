// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "vm_config.h"
#include "network_config.h"
#include <chrono>
#include <map>
#include <vector>

namespace droidvm {
// Ephemeral, principal-scoped staging only. The bound store outlives this service.
// Disconnects leave uploads resumable until their fixed deadline; restart loses
// them. A completed commit (including failure) consumes the upload exactly once.
class ConfigUploads {
public:
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;
    using DeleteNetwork = std::function<VmConfigService::Snapshot(const CallContext&, const std::string&, const Json::Value&)>;
    struct DeletedNetwork { std::string id; VmConfigService::Snapshot vms; };
    static constexpr size_t chunk_bytes = 48u << 10;
    static constexpr size_t max_uploads = 4, max_reserved = 32u << 20;
    static constexpr auto lifetime = std::chrono::minutes(2);
    explicit ConfigUploads(VmConfigService& store, Now now = [] { return Clock::now(); })
        : ConfigUploads(&store, nullptr, std::move(now)) {}
    ConfigUploads(VmConfigService* store, NetworkConfigService* networks, Now now = [] { return Clock::now(); }, DeleteNetwork deletion = {})
        : store_(store), networks_(networks), now_(std::move(now)), deletion_(std::move(deletion)) {}
    std::string begin(const CallContext& caller, const std::string& revision, size_t bytes);
    // Exact contiguous byte offsets; repeated identical chunks are idempotent.
    size_t append(const CallContext& caller, const std::string& id, size_t offset, std::string_view bytes);
    VmConfigService::Snapshot commit(const CallContext& caller, const std::string& id);
    void abort(const CallContext& caller, const std::string& id);
    std::string begin_network(const CallContext& caller, size_t bytes);
    size_t append_network(const CallContext& caller, const std::string& id, size_t offset, std::string_view bytes);
    Json::Value commit_network(const CallContext& caller, const std::string& id);
    void abort_network(const CallContext& caller, const std::string& id);
    std::string begin_delete(const CallContext& caller, const std::string& revision, size_t bytes);
    size_t append_delete(const CallContext& caller, const std::string& id, size_t offset, std::string_view bytes);
    DeletedNetwork commit_delete(const CallContext& caller, const std::string& id);
    void abort_delete(const CallContext& caller, const std::string& id);
private:
    enum class Kind { vm, network, network_delete };
    struct Upload {
        std::string principal, revision;
        std::vector<char> data;
        size_t total, reservation;
        Clock::time_point expires;
        bool committing = false;
        Kind kind = Kind::vm;
    };
    VmConfigService* store_;
    NetworkConfigService* networks_;
    Now now_;
    DeleteNetwork deletion_;
    std::mutex mutex_;
    std::map<std::string, std::shared_ptr<Upload>> uploads_;
    size_t reserved_ = 0;
    void reap(); // mutex held
    std::shared_ptr<Upload> find(const CallContext& caller, const std::string& id, Kind kind);
    std::string begin_impl(const CallContext& caller, const std::string& revision, size_t bytes, Kind kind);
    size_t append_impl(const CallContext& caller, const std::string& id, size_t offset, std::string_view bytes, Kind kind);
    void abort_impl(const CallContext& caller, const std::string& id, Kind kind);
    void consume(const CallContext& caller, const std::string& id, Kind kind,
        const std::function<void(const std::string&, std::string_view)>& apply);
    void finish(const std::string& id) noexcept;
};
// Keep existing VM callers and contract helpers source-compatible.
using VmConfigUploads = ConfigUploads;
}
