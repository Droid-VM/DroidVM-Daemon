// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "vm_config.h"
#include <chrono>
#include <map>
#include <vector>

namespace droidvm {
// Ephemeral, principal-scoped staging only. The bound store outlives this service.
// Disconnects leave uploads resumable until their fixed deadline; restart loses
// them. A completed commit (including failure) consumes the upload exactly once.
class VmConfigUploads {
public:
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;
    static constexpr size_t chunk_bytes = 48u << 10;
    static constexpr size_t max_uploads = 4, max_reserved = 32u << 20;
    static constexpr auto lifetime = std::chrono::minutes(2);
    explicit VmConfigUploads(VmConfigService& store, Now now = [] { return Clock::now(); }) : store_(store), now_(std::move(now)) {}
    std::string begin(const CallContext& caller, const std::string& revision, size_t bytes);
    // Exact contiguous byte offsets; repeated identical chunks are idempotent.
    size_t append(const CallContext& caller, const std::string& id, size_t offset, std::string_view bytes);
    VmConfigService::Snapshot commit(const CallContext& caller, const std::string& id);
    void abort(const CallContext& caller, const std::string& id);
private:
    struct Upload {
        std::string principal, revision;
        std::vector<char> data;
        size_t total, reservation;
        Clock::time_point expires;
        bool committing = false;
    };
    VmConfigService& store_;
    Now now_;
    std::mutex mutex_;
    std::map<std::string, std::shared_ptr<Upload>> uploads_;
    size_t reserved_ = 0;
    void reap(); // mutex held
    std::shared_ptr<Upload> find(const CallContext& caller, const std::string& id);
    void finish(const std::string& id) noexcept;
};
}
