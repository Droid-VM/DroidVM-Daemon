// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "services/context.h"
#include "services/tasks.h"
#include "store/disk_file_leases.h"
#include <json/json.h>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <sys/types.h>

namespace droidvm::pkg {
struct TransferFile { std::string name; uint64_t size = 0; };
class DownloadReader {
public:
    uint64_t size() const { return size_; }
    std::string read(uint64_t offset, size_t maximum) { return read_(offset, maximum); }
private:
    friend class TransferService;
    uint64_t size_ = 0;
    std::function<std::string(uint64_t, size_t)> read_;
};
class TransferService {
public:
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;
    struct Limits {
        size_t records = 8, files = 1000, readers = 2;
        uint64_t file_bytes = 64ull << 30, session_bytes = 128ull << 30, total_bytes = 128ull << 30;
        size_t chunk_bytes = 256u << 10;
        uint64_t free_bytes = 16u << 20;
        std::chrono::milliseconds ttl = std::chrono::hours(2);
    };
    TransferService(int cache_fd, std::string cache_path, uid_t owner, std::shared_ptr<config::DiskFileLeases> leases);
    TransferService(int cache_fd, std::string cache_path, uid_t owner, std::shared_ptr<config::DiskFileLeases> leases,
        Limits limits, Now now = [] { return Clock::now(); });
    ~TransferService();
    TransferService(const TransferService&) = delete;
    TransferService& operator=(const TransferService&) = delete;
    Json::Value begin(const CallContext& caller, const std::string& request_id, const std::vector<TransferFile>& files);
    Json::Value begin_image(const CallContext& caller, const std::string& request_id, const TransferFile& file);
    Json::Value status(const CallContext& caller, const std::string& id, bool image = false) const;
    Json::Value append(const CallContext& caller, const std::string& id, size_t index, uint64_t offset, std::string_view bytes, bool image = false);
    Json::Value finish(const CallContext& caller, const std::string& id, bool image = false);
    void erase(const CallContext& caller, const std::string& id, bool image = false);
    using PublishImage = std::function<void(const std::string&, const std::function<void()>&)>;
    TaskCompletion install_image(const CallContext& caller, const std::string& upload_id,
        const std::string& folder, const std::string& name, const std::string& qemu_img, TaskControl& control,
        PublishImage publish_image = {});
    // Reject all temporary transfer files, including inode aliases outside the cache.
    void require_persistent_source(const std::string& path, int admitted_fd) const;
    Json::Value prepare_download(const CallContext& caller, const std::string& request_id, const Json::Value& exported);
    std::shared_ptr<DownloadReader> open_download(const CallContext& caller, const std::string& id, size_t index);
    // Empty for ordinary host paths. Upload-owned sources require the exact
    // owner and a ready record; pins keep cleanup out until the import ends.
    std::shared_ptr<const void> pin_source(const CallContext& caller, const std::string& path);
    void maintenance();
    void shutdown();
private:
    Json::Value begin_upload(const CallContext& caller, const std::string& request_id,
        const std::vector<TransferFile>& files, bool image);
    struct Shared;
    std::shared_ptr<Shared> shared_;
};
}
