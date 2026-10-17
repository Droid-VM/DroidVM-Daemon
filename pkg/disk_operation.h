// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "services/tasks.h"
#include "store/json_file.h"
#include <json/json.h>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <sys/types.h>

namespace droidvm {
class ConfigurationService;
}
namespace droidvm::pkg {
struct DiskOperationContext {
    ConfigurationService* configuration = nullptr; // Coordinated disk owner; startup binding only.
    int directory = -1; // Configuration directory; duplicated, not owned.
    uid_t owner = 0;
    std::string data_dir; // Constants.DATA_DIR; empty = /data/data/<package>
    std::function<void(const char* level, const std::string& text)> log = [](const char*, const std::string&) {};
    config::JsonFile::Observer observer; // Journal fault injection.
    // Test-only boundary after the image tool succeeds and before replacement.
    std::function<void(const char* stage)> fault;
};
// In-place qemu-img operations on registered disks (DiskOperationActivity's
// resize/convert/flatten). Every operation reserves its registry rows, holds
// file leases on the image and its registered ancestors, reads through retained
// descriptors and replaces images only by renaming a journaled temporary file.
// Construct under the Instance lock after the coordinator, before serving: it
// replays unfinished operations first.
class DiskOperationService {
public:
    static constexpr size_t max_tasks = 4;
    explicit DiskOperationService(DiskOperationContext context);
    ~DiskOperationService();
    DiskOperationService(const DiskOperationService&) = delete;
    DiskOperationService& operator=(const DiskOperationService&) = delete;
    // {"disk_revision","disk_id","action":"resize|convert|flatten",...} ->
    // {"task_id","epoch"}. Admission errors (stale revision, busy files or rows,
    // header/registry mismatch) are thrown before a task exists.
    Json::Value start(const CallContext& caller, const Json::Value& request);
    // Administrator retry of operations whose cleanup or registry follow-up
    // could not finish. {"pending": n}; nothing is resubmitted.
    Json::Value recover(const CallContext& caller);
    size_t pending() const;
    void shutdown();
private:
    class Operation;
    DiskOperationContext context_;
    std::unique_ptr<config::JsonFile> journal_;
    mutable std::mutex journal_mutex_;
    Json::Value records_{Json::arrayValue};
    std::set<std::string> running_; // Records owned by live operations; replay skips them.
    std::shared_ptr<std::atomic<bool>> stopping_ = std::make_shared<std::atomic<bool>>(false);
    std::shared_ptr<std::atomic<size_t>> active_ = std::make_shared<std::atomic<size_t>>(0);
    void put_record(const Json::Value& record);
    void drop_record(const std::string& id);
    void replay();
    bool replay_one(const Json::Value& record);
    bool replay_new(int directory, const Json::Value& record);
    bool replay_merge(const Json::Value& record);
    bool replay_delete(const Json::Value& record);
};
}
