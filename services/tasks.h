// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "context.h"
#include "events.h"
#include <json/json.h>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace droidvm {
struct VmConfigSnapshot;
enum class TaskState { queued, running, cancelling, succeeded, failed, cancelled };
bool task_terminal(TaskState state);
const char* task_state_name(TaskState state);
struct TaskRef { std::string epoch, id; };
struct TaskProgress {
    std::string phase, unit;
    uint64_t completed = 0;
    std::optional<uint64_t> total;
};
struct TaskView {
    TaskRef ref;
    std::string kind, owner, resource;
    TaskState state = TaskState::queued;
    uint64_t revision = 0;
    bool cancellable = true;
    TaskProgress progress;
    Json::Value result;
    std::optional<ErrorCode> error;
    std::string message;
    std::chrono::steady_clock::time_point created;
    std::optional<std::chrono::steady_clock::time_point> finished;
};
// Public state projection. Large immutable results remain available through get.
Json::Value task_summary(const TaskView& task);
struct TaskSpec {
    std::string kind, resource;
    size_t result_bytes = 64u << 10;
    bool cancellable = true;
    bool background = false;
};
struct TaskLimits {
    size_t workers = 2, queued = 64, records = 256;
    size_t retained_bytes = 16u << 20, max_result_bytes = 64u << 10;
    std::chrono::milliseconds retention = std::chrono::minutes(30);
    // Long operations use a separate pool without a second task/event registry.
    size_t background_workers = 0;
};
struct TaskCompletion {
    TaskState state;
    Json::Value result;
    ErrorCode error = ErrorCode::internal;
    std::string message;
    static TaskCompletion success(Json::Value value = Json::Value());
    static TaskCompletion failure(ErrorCode code, std::string public_message);
    // Only return after this operation's owned resources have been cleaned up.
    static TaskCompletion cancelled();
};
namespace task_detail { struct Shared; struct Record; }
class TaskControl {
public:
    TaskControl(const TaskControl&) = delete;
    TaskControl& operator=(const TaskControl&) = delete;
    bool cancellation_requested() const;
    TaskRef ref() const;
    // The same lock arbitrates cancellation and entry to an irreversible commit.
    // False means cancellation won: clean up and return cancelled(), not success.
    bool enter_commit();
    void progress(TaskProgress value);
private:
    friend class TaskService;
    TaskControl(std::shared_ptr<task_detail::Shared> shared, std::shared_ptr<task_detail::Record> record);
    std::shared_ptr<task_detail::Shared> shared_;
    std::shared_ptr<task_detail::Record> record_;
};
class TaskService {
public:
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;
    using Work = std::function<TaskCompletion(TaskControl&)>;
    using Discarded = std::function<void(const TaskRef&)>;
    explicit TaskService(TaskLimits limits = {}, Now now = [] { return Clock::now(); }, EventLimits event_limits = {});
    ~TaskService();
    TaskService(const TaskService&) = delete;
    TaskService& operator=(const TaskService&) = delete;
    const std::string& epoch() const;
    // discarded runs outside the state lock only if queued work never starts;
    // it must not introduce domain side effects or wait for this pool to stop.
    TaskRef submit(const CallContext& caller, TaskSpec spec, Work work, Discarded discarded = {});
    // Short synchronous RPC work shares this bounded worker queue without
    // retaining task records. true means shutdown discarded it before execution.
    // The caller must separately bound captured input and completion storage.
    void post(const CallContext& caller, std::function<void(bool)> work);
    TaskView get(const CallContext& caller, const TaskRef& ref);
    TaskView cancel(const CallContext& caller, const TaskRef& ref);
    SnapshotPage snapshot(const CallContext& caller, size_t max_bytes = 256u << 10);
    // Trusted domain publication only: immutable active configuration rows,
    // bounded by NetworkConfigService's storage quota. No callbacks/domain locks
    // are acquired under the journal lock. Caller serializes domain commits.
    void publish_network_config(std::shared_ptr<const Json::Value> rows) noexcept;
    SnapshotPage network_config_snapshot(const CallContext& caller, size_t max_bytes = 256u << 10);
    void publish_vm_config(std::shared_ptr<const VmConfigSnapshot> snapshot) noexcept;
    SnapshotPage vm_config_snapshot(const CallContext& caller, size_t max_bytes = 256u << 10);
    SnapshotPage snapshot_page(const CallContext& caller, const std::string& id, size_t offset, size_t max_bytes = 256u << 10);
    void release_snapshot(const CallContext& caller, const std::string& id);
    std::string subscribe(const CallContext& caller, const EventCursor& cursor);
    EventBatch poll(const CallContext& caller, const std::string& id, size_t max_events = 64, size_t max_bytes = 256u << 10);
    void unsubscribe(const CallContext& caller, const std::string& id);
    // Reject new work, cancel queued work, request cooperative cancellation of
    // running work, and join workers. Callbacks must bound waits and clean up.
    // Call from the owning thread, never from one of this pool's callbacks.
    void shutdown();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
