// SPDX-License-Identifier: GPL-3.0-or-later
#include "tasks.h"
#include "common/identity.h"
#include "common/wire.h"
#include <algorithm>
#include <condition_variable>
#include <deque>
#include <limits>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

namespace droidvm {
bool task_terminal(TaskState state) {
    return state == TaskState::succeeded || state == TaskState::failed || state == TaskState::cancelled;
}
const char* task_state_name(TaskState state) {
    switch (state) {
        case TaskState::queued: return "queued";
        case TaskState::running: return "running";
        case TaskState::cancelling: return "cancelling";
        case TaskState::succeeded: return "succeeded";
        case TaskState::failed: return "failed";
        case TaskState::cancelled: return "cancelled";
    }
    return "failed";
}
Json::Value task_summary(const TaskView& task) {
    Json::Value value;
    value["epoch"] = task.ref.epoch;
    value["task_id"] = task.ref.id;
    value["revision"] = std::to_string(task.revision);
    value["kind"] = task.kind;
    value["owner"] = task.owner;
    value["resource"] = task.resource;
    value["state"] = task_state_name(task.state);
    value["cancellable"] = task.cancellable;
    value["phase"] = task.progress.phase;
    value["unit"] = task.progress.unit;
    value["completed"] = std::to_string(task.progress.completed);
    if (task.progress.total) value["total"] = std::to_string(*task.progress.total);
    value["created_monotonic_ms"] = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(task.created.time_since_epoch()).count());
    if (task.finished) value["finished_monotonic_ms"] = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(task.finished->time_since_epoch()).count());
    value["result_available"] = task.state == TaskState::succeeded;
    if (task.error) {
        value["error"]["code"] = error_code_name(*task.error);
        value["error"]["message"] = task.message;
    }
    return value;
}
TaskCompletion TaskCompletion::success(Json::Value value) {
    return {TaskState::succeeded, std::move(value), ErrorCode::internal, {}};
}
TaskCompletion TaskCompletion::failure(ErrorCode code, std::string message) {
    return {TaskState::failed, {}, code, std::move(message)};
}
TaskCompletion TaskCompletion::cancelled() { return {TaskState::cancelled, {}, ErrorCode::internal, {}}; }

namespace task_detail {
// A quota for bounded metadata + encoded result storage, not an RSS promise.
// Domain services separately bound their callback captures and working memory.
constexpr size_t metadata_reservation = 4096;
struct Record {
    TaskView view;
    std::string encoded;
    size_t result_limit = 0, reservation = 0;
    bool operation_cancellable = true;
};
struct Job { std::shared_ptr<Record> record; TaskService::Work work; std::function<void(bool)> direct; TaskService::Discarded discarded; };
struct Shared {
    std::mutex mutex;
    std::condition_variable ready;
    EventJournal events;
    const std::string epoch;
    TaskLimits limits;
    TaskService::Now now;
    std::unordered_map<std::string, std::shared_ptr<Record>> records;
    std::deque<Job> queue;
    std::deque<Job> background_queue;
    size_t reserved = 0;
    bool stopping = false;
    Shared(TaskLimits limits, TaskService::Now now, EventLimits event_limits)
        : events(event_limits, now), epoch(events.epoch()), limits(limits), now(std::move(now)) {}
    void changed(Record& record) noexcept {
        record.view.revision = events.sequence() == std::numeric_limits<uint64_t>::max() ? events.sequence() : events.sequence() + 1;
        try { events.publish("task.changed", record.view.ref.id, record.view.owner, task_summary(record.view)); }
        catch (...) { events.missed(); }
    }
    void reap() {
        const auto time = now();
        for (auto it = records.begin(); it != records.end();) {
            const auto& record = *it->second;
            if (record.view.finished && time - *record.view.finished >= limits.retention) {
                try {
                    Json::Value removed;
                    removed["task_id"] = record.view.ref.id;
                    events.publish("task.removed", record.view.ref.id, record.view.owner, removed);
                } catch (...) { events.missed(); }
                reserved -= record.reservation;
                it = records.erase(it);
            } else ++it;
        }
    }
    void finish(Record& record, TaskState state) {
        record.view.state = state;
        record.view.cancellable = false;
        record.view.finished = now();
        changed(record);
    }
};
}
namespace {
void require_access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.manage_tasks) throw ServiceError(ErrorCode::permission_denied, "Task permission required");
    if (caller.principal.empty() || caller.principal.size() > 128)
        throw ServiceError(ErrorCode::invalid_argument, "Invalid principal");
}
task_detail::Record& find(task_detail::Shared& shared, const CallContext& caller, const TaskRef& ref) {
    if (ref.epoch != shared.epoch) throw ServiceError(ErrorCode::task_epoch_mismatch, "Task belongs to another daemon epoch");
    shared.reap();
    auto found = shared.records.find(ref.id);
    if (found == shared.records.end()) throw ServiceError(ErrorCode::task_not_found, "Task not found");
    auto& record = *found->second;
    if (!caller.administrator && record.view.owner != caller.principal)
        throw ServiceError(ErrorCode::permission_denied, "Task belongs to another principal");
    return record;
}
TaskView view(const task_detail::Record& record) {
    auto result = record.view;
    if (result.state == TaskState::succeeded) result.result = wire::parse(record.encoded);
    return result;
}
}
TaskControl::TaskControl(std::shared_ptr<task_detail::Shared> shared, std::shared_ptr<task_detail::Record> record)
    : shared_(std::move(shared)), record_(std::move(record)) {}
TaskRef TaskControl::ref() const { return record_->view.ref; } // Immutable after admission.
bool TaskControl::cancellation_requested() const {
    std::lock_guard lock(shared_->mutex);
    return record_->view.state == TaskState::cancelling;
}
bool TaskControl::enter_commit() {
    std::lock_guard lock(shared_->mutex);
    if (record_->view.state != TaskState::running) return false;
    if (record_->view.cancellable) {
        record_->view.cancellable = false;
        shared_->changed(*record_);
    }
    return true;
}
void TaskControl::progress(TaskProgress value) {
    if (value.phase.size() > 128 || value.unit.size() > 32 || (value.total && value.completed > *value.total))
        throw ServiceError(ErrorCode::invalid_argument, "Invalid task progress");
    std::lock_guard lock(shared_->mutex);
    if (task_terminal(record_->view.state)) throw ServiceError(ErrorCode::internal, "Task already finished");
    const auto& previous = record_->view.progress;
    if (previous.phase == value.phase && previous.unit == value.unit && value.completed < previous.completed)
        throw ServiceError(ErrorCode::invalid_argument, "Task progress moved backwards");
    record_->view.progress = std::move(value);
    shared_->changed(*record_);
}

struct TaskService::Impl {
    std::shared_ptr<task_detail::Shared> shared;
    std::vector<std::thread> workers;
    std::mutex join_mutex;
    Impl(TaskLimits limits, Now now, EventLimits event_limits) : shared(std::make_shared<task_detail::Shared>(limits, std::move(now), event_limits)) {
        if (!limits.workers || limits.workers > 64 || limits.background_workers > 64 - limits.workers || !limits.queued || !limits.records ||
            limits.max_result_bytes < 4 || limits.max_result_bytes > wire::max_payload ||
            limits.retained_bytes < task_detail::metadata_reservation + 4 ||
            limits.retention < std::chrono::milliseconds::zero() || !shared->now || event_limits.max_event_bytes < (16u << 10))
            throw ServiceError(ErrorCode::invalid_argument, "Invalid task limits");
        workers.reserve(limits.workers + limits.background_workers);
        try {
            for (size_t i = 0; i < limits.workers; ++i) workers.emplace_back([this] { run(false); });
            for (size_t i = 0; i < limits.background_workers; ++i) workers.emplace_back([this] { run(true); });
        } catch (...) {
            shutdown();
            throw;
        }
    }
    void run(bool background) {
        auto& queue = background ? shared->background_queue : shared->queue;
        for (;;) {
            task_detail::Job job;
            {
                std::unique_lock lock(shared->mutex);
                shared->ready.wait(lock, [&] { return shared->stopping || !queue.empty(); });
                if (queue.empty()) return;
                job = std::move(queue.front());
                queue.pop_front();
                if (job.record) {
                    job.record->view.state = TaskState::running;
                    job.record->view.cancellable = job.record->operation_cancellable;
                    shared->changed(*job.record);
                }
            }
            if (job.direct) { try { job.direct(false); } catch (...) {} continue; }
            TaskControl control(shared, job.record);
            TaskCompletion completion = TaskCompletion::failure(ErrorCode::internal, "Task failed");
            std::string encoded;
            try {
                completion = job.work(control);
                if (completion.state == TaskState::succeeded) {
                    try { encoded = wire::stringify_bounded(completion.result, job.record->result_limit); }
                    catch (const std::length_error&) {
                        completion = TaskCompletion::failure(ErrorCode::resource_exhausted, "Task result exceeds its reserved size");
                    }
                }
            } catch (const ServiceError& error) {
                completion = TaskCompletion::failure(error.code(), error.what());
            } catch (...) {
                // Never expose arbitrary exception text, paths or credentials.
                completion = TaskCompletion::failure(ErrorCode::internal, "Task failed");
            }
            // Destroy domain captures before making their completed record eligible
            // for expiry. A callback destructor never runs under the service lock.
            job.work = {};
            {
                std::lock_guard lock(shared->mutex);
                auto& record = *job.record;
                const bool cancelling = record.view.state == TaskState::cancelling;
                if ((completion.state == TaskState::succeeded && cancelling) ||
                    (completion.state == TaskState::cancelled && !cancelling) || !task_terminal(completion.state)) {
                    completion = TaskCompletion::failure(ErrorCode::internal, "Task did not acknowledge its cancellation state");
                }
                if (completion.state == TaskState::succeeded) record.encoded.assign(encoded);
                if (completion.state == TaskState::failed) {
                    record.view.error = completion.error;
                    record.view.message = completion.message.substr(0, 512);
                }
                shared->finish(record, completion.state);
            }
        }
    }
    void shutdown() {
        std::lock_guard join_lock(join_mutex);
        std::deque<task_detail::Job> discarded;
        std::deque<task_detail::Job> background_discarded;
        {
            std::lock_guard lock(shared->mutex);
            shared->stopping = true;
            discarded.swap(shared->queue);
            background_discarded.swap(shared->background_queue);
            for (auto& job : discarded) if (job.record) shared->finish(*job.record, TaskState::cancelled);
            for (auto& job : background_discarded) shared->finish(*job.record, TaskState::cancelled);
            for (auto& [id, record] : shared->records) {
                if (record->view.state == TaskState::running && record->view.cancellable) {
                    record->view.state = TaskState::cancelling;
                    record->view.cancellable = false;
                    shared->changed(*record);
                }
            }
        }
        shared->ready.notify_all();
        for (auto& job : discarded) if (job.direct) { try { job.direct(true); } catch (...) {} }
        for (auto* queue : {&discarded, &background_discarded})
            for (auto& job : *queue) if (job.discarded) { try { job.discarded(job.record->view.ref); } catch (...) {} }
        discarded.clear();
        background_discarded.clear();
        for (auto& worker : workers) if (worker.joinable()) worker.join();
    }
};
TaskService::TaskService(TaskLimits limits, Now now, EventLimits event_limits) : impl_(std::make_unique<Impl>(limits, std::move(now), event_limits)) {}
TaskService::~TaskService() { impl_->shutdown(); }
void TaskService::shutdown() { impl_->shutdown(); }
const std::string& TaskService::epoch() const { return impl_->shared->epoch; }
TaskRef TaskService::submit(const CallContext& caller, TaskSpec spec, Work work, Discarded discarded) {
    require_access(caller);
    auto& shared = *impl_->shared;
    if (spec.kind.empty() || spec.kind.size() > 64 || spec.resource.size() > 256 || !work ||
        spec.result_bytes < 4 || spec.result_bytes > shared.limits.max_result_bytes ||
        (spec.background && !shared.limits.background_workers))
        throw ServiceError(ErrorCode::invalid_argument, "Invalid task specification");
    std::unique_lock lock(shared.mutex);
    if (shared.stopping) throw ServiceError(ErrorCode::unavailable, "Task service is stopping");
    shared.reap();
    const size_t reservation = task_detail::metadata_reservation + spec.result_bytes;
    if (shared.queue.size() + shared.background_queue.size() >= shared.limits.queued || shared.records.size() >= shared.limits.records ||
        reservation > shared.limits.retained_bytes - shared.reserved)
        throw ServiceError(ErrorCode::resource_exhausted, "Task capacity exhausted");
    auto record = std::make_shared<task_detail::Record>();
    record->view.ref = {shared.epoch, random_id(true)};
    record->view.kind = std::move(spec.kind);
    record->view.resource = std::move(spec.resource);
    record->view.owner = caller.principal;
    record->view.created = shared.now();
    record->operation_cancellable = spec.cancellable;
    record->result_limit = spec.result_bytes;
    record->reservation = reservation;
    record->encoded.reserve(spec.result_bytes);
    const auto ref = record->view.ref;
    const auto [entry, inserted] = shared.records.emplace(ref.id, record);
    if (!inserted) throw ServiceError(ErrorCode::internal, "Task ID collision");
    auto& queue = spec.background ? shared.background_queue : shared.queue;
    try { queue.push_back({record, std::move(work), {}, std::move(discarded)}); }
    catch (...) { shared.records.erase(entry); throw; }
    shared.reserved += reservation;
    shared.changed(*record);
    lock.unlock();
    shared.ready.notify_all();
    return ref;
}
void TaskService::post(const CallContext& caller, std::function<void(bool)> work) {
    require_access(caller);
    if (!work) throw ServiceError(ErrorCode::invalid_argument, "Missing work callback");
    auto& shared = *impl_->shared;
    {
        std::lock_guard lock(shared.mutex);
        if (shared.stopping) throw ServiceError(ErrorCode::unavailable, "Task service is stopping");
        if (shared.queue.size() + shared.background_queue.size() >= shared.limits.queued) throw ServiceError(ErrorCode::resource_exhausted, "Worker queue is full");
        shared.queue.push_back({{}, {}, std::move(work), {}});
    }
    shared.ready.notify_all();
}
TaskView TaskService::get(const CallContext& caller, const TaskRef& ref) {
    require_access(caller);
    auto& shared = *impl_->shared;
    std::lock_guard lock(shared.mutex);
    return view(find(shared, caller, ref));
}
TaskView TaskService::cancel(const CallContext& caller, const TaskRef& ref) {
    require_access(caller);
    auto& shared = *impl_->shared;
    Work discarded;
    Discarded notify_discarded;
    std::unique_lock lock(shared.mutex);
    auto& record = find(shared, caller, ref);
    if (task_terminal(record.view.state) || record.view.state == TaskState::cancelling) return view(record);
    // Queued work has no side effects and is always cancellable.
    if (record.view.state == TaskState::queued) {
        auto* queue = &shared.queue;
        auto found = std::find_if(queue->begin(), queue->end(), [&](const auto& job) { return job.record.get() == &record; });
        if (found == queue->end()) {
            queue = &shared.background_queue;
            found = std::find_if(queue->begin(), queue->end(), [&](const auto& job) { return job.record.get() == &record; });
        }
        if (found == queue->end()) throw ServiceError(ErrorCode::internal, "Queued task has no work");
        discarded = std::move(found->work);
        notify_discarded = std::move(found->discarded);
        queue->erase(found);
        shared.finish(record, TaskState::cancelled);
    } else {
        if (!record.view.cancellable) throw ServiceError(ErrorCode::not_cancellable, "Task has entered a non-cancellable operation");
        record.view.state = TaskState::cancelling;
        record.view.cancellable = false;
        shared.changed(record);
    }
    auto result = view(record);
    lock.unlock();
    if (notify_discarded) { try { notify_discarded(ref); } catch (...) {} }
    return result;
}
SnapshotPage TaskService::snapshot(const CallContext& caller, size_t max_bytes) {
    require_access(caller);
    auto& shared = *impl_->shared;
    std::lock_guard lock(shared.mutex);
    shared.reap();
    std::vector<std::string> items;
    size_t bytes = 256 + caller.principal.size();
    for (const auto& [id, record] : shared.records) {
        if (!caller.administrator && record->view.owner != caller.principal) continue;
        auto item = wire::stringify_bounded(task_summary(record->view), shared.events.limits().max_event_bytes);
        if (item.capacity() + 64 > shared.events.limits().max_snapshot_bytes - bytes)
            throw ServiceError(ErrorCode::resource_exhausted, "Task snapshot capacity exhausted");
        bytes += item.capacity() + 64;
        items.push_back(std::move(item));
    }
    std::sort(items.begin(), items.end());
    const EventScope scope{caller.principal, caller.administrator};
    auto id = shared.events.snapshot(scope, std::move(items));
    try { return shared.events.page(scope, id, 0, max_bytes); }
    catch (...) { shared.events.release_snapshot(scope, id); throw; }
}
SnapshotPage TaskService::snapshot_page(const CallContext& caller, const std::string& id, size_t offset, size_t max_bytes) {
    require_access(caller);
    auto& shared = *impl_->shared;
    std::lock_guard lock(shared.mutex);
    return shared.events.page({caller.principal, caller.administrator}, id, offset, max_bytes);
}
void TaskService::release_snapshot(const CallContext& caller, const std::string& id) {
    require_access(caller);
    auto& shared = *impl_->shared;
    std::lock_guard lock(shared.mutex);
    shared.events.release_snapshot({caller.principal, caller.administrator}, id);
}
std::string TaskService::subscribe(const CallContext& caller, const EventCursor& cursor) {
    require_access(caller);
    auto& shared = *impl_->shared;
    std::lock_guard lock(shared.mutex);
    shared.reap();
    return shared.events.subscribe({caller.principal, caller.administrator}, cursor);
}
EventBatch TaskService::poll(const CallContext& caller, const std::string& id, size_t max_events, size_t max_bytes) {
    require_access(caller);
    auto& shared = *impl_->shared;
    std::lock_guard lock(shared.mutex);
    shared.reap();
    return shared.events.poll({caller.principal, caller.administrator}, id, max_events, max_bytes);
}
void TaskService::unsubscribe(const CallContext& caller, const std::string& id) {
    require_access(caller);
    auto& shared = *impl_->shared;
    std::lock_guard lock(shared.mutex);
    shared.events.unsubscribe({caller.principal, caller.administrator}, id);
}
}
