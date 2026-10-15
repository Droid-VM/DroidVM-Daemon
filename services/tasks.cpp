// SPDX-License-Identifier: GPL-3.0-or-later
#include "tasks.h"
#include "common/identity.h"
#include "common/wire.h"
#include <algorithm>
#include <condition_variable>
#include <deque>
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
struct Job { std::shared_ptr<Record> record; TaskService::Work work; };
struct Shared {
    std::mutex mutex;
    std::condition_variable ready;
    const std::string epoch = random_id(true);
    TaskLimits limits;
    TaskService::Now now;
    std::unordered_map<std::string, std::shared_ptr<Record>> records;
    std::deque<Job> queue;
    size_t reserved = 0;
    bool stopping = false;
    Shared(TaskLimits limits, TaskService::Now now) : limits(limits), now(std::move(now)) {}
    void reap() {
        const auto time = now();
        for (auto it = records.begin(); it != records.end();) {
            const auto& record = *it->second;
            if (record.view.finished && time - *record.view.finished >= limits.retention) {
                reserved -= record.reservation;
                it = records.erase(it);
            } else ++it;
        }
    }
    void finish(Record& record, TaskState state) {
        record.view.state = state;
        record.view.cancellable = false;
        record.view.finished = now();
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
bool TaskControl::cancellation_requested() const {
    std::lock_guard lock(shared_->mutex);
    return record_->view.state == TaskState::cancelling;
}
bool TaskControl::enter_commit() {
    std::lock_guard lock(shared_->mutex);
    if (record_->view.state != TaskState::running) return false;
    record_->view.cancellable = false;
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
}

struct TaskService::Impl {
    std::shared_ptr<task_detail::Shared> shared;
    std::vector<std::thread> workers;
    std::mutex join_mutex;
    Impl(TaskLimits limits, Now now) : shared(std::make_shared<task_detail::Shared>(limits, std::move(now))) {
        if (!limits.workers || limits.workers > 64 || !limits.queued || !limits.records ||
            limits.max_result_bytes < 4 || limits.max_result_bytes > wire::max_payload ||
            limits.retained_bytes < task_detail::metadata_reservation + 4 ||
            limits.retention < std::chrono::milliseconds::zero() || !shared->now)
            throw ServiceError(ErrorCode::invalid_argument, "Invalid task limits");
        workers.reserve(limits.workers);
        try {
            for (size_t i = 0; i < limits.workers; ++i) workers.emplace_back([this] { run(); });
        } catch (...) {
            shutdown();
            throw;
        }
    }
    void run() {
        for (;;) {
            task_detail::Job job;
            {
                std::unique_lock lock(shared->mutex);
                shared->ready.wait(lock, [&] { return shared->stopping || !shared->queue.empty(); });
                if (shared->queue.empty()) return;
                job = std::move(shared->queue.front());
                shared->queue.pop_front();
                job.record->view.state = TaskState::running;
                job.record->view.cancellable = job.record->operation_cancellable;
            }
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
        {
            std::lock_guard lock(shared->mutex);
            shared->stopping = true;
            discarded.swap(shared->queue);
            for (auto& job : discarded) shared->finish(*job.record, TaskState::cancelled);
            for (auto& [id, record] : shared->records) {
                if (record->view.state == TaskState::running && record->view.cancellable) {
                    record->view.state = TaskState::cancelling;
                    record->view.cancellable = false;
                }
            }
        }
        shared->ready.notify_all();
        discarded.clear();
        for (auto& worker : workers) if (worker.joinable()) worker.join();
    }
};
TaskService::TaskService(TaskLimits limits, Now now) : impl_(std::make_unique<Impl>(limits, std::move(now))) {}
TaskService::~TaskService() { impl_->shutdown(); }
void TaskService::shutdown() { impl_->shutdown(); }
const std::string& TaskService::epoch() const { return impl_->shared->epoch; }
TaskRef TaskService::submit(const CallContext& caller, TaskSpec spec, Work work) {
    require_access(caller);
    auto& shared = *impl_->shared;
    if (spec.kind.empty() || spec.kind.size() > 64 || spec.resource.size() > 256 || !work ||
        spec.result_bytes < 4 || spec.result_bytes > shared.limits.max_result_bytes)
        throw ServiceError(ErrorCode::invalid_argument, "Invalid task specification");
    std::unique_lock lock(shared.mutex);
    if (shared.stopping) throw ServiceError(ErrorCode::unavailable, "Task service is stopping");
    shared.reap();
    const size_t reservation = task_detail::metadata_reservation + spec.result_bytes;
    if (shared.queue.size() >= shared.limits.queued || shared.records.size() >= shared.limits.records ||
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
    try { shared.queue.push_back({record, std::move(work)}); }
    catch (...) { shared.records.erase(entry); throw; }
    shared.reserved += reservation;
    lock.unlock();
    shared.ready.notify_one();
    return ref;
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
    std::lock_guard lock(shared.mutex);
    auto& record = find(shared, caller, ref);
    if (task_terminal(record.view.state) || record.view.state == TaskState::cancelling) return view(record);
    // Queued work has no side effects and is always cancellable.
    if (record.view.state == TaskState::queued) {
        auto found = std::find_if(shared.queue.begin(), shared.queue.end(), [&](const auto& job) { return job.record.get() == &record; });
        discarded = std::move(found->work);
        shared.queue.erase(found);
        shared.finish(record, TaskState::cancelled);
    } else {
        if (!record.view.cancellable) throw ServiceError(ErrorCode::not_cancellable, "Task has entered a non-cancellable operation");
        record.view.state = TaskState::cancelling;
        record.view.cancellable = false;
    }
    return view(record);
}
}
