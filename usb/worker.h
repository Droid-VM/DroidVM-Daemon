// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>

namespace droidvm::usb {
// A single-thread ScheduledExecutorService: tasks run in due-time order, FIFO
// among equals. After shutdown() nothing new is accepted, while queued and
// delayed tasks still run (the JDK's default policy) until the deadline.
class Worker {
public:
    using Clock = std::chrono::steady_clock;
    using Cancel = std::shared_ptr<std::atomic<bool>>;
    explicit Worker(std::string name);
    ~Worker();
    // false when the worker is shut down (RejectedExecutionException).
    bool schedule(std::function<void()> task, std::chrono::milliseconds delay = std::chrono::milliseconds(0), Cancel cancel = {});
    // Runs [task] on the worker and waits; nullopt when rejected. A thrown
    // exception is rethrown here (ExecutionException).
    template <typename F> auto submit(F task) -> std::optional<decltype(task())>;
    // Waits up to [timeout] for queued work, then marks the worker
    // interrupted (waits inside tasks end early) and joins. Returns whether
    // everything finished in time.
    bool shutdown(std::chrono::milliseconds timeout);
    bool interrupted() const { return interrupted_; }
    bool on_worker() const { return std::this_thread::get_id() == thread_.get_id(); }
    // Test hook: waits until nothing is queued or running.
    bool wait_idle(std::chrono::milliseconds timeout);
private:
    struct Entry { std::function<void()> task; Cancel cancel; };
    std::mutex mutex_;
    std::condition_variable wake_, idle_;
    std::multimap<std::pair<Clock::time_point, uint64_t>, Entry> queue_;
    uint64_t sequence_ = 0;
    bool accepting_ = true, stopping_ = false, running_ = false;
    std::atomic<bool> interrupted_{false};
    std::thread thread_;
    void run();
};
template <typename F> auto Worker::submit(F task) -> std::optional<decltype(task())> {
    using T = decltype(task());
    struct Slot { std::mutex mutex; std::condition_variable done; bool finished = false; std::optional<T> value; std::exception_ptr error; };
    // Completes the wait when the task is destroyed, run or dropped at shutdown.
    struct Guard {
        std::shared_ptr<Slot> slot;
        ~Guard() { std::lock_guard lock(slot->mutex); slot->finished = true; slot->done.notify_all(); }
    };
    auto slot = std::make_shared<Slot>();
    std::shared_ptr<Guard> guard(new Guard{slot});
    const bool queued = schedule([guard, task = std::move(task)]() mutable {
        std::optional<T> value;
        std::exception_ptr error;
        try { value.emplace(task()); } catch (...) { error = std::current_exception(); }
        std::lock_guard lock(guard->slot->mutex);
        guard->slot->value = std::move(value);
        guard->slot->error = error;
    });
    guard.reset();
    if (!queued) return std::nullopt;
    std::unique_lock lock(slot->mutex);
    slot->done.wait(lock, [&] { return slot->finished; });
    if (slot->error) std::rethrow_exception(slot->error);
    return std::move(slot->value);
}
}
