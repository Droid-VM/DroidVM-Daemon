// SPDX-License-Identifier: GPL-3.0-or-later
#include "usb/worker.h"
#include <pthread.h>

namespace droidvm::usb {
Worker::Worker(std::string name) {
    thread_ = std::thread([this, name = std::move(name)] {
        pthread_setname_np(pthread_self(), name.substr(0, 15).c_str());
        run();
    });
}
Worker::~Worker() { shutdown(std::chrono::milliseconds(0)); }
bool Worker::schedule(std::function<void()> task, std::chrono::milliseconds delay, Cancel cancel) {
    std::lock_guard lock(mutex_);
    if (!accepting_) return false;
    queue_.emplace(std::pair{Clock::now() + delay, sequence_++}, Entry{std::move(task), std::move(cancel)});
    wake_.notify_all();
    return true;
}
void Worker::run() {
    std::unique_lock lock(mutex_);
    while (true) {
        if (queue_.empty()) {
            idle_.notify_all();
            if (stopping_ || !accepting_) return;
            wake_.wait(lock);
            continue;
        }
        if (stopping_) return;
        auto first = queue_.begin();
        if (first->first.first > Clock::now()) {
            wake_.wait_until(lock, first->first.first);
            continue;
        }
        auto entry = std::move(first->second);
        queue_.erase(first);
        if (entry.cancel && *entry.cancel) continue;
        running_ = true;
        lock.unlock();
        try { entry.task(); } catch (...) {}
        entry = {};
        lock.lock();
        running_ = false;
    }
}
bool Worker::shutdown(std::chrono::milliseconds timeout) {
    std::unique_lock lock(mutex_);
    accepting_ = false;
    wake_.notify_all();
    const bool finished = idle_.wait_for(lock, timeout, [&] { return queue_.empty() && !running_; });
    stopping_ = true;
    interrupted_ = true;
    wake_.notify_all();
    lock.unlock();
    if (thread_.joinable() && !on_worker()) thread_.join();
    // Dropped delayed tasks complete any waiting submit().
    lock.lock();
    auto dropped = std::move(queue_);
    queue_.clear();
    lock.unlock();
    dropped.clear();
    return finished;
}
bool Worker::wait_idle(std::chrono::milliseconds timeout) {
    std::unique_lock lock(mutex_);
    return idle_.wait_for(lock, timeout, [&] { return queue_.empty() && !running_; });
}
}
