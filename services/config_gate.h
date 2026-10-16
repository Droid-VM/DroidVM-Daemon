// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "context.h"
#include <condition_variable>
#include <memory>
#include <mutex>
#include <utility>

namespace droidvm {
// Shared by configuration services, fixed-view creation and VM admission.
// No mutex is held while domain code runs. Nested admissions are allowed; once
// a transaction starts draining, new/nested calls fail promptly instead of
// deadlocking a worker or blocking the transport's snapshot handler on disk IO.
class ConfigurationGate : public std::enable_shared_from_this<ConfigurationGate> {
public:
    class Admission {
    public:
        Admission() = default;
        Admission(Admission&& other) noexcept : gate_(std::move(other.gate_)) {}
        Admission(const Admission&) = delete;
        ~Admission() {
            if (!gate_) return;
            std::lock_guard lock(gate_->mutex_);
            --gate_->active_; gate_->ready_.notify_all();
        }
    private:
        friend class ConfigurationGate;
        explicit Admission(std::shared_ptr<ConfigurationGate> gate) : gate_(std::move(gate)) {}
        std::shared_ptr<ConfigurationGate> gate_;
    };
    class Transaction {
    public:
        Transaction(Transaction&& other) noexcept : gate_(std::move(other.gate_)) {}
        Transaction(const Transaction&) = delete;
        ~Transaction() {
            if (!gate_) return;
            std::lock_guard lock(gate_->mutex_);
            gate_->exclusive_ = false; gate_->ready_.notify_all();
        }
        // Only restore after durable recovery AND coherent domain publication.
        void require_recovery() { std::lock_guard lock(gate_->mutex_); gate_->failed_ = true; }
        void recovered() { std::lock_guard lock(gate_->mutex_); gate_->failed_ = false; }
        void require_available() {
            std::lock_guard lock(gate_->mutex_);
            if (gate_->failed_) throw ServiceError(ErrorCode::unavailable, "Configuration recovery required");
        }
    private:
        friend class ConfigurationGate;
        explicit Transaction(std::shared_ptr<ConfigurationGate> gate) : gate_(std::move(gate)) {}
        std::shared_ptr<ConfigurationGate> gate_;
    };
    static Admission enter(const std::shared_ptr<ConfigurationGate>& gate) {
        if (!gate) return {};
        std::lock_guard lock(gate->mutex_);
        if (gate->exclusive_ || gate->failed_)
            throw ServiceError(ErrorCode::unavailable, "Configuration transaction active or recovery required");
        ++gate->active_;
        return Admission(gate);
    }
    // Coordinator-only worker operation. Do not call while holding an admission
    // or any domain lock: drain those operations BEFORE acquiring domain locks.
    Transaction transaction() {
        auto self = shared_from_this();
        std::unique_lock lock(mutex_);
        ready_.wait(lock, [&] { return !exclusive_; });
        exclusive_ = true;
        ready_.wait(lock, [&] { return active_ == 0; });
        return Transaction(std::move(self));
    }
private:
    std::mutex mutex_;
    std::condition_variable ready_;
    size_t active_ = 0;
    bool exclusive_ = false, failed_ = false;
};
}
