// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>

namespace droidvm::vm {
// lib/hugepage/PoolPreflight's gh_hugepage_reserve module knobs (2 MiB pages).
class HugepagePool {
public:
    static constexpr int64_t page_mb = 2;
    explicit HugepagePool(std::string parameters = "/sys/module/gh_hugepage_reserve/parameters");
    bool present() const;
    bool resizable() const; // pool_want exists
    std::optional<int64_t> read(const char* knob) const;
    // Kernels may round a nonzero target up to pageblock alignment.
    bool set_reserved(int64_t pages) const;
    void acquire() const; // acquire=2, else manual_refill=1
    // waitForPool: true once pool_avail >= needed; asks the module to acquire
    // at attempt 5; false on abort, missing reading or after every attempt.
    bool wait(int64_t needed, const std::function<bool()>& abort, int attempts = 300,
              std::chrono::milliseconds interval = std::chrono::seconds(1), int acquire_at = 5) const;
private:
    std::string parameters_;
    bool write(const char* knob, const std::string& value) const;
};
// VMInstanceStore.poolReservations: one kernel target summed over starting
// and running VMs. A rejected write is rolled back, including the target.
class PoolReservations {
public:
    explicit PoolReservations(std::function<bool(int64_t)> write_target) : write_(std::move(write_target)) {}
    bool reserve(const std::string& vm, int64_t pages); // duplicates (reboot) write nothing
    void release(const std::string& vm);
    bool contains(const std::string& vm) const;
    int64_t total() const;
private:
    std::function<bool(int64_t)> write_;
    mutable std::mutex mutex_;
    std::map<std::string, int64_t> pages_;
    int64_t total_locked() const;
};
}
