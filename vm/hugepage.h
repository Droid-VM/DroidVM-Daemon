// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <memory>

namespace droidvm::vm {
// lib/hugepage/PoolPreflight's gh_hugepage_reserve module knobs (2 MiB pages).
class HugepagePool {
public:
    static constexpr int64_t page_mb = 2;
    explicit HugepagePool(std::string parameters = "/sys/module/gh_hugepage_reserve/parameters");
    bool present() const;
    bool resizable() const; // pool_want exists
    bool has(const char* knob) const;
    std::optional<std::string> text(const char* knob, size_t limit = 65536) const;
    bool write(const char* knob, const std::string& value) const;
    std::optional<int64_t> read(const char* knob) const;
    // Kernels may round a nonzero target up to pageblock alignment.
    bool set_reserved(int64_t pages) const;
    void acquire() const; // acquire=2, else manual_refill=1
    // waitForPool: true once pool_avail >= needed; asks the module to acquire
    // at attempt 5; false on abort, missing reading or after every attempt.
    bool wait(int64_t needed, const std::function<bool()>& abort, int attempts = 300,
              std::chrono::milliseconds interval = std::chrono::seconds(1), int acquire_at = 5,
              std::function<void()> acquire_request = {}) const;
private:
    std::string parameters_;
};
// One owner for every Gunyah consumer and administrative write. Unknown write
// outcomes are never replayed; manual baselines survive automatic VM release.
class PoolReservations {
public:
    explicit PoolReservations(std::function<bool(int64_t)> write_target)
        : write_([write = std::move(write_target)](int64_t pages, int64_t) { return write(pages); }) {}
    explicit PoolReservations(std::function<bool(int64_t, int64_t)> write_target) : write_(std::move(write_target)) {}
    struct State { int64_t pages = 0, manual_pages = 0; size_t consumers = 0; uint64_t revision = 0; bool busy = false, manual_known = true; };
    class ControlLease {
    public:
        ~ControlLease();
        ControlLease(const ControlLease&) = delete;
        ControlLease& operator=(const ControlLease&) = delete;
        void suppress_release_adjustment() { reconcile_ = false; }
    private:
        friend class PoolReservations;
        explicit ControlLease(PoolReservations& owner) : owner_(owner) {}
        PoolReservations& owner_;
        bool reconcile_ = true;
    };
    // A logical lease blocks admissions and other writes without holding a mutex
    // across a child process or polling. Consumer release remains nonblocking.
    std::unique_ptr<ControlLease> begin_control();
    bool control(const std::function<void()>& write);
    State snapshot() const;
    void initialize_manual(std::optional<int64_t> pages); // startup; unknown forbids automatic resizing
    bool set_manual(const ControlLease&, int64_t pages); // after verified kernel write
    bool admit(const std::string& vm, uint64_t generation, int64_t pages, bool automatic);
    void release(const std::string& vm, uint64_t generation);
    bool automatic(const std::string& vm) const;
    bool reserve(const std::string& vm, int64_t pages); // duplicates (reboot) write nothing
    void release(const std::string& vm);
    bool contains(const std::string& vm) const;
    int64_t total() const;
private:
    std::function<bool(int64_t, int64_t)> write_;
    mutable std::mutex mutex_;
    struct Consumer { uint64_t generation; int64_t pages; bool automatic; };
    std::map<std::string, Consumer> pages_;
    int64_t manual_ = 0;
    uint64_t revision_ = 0;
    bool busy_ = false, automatic_target_ = false, deferred_release_ = false, manual_known_ = true;
    void end_control(bool reconcile);
    int64_t total_locked() const;
};
}
