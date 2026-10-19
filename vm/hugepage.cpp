// SPDX-License-Identifier: GPL-3.0-or-later
#include "hugepage.h"
#include <algorithm>
#include <charconv>
#include <cerrno>
#include <climits>
#include <fcntl.h>
#include <sys/stat.h>
#include <thread>
#include <stdexcept>
#include <filesystem>
#ifdef _WIN32
#include <io.h>
#include <share.h>
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#else
#include <unistd.h>
#endif

namespace droidvm::vm {
namespace {
#ifdef _WIN32
int native_open(const char* path, int mode) {
    int fd = -1;
    return _sopen_s(&fd, path, mode, _SH_DENYNO, 0) == 0 ? fd : -1;
}
int native_read(int fd, void* bytes, unsigned int size) { return _read(fd, bytes, size); }
int native_write(int fd, const void* bytes, unsigned int size) { return _write(fd, bytes, size); }
int native_close(int fd) { return _close(fd); }
#else
int native_open(const char* path, int mode) { return ::open(path, mode); }
ssize_t native_read(int fd, void* bytes, unsigned int size) { return ::read(fd, bytes, size); }
ssize_t native_write(int fd, const void* bytes, unsigned int size) { return ::write(fd, bytes, size); }
int native_close(int fd) { return ::close(fd); }
#endif
bool exists(const std::string& path) { std::error_code error; return std::filesystem::exists(path, error) && !error; }
}
HugepagePool::HugepagePool(std::string parameters) : parameters_(std::move(parameters)) {}
bool HugepagePool::present() const { return exists(parameters_); }
bool HugepagePool::resizable() const { return has("pool_want"); }
bool HugepagePool::has(const char* knob) const { return exists(parameters_ + "/" + knob); }
std::optional<std::string> HugepagePool::text(const char* knob, size_t limit) const {
    const auto path = parameters_ + "/" + knob;
    int fd = native_open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return {};
    std::string value;
    char buffer[4096];
    for (;;) {
        auto count = native_read(fd, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 || (count > 0 && value.size() + static_cast<size_t>(count) > limit)) { native_close(fd); return {}; }
        if (count == 0) break;
        value.append(buffer, static_cast<size_t>(count));
    }
    native_close(fd);
    return value;
}
std::optional<int64_t> HugepagePool::read(const char* knob) const {
    const auto value = text(knob, 64);
    if (!value) return {};
    size_t first = value->find_first_not_of(" \t\r\n"), last = value->find_last_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    int64_t result = 0;
    auto parsed = std::from_chars(value->data() + first, value->data() + last + 1, result);
    if (parsed.ec != std::errc{} || parsed.ptr != value->data() + last + 1) return {};
    return result;
}
bool HugepagePool::write(const char* knob, const std::string& value) const {
    const auto path = parameters_ + "/" + knob;
    int fd = native_open(path.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0) return false;
    const auto bytes = value + "\n";
    const auto written = native_write(fd, bytes.data(), static_cast<unsigned int>(bytes.size()));
    const bool closed = native_close(fd) == 0;
    return written >= 0 && static_cast<size_t>(written) == bytes.size() && closed;
}
bool HugepagePool::set_reserved(int64_t pages) const {
    if (!write("pool_want", std::to_string(pages))) return false;
    const auto actual = read("pool_want");
    return actual && (*actual == pages || (pages > 0 && *actual > pages));
}
void HugepagePool::acquire() const {
    // Only absence permits the legacy path; a failed write can have taken effect.
    if (has("acquire")) write("acquire", "2");
    else if (has("manual_refill")) write("manual_refill", "1");
}
bool HugepagePool::wait(int64_t needed, const std::function<bool()>& abort, int attempts,
                        std::chrono::milliseconds interval, int acquire_at, std::function<void()> acquire_request) const {
    auto enough = [&] { const auto available = read("pool_avail"); return available && *available >= needed; };
    if (abort()) return false;
    if (enough()) return true;
    for (int attempt = 1; attempt <= attempts; ++attempt) {
        if (abort()) return false;
        if (attempt == acquire_at) { if (acquire_request) acquire_request(); else acquire(); }
        std::this_thread::sleep_for(interval);
        if (abort()) return false;
        if (enough()) return true;
    }
    return false;
}
int64_t PoolReservations::total_locked() const {
    int64_t total = 0;
    for (const auto& [vm, consumer] : pages_) {
        (void) vm;
        if (consumer.pages > INT64_MAX - total) return INT64_MAX;
        total += consumer.pages;
    }
    return total;
}
bool PoolReservations::admit(const std::string& vm, uint64_t generation, int64_t pages, bool automatic) {
    std::lock_guard lock(mutex_);
    if (busy_ || (automatic && !manual_known_) || pages <= 0 || pages > INT64_MAX - total_locked()) return false;
    if (auto found = pages_.find(vm); found != pages_.end()) return found->second.generation == generation;
    pages_[vm] = {generation, pages, automatic};
    ++revision_;
    if (!automatic) return true;
    // Every consumer contributes, including ones which opted out of resizing.
    bool written = false;
    try { written = write_(std::max(manual_, total_locked()), manual_); } catch (...) { /* Admission fails without retaining a ghost consumer. */ }
    if (written) { automatic_target_ = true; return true; }
    pages_.erase(vm);
    // A failed write/readback may have changed the target: do not replay it.
    ++revision_;
    return false;
}
bool PoolReservations::reserve(const std::string& vm, int64_t pages) { return admit(vm, 0, pages, true); }
void PoolReservations::release(const std::string& vm, uint64_t generation) {
    std::lock_guard lock(mutex_);
    const auto found = pages_.find(vm);
    if (found == pages_.end() || found->second.generation != generation) return;
    pages_.erase(found);
    ++revision_;
    if (!automatic_target_) return;
    if (busy_) { deferred_release_ = true; return; }
    try { if (write_(std::max(manual_, total_locked()), manual_) && pages_.empty()) automatic_target_ = false; } catch (...) {}
}
void PoolReservations::release(const std::string& vm) { release(vm, 0); }
bool PoolReservations::contains(const std::string& vm) const { std::lock_guard lock(mutex_); return pages_.contains(vm); }
bool PoolReservations::automatic(const std::string& vm) const {
    std::lock_guard lock(mutex_); auto found = pages_.find(vm); return found != pages_.end() && found->second.automatic;
}
int64_t PoolReservations::total() const { std::lock_guard lock(mutex_); return total_locked(); }
PoolReservations::State PoolReservations::snapshot() const {
    std::lock_guard lock(mutex_); return {total_locked(), manual_, pages_.size(), revision_, busy_, manual_known_};
}
void PoolReservations::initialize_manual(std::optional<int64_t> pages) {
    std::lock_guard lock(mutex_);
    if (!pages_.empty() || busy_ || (pages && *pages < 0)) throw std::logic_error("Hugepage baseline initialization after admission");
    manual_known_ = pages.has_value(); manual_ = pages.value_or(0); ++revision_;
}
bool PoolReservations::set_manual(const ControlLease& lease, int64_t pages) {
    std::lock_guard lock(mutex_);
    if (&lease.owner_ != this || !busy_ || pages < total_locked()) return false;
    manual_ = pages; manual_known_ = true; ++revision_; automatic_target_ = false; deferred_release_ = false;
    return true;
}
std::unique_ptr<PoolReservations::ControlLease> PoolReservations::begin_control() {
    std::lock_guard lock(mutex_);
    if (busy_) return {};
    busy_ = true;
    return std::unique_ptr<ControlLease>(new ControlLease(*this));
}
bool PoolReservations::control(const std::function<void()>& write) {
    std::lock_guard lock(mutex_);
    if (busy_) return false;
    ++revision_;
    write();
    return true;
}
PoolReservations::ControlLease::~ControlLease() { owner_.end_control(reconcile_); }
void PoolReservations::end_control(bool reconcile) {
    std::lock_guard lock(mutex_);
    busy_ = false; ++revision_;
    if (deferred_release_) {
        deferred_release_ = false;
        // After an unknown management write, retain surplus pages instead of
        // replaying a target calculated before that operation. Later explicit
        // management or consumer transitions can reconcile the pool.
        if (!reconcile) return;
        try { if (write_(std::max(manual_, total_locked()), manual_) && pages_.empty()) automatic_target_ = false; }
        catch (...) { /* Lifecycle release cannot throw from a lease destructor. */ }
    }
}
}
