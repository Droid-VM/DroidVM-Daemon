// SPDX-License-Identifier: GPL-3.0-or-later
#include "hugepage.h"
#include "store/network_config.h"
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

namespace droidvm::vm {
namespace {
bool exists(const std::string& path) { struct stat info{}; return stat(path.c_str(), &info) == 0; }
}
HugepagePool::HugepagePool(std::string parameters) : parameters_(std::move(parameters)) {}
bool HugepagePool::present() const { return exists(parameters_); }
bool HugepagePool::resizable() const { return exists(parameters_ + "/pool_want"); }
std::optional<int64_t> HugepagePool::read(const char* knob) const {
    const auto path = parameters_ + "/" + knob;
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return {};
    char buffer[64];
    ssize_t count;
    do count = ::read(fd, buffer, sizeof(buffer) - 1); while (count < 0 && errno == EINTR);
    ::close(fd);
    if (count <= 0) return {};
    std::string text(buffer, static_cast<size_t>(count));
    size_t first = 0, last = text.size();
    while (first < last && static_cast<unsigned char>(text[first]) <= ' ') ++first;
    while (last > first && static_cast<unsigned char>(text[last - 1]) <= ' ') --last;
    try { return config::java_long(std::string_view(text).substr(first, last - first)); }
    catch (const std::invalid_argument&) { return {}; }
}
bool HugepagePool::write(const char* knob, const std::string& value) const {
    const auto path = parameters_ + "/" + knob;
    if (!exists(path)) return false;
    int fd = open(path.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0) return false;
    const auto text = value + "\n";
    ssize_t written;
    do written = ::write(fd, text.data(), text.size()); while (written < 0 && errno == EINTR);
    const bool closed = ::close(fd) == 0;
    return written == static_cast<ssize_t>(text.size()) && closed;
}
bool HugepagePool::set_reserved(int64_t pages) const {
    // gh_hugepage_reserve rejects a write that closely follows the previous
    // one (a stop then an immediate start); the legacy single write failed there.
    bool written = write("pool_want", std::to_string(pages));
    for (int attempt = 0; !written && attempt < 10 && resizable(); ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        written = write("pool_want", std::to_string(pages));
    }
    if (!written) return false;
    const auto actual = read("pool_want");
    return actual && (*actual == pages || (pages > 0 && *actual > pages));
}
void HugepagePool::acquire() const { if (!write("acquire", "2")) write("manual_refill", "1"); }
bool HugepagePool::wait(int64_t needed, const std::function<bool()>& abort, int attempts,
                        std::chrono::milliseconds interval, int acquire_at) const {
    auto enough = [&] { const auto available = read("pool_avail"); return available && *available >= needed; };
    if (abort()) return false;
    if (enough()) return true;
    for (int attempt = 1; attempt <= attempts; ++attempt) {
        if (abort()) return false;
        if (attempt == acquire_at) acquire();
        std::this_thread::sleep_for(interval);
        if (abort()) return false;
        if (enough()) return true;
    }
    return false;
}
int64_t PoolReservations::total_locked() const {
    int64_t total = 0;
    for (const auto& [vm, pages] : pages_) total += pages;
    return total;
}
bool PoolReservations::reserve(const std::string& vm, int64_t pages) {
    std::lock_guard lock(mutex_);
    if (pages <= 0 || pages_.contains(vm)) return true;
    pages_[vm] = pages;
    if (write_(total_locked())) return true;
    // A rejected read-back may still have changed the kernel target.
    pages_.erase(vm);
    write_(total_locked());
    return false;
}
void PoolReservations::release(const std::string& vm) {
    std::lock_guard lock(mutex_);
    if (!pages_.erase(vm)) return;
    write_(total_locked());
}
bool PoolReservations::contains(const std::string& vm) const { std::lock_guard lock(mutex_); return pages_.contains(vm); }
int64_t PoolReservations::total() const { std::lock_guard lock(mutex_); return total_locked(); }
}
