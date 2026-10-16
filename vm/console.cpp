// SPDX-License-Identifier: GPL-3.0-or-later
#include "console.h"
#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

namespace droidvm::vm {
namespace {
bool write_all(int fd, std::string_view data) {
    while (!data.empty()) {
        const auto written = write(fd, data.data(), data.size());
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return false;
        data.remove_prefix(static_cast<size_t>(written));
    }
    return true;
}
}
ConsoleLog::ConsoleLog(std::string path, uid_t owner, bool persistent) : path_(std::move(path)), owner_(owner), persistent_(persistent) {
    Fd file(open(path_.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
    if (file.get() < 0) return;
    char buffer[65536];
    for (;;) {
        const auto count = read(file.get(), buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        push({buffer, static_cast<size_t>(count)});
    }
}
void ConsoleLog::push(std::string_view data) {
    if (data.size() >= capacity) { data = data.substr(data.size() - capacity); head_ = 0; size_ = 0; }
    for (size_t offset = 0; offset < data.size();) {
        const auto tail = (head_ + size_) % capacity;
        const auto chunk = std::min(data.size() - offset, capacity - tail);
        std::copy_n(data.data() + offset, chunk, ring_.begin() + static_cast<std::ptrdiff_t>(tail));
        offset += chunk;
        size_ += chunk;
        if (size_ > capacity) { head_ = (head_ + size_ - capacity) % capacity; size_ = capacity; }
    }
}
std::string ConsoleLog::contents_locked() const {
    std::string result(size_, '\0');
    const auto first = std::min(size_, capacity - head_);
    std::copy_n(ring_.begin() + static_cast<std::ptrdiff_t>(head_), first, result.begin());
    std::copy_n(ring_.begin(), size_ - first, result.begin() + static_cast<std::ptrdiff_t>(first));
    return result;
}
void ConsoleLog::append(std::string_view data) {
    std::lock_guard lock(mutex_);
    push(data);
    appended_ += data.size();
    if (disable_save_ || !persistent_) return;
    if (writer_.get() < 0) {
        // First write rewrites the copy from the whole buffer, as the legacy stream.
        Fd file(open(path_.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600));
        if (file.get() < 0 || !write_all(file.get(), contents_locked()) || fchown(file.get(), owner_, owner_) != 0) {
            disable_save_ = true;
            return;
        }
        writer_ = std::move(file);
    } else if (!write_all(writer_.get(), data)) {
        disable_save_ = true;
    }
}
void ConsoleLog::clear() {
    std::lock_guard lock(mutex_);
    head_ = size_ = 0;
    disable_save_ = false;
    writer_ = Fd();
    unlink(path_.c_str());
}
void ConsoleLog::close() { std::lock_guard lock(mutex_); writer_ = Fd(); }
void ConsoleLog::set_persistent(bool enabled) {
    std::lock_guard lock(mutex_);
    persistent_ = enabled;
    if (!enabled) writer_ = Fd();
}
std::string ConsoleLog::contents() const { std::lock_guard lock(mutex_); return contents_locked(); }
size_t ConsoleLog::size() const { std::lock_guard lock(mutex_); return size_; }
uint64_t ConsoleLog::mark() const { std::lock_guard lock(mutex_); return appended_; }
std::string ConsoleLog::since(uint64_t mark) const {
    std::lock_guard lock(mutex_);
    if (appended_ <= mark) return {};
    const auto count = appended_ - mark;
    auto all = contents_locked();
    if (count >= all.size()) return all;
    return all.substr(all.size() - static_cast<size_t>(count));
}
std::string url_encode_bytes(std::string_view data) {
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(data.size() * 3);
    for (const auto c : data) {
        const auto b = static_cast<unsigned char>(c);
        result += '%'; result += hex[b >> 4]; result += hex[b & 15];
    }
    return result;
}
std::string console_log_path(const std::string& cache, const std::string& vm_id, const std::string& stream) {
    return cache + "/console_" + vm_id + "_" + stream + ".log";
}
}
