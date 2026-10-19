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
    if (path_.empty()) return;
    Fd file(open(path_.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
    if (file.get() < 0) return;
    char buffer[65536];
    for (;;) {
        const auto count = ::read(file.get(), buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        history_.append({buffer, static_cast<size_t>(count)});
    }
}
void ConsoleLog::append(std::string_view data) {
    std::lock_guard lock(mutex_);
    history_.append(data);
    appended_ += data.size();
    if (path_.empty() || disable_save_ || !persistent_) return;
    if (writer_.get() < 0) {
        // First write rewrites the copy from the whole buffer, as the legacy stream.
        Fd file(open(path_.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600));
        if (file.get() < 0 || !write_all(file.get(), history_.contents()) || fchown(file.get(), owner_, owner_) != 0) {
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
    history_.clear();
    disable_save_ = false;
    writer_ = Fd();
    if (!path_.empty()) unlink(path_.c_str());
}
void ConsoleLog::close() { std::lock_guard lock(mutex_); writer_ = Fd(); }
void ConsoleLog::set_persistent(bool enabled) {
    std::lock_guard lock(mutex_);
    persistent_ = enabled;
    if (!enabled) writer_ = Fd();
}
std::string ConsoleLog::contents() const { std::lock_guard lock(mutex_); return history_.contents(); }
size_t ConsoleLog::size() const { std::lock_guard lock(mutex_); return history_.size(); }
LogSlice ConsoleLog::read(const std::optional<LogCursor>& cursor, bool tail) const { std::lock_guard lock(mutex_); return history_.read(cursor, tail); }
std::optional<LogSlice> ConsoleLog::try_read(const std::optional<LogCursor>& cursor, bool tail) const {
    std::unique_lock lock(mutex_, std::try_to_lock);
    if (!lock.owns_lock()) return {};
    return history_.read(cursor, tail);
}
uint64_t ConsoleLog::mark() const { std::lock_guard lock(mutex_); return appended_; }
std::string ConsoleLog::since(uint64_t mark) const {
    std::lock_guard lock(mutex_);
    if (appended_ <= mark) return {};
    const auto count = appended_ - mark;
    auto all = history_.contents();
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
