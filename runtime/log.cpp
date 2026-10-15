// SPDX-License-Identifier: GPL-3.0-or-later
#include "log.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <cerrno>
#include <cstdio>
#include <ctime>
#include <stdexcept>
#include <string>
#include <system_error>

namespace droidvm {
namespace {
void require(bool result, const char* operation) {
    if (!result) throw std::system_error(errno, std::generic_category(), operation);
}
void append(int fd, std::string_view value) {
    while (!value.empty()) {
        auto count = ::write(fd, value.data(), value.size());
        if (count < 0 && errno == EINTR) continue;
        require(count > 0, "write daemon log");
        value.remove_prefix(static_cast<size_t>(count));
    }
}
}
RuntimeLog::RuntimeLog(int directory, uid_t owner)
    : file_(openat(directory, "daemon.log", O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600)) {
    require(file_.get() >= 0, "open daemon log");
    struct stat info{};
    require(fstat(file_.get(), &info) == 0, "stat daemon log");
    if (!S_ISREG(info.st_mode) || info.st_nlink != 1)
        throw std::runtime_error("daemon log must be a regular file with one link");
    if (info.st_uid != owner && info.st_uid != geteuid())
        throw std::runtime_error("daemon log has an unexpected owner");
    require(fchown(file_.get(), owner, owner) == 0, "own daemon log");
    require(fchmod(file_.get(), 0600) == 0, "protect daemon log");
    // Retain prior startup/failure evidence, but never retain an oversized log.
    if (info.st_size < 0 || static_cast<uint64_t>(info.st_size) > max_bytes)
        require(ftruncate(file_.get(), 0) == 0, "bound daemon log");
    else size_ = static_cast<size_t>(info.st_size);
}
void RuntimeLog::write(std::string_view level, std::string_view message) noexcept {
    try {
        std::lock_guard guard(mutex_);
        if (file_.get() < 0) return;
        timespec now{};
        clock_gettime(CLOCK_REALTIME, &now);
        std::string line = std::to_string(now.tv_sec) + "." + std::to_string(now.tv_nsec / 1000000) + " ";
        line.append(level.substr(0, 16));
        line += " droidvmd: ";
        for (char ch : message.substr(0, max_message))
            line += static_cast<unsigned char>(ch) < 32 || ch == 127 ? ' ' : ch;
        if (message.size() > max_message) line += " [truncated]";
        line += '\n';
        if (size_ + line.size() > max_bytes) {
            require(ftruncate(file_.get(), 0) == 0, "truncate daemon log");
            constexpr std::string_view marker = "--- daemon log size limit reached; older records discarded ---\n";
            append(file_.get(), marker);
            size_ = marker.size();
        }
        append(file_.get(), line);
        size_ += line.size();
    } catch (...) {
        // Disk failures must not terminate VM/task control. Disable this sink;
        // avoid recursively logging an error or repeatedly blocking on failure.
        std::lock_guard guard(mutex_);
        file_ = Fd();
        std::fputs("droidvmd: persistent log write failed; logging disabled\n", stderr);
    }
}
}
