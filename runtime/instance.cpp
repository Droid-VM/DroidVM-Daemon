// SPDX-License-Identifier: GPL-3.0-or-later
#include "instance.h"
#include "child.h"
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <thread>

namespace droidvm {
namespace {
void require(bool success, const char* operation) {
    if (!success) throw std::runtime_error(std::string(operation) + ": " + strerror(errno));
}
void write_all(int fd, std::string_view value) {
    while (!value.empty()) {
        auto count = write(fd, value.data(), value.size());
        if (count < 0 && errno == EINTR) continue;
        require(count > 0, "write runtime file");
        value.remove_prefix(static_cast<size_t>(count));
    }
}
}
// Reuse Android's existing SHA-256 tool with argv and an already-open regular
// APK file. This is the installed APK hash, never the native binary's hash.
std::string apk_sha256(const std::string& path) {
    Fd apk(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    struct stat info{};
    require(apk.get() >= 0 && fstat(apk.get(), &info) == 0 && S_ISREG(info.st_mode), "open APK");
    ChildOptions options;
    options.argv = {"/system/bin/sha256sum"};
    options.stdio[0] = apk.get();
    auto result = Child(options).communicate({}, std::chrono::seconds(30), 256);
    const auto& hash = result.output;
    if (result.exit_code || result.timed_out || result.truncated || hash.size() < 65 || hash[64] != ' ' ||
        hash.substr(0, 64).find_first_not_of("0123456789abcdef") != std::string::npos)
        throw std::runtime_error("APK SHA-256 failed");
    return hash.substr(0, 64);
}

bool Instance::try_lock() {
    struct flock region{};
    region.l_type = F_WRLCK;
    region.l_whence = SEEK_SET;
    // POSIX record locks interoperate with FileChannel.tryLock(), unlike flock.
    if (fcntl(lock_.get(), F_SETLK, &region) == 0) return true;
    if (errno == EACCES || errno == EAGAIN) return false;
    require(false, "lock daemon");
    return false;
}
int Instance::lock_owner() const {
    struct flock region{};
    region.l_type = F_WRLCK;
    region.l_whence = SEEK_SET;
    require(fcntl(lock_.get(), F_GETLK, &region) == 0, "query lock owner");
    return region.l_type == F_UNLCK ? -1 : region.l_pid;
}
Instance::Instance(const std::string& directory, bool force) {
    directory_ = Fd(open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    require(directory_.get() >= 0, "open run directory");
    lock_ = Fd(openat(directory_.get(), "droidvmd.lock", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600));
    struct stat info{};
    require(lock_.get() >= 0 && fstat(lock_.get(), &info) == 0 && S_ISREG(info.st_mode) && info.st_nlink == 1,
            "open daemon lock");
    if (!try_lock()) {
        if (!force) throw std::runtime_error("another daemon owns the runtime lock");
        const int holder = lock_owner();
        // pidfd fixes the identity before rechecking the kernel lock. Never
        // signal a PID read from a stale or attacker-written discovery file.
        Fd process(holder > 1 ? static_cast<int>(syscall(SYS_pidfd_open, holder, 0)) : -1);
        if (process.get() < 0 || lock_owner() != holder) {
            if (!try_lock()) throw std::runtime_error("cannot safely identify the existing lock holder");
        } else {
            auto terminate = [&](int signal) {
                if (lock_owner() != holder) return;
                if (syscall(SYS_pidfd_send_signal, process.get(), signal, nullptr, 0) < 0 && errno != ESRCH)
                    require(false, "signal lock holder");
            };
            terminate(SIGINT);
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
            bool acquired = false;
            while (!(acquired = try_lock()) && std::chrono::steady_clock::now() < deadline)
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            if (!acquired) {
                terminate(SIGKILL);
                deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
                while (!(acquired = try_lock()) && std::chrono::steady_clock::now() < deadline)
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            if (!acquired) throw std::runtime_error("existing daemon did not release the runtime lock");
        }
    }
    owns_ = true;
    require(ftruncate(lock_.get(), 0) == 0, "truncate lock owner");
    write_all(lock_.get(), std::to_string(getpid()));
    require(fsync(lock_.get()) == 0, "sync lock owner");
}
Instance::~Instance() {
    if (owns_ && published_) {
        for (const char* name : {"droidvmd-port.txt", "droidvmd-token.txt", "droidvmd.pid"})
            unlinkat(directory_.get(), name, 0);
        fsync(directory_.get());
    }
    // Keep the lock inode. Unlinking it would let a second process lock a new
    // inode while an existing waiter still holds the previous one.
}
void Instance::publish(std::string_view name, std::string_view value) {
    const std::string target(name), temporary = "." + target + "." + random_id(false);
    Fd file(openat(directory_.get(), temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    require(file.get() >= 0, "create runtime file");
    try {
        write_all(file.get(), value);
        require(fsync(file.get()) == 0, "sync runtime file");
        require(renameat(directory_.get(), temporary.c_str(), directory_.get(), target.c_str()) == 0, "publish runtime file");
        require(fsync(directory_.get()) == 0, "sync run directory");
    } catch (...) {
        unlinkat(directory_.get(), temporary.c_str(), 0);
        throw;
    }
}
void Instance::publish_discovery(unsigned port, const std::string& token) {
    published_ = true;
    publish("droidvmd.pid", std::to_string(getpid()));
    publish("droidvmd-token.txt", token);
    publish("droidvmd-port.txt", std::to_string(port));
}
bool Instance::token_exists() const {
    struct stat info{};
    return fstatat(directory_.get(), "droidvmd-token.txt", &info, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(info.st_mode);
}
std::string Instance::read_token() const {
    Fd file(openat(directory_.get(), "droidvmd-token.txt", O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    require(file.get() >= 0, "read token file");
    char bytes[128];
    ssize_t count;
    do { count = read(file.get(), bytes, sizeof(bytes)); } while (count < 0 && errno == EINTR);
    require(count >= 0, "read token bytes");
    std::string value(bytes, static_cast<size_t>(count));
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    return value.substr(first, value.find_last_not_of(" \t\r\n") - first + 1);
}
}
