// SPDX-License-Identifier: GPL-3.0-or-later
#include "helper_identity.h"
#include <algorithm>
#include <charconv>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sstream>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <system_error>

namespace droidvm {
namespace {
void require(bool ok, const char* operation) {
    if (!ok) throw std::system_error(errno, std::generic_category(), operation);
}
std::string read_text(const std::string& path) {
    Fd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    require(fd.get() >= 0, "open helper identity input");
    std::string result;
    char buffer[512];
    for (;;) {
        ssize_t count;
        do { count = read(fd.get(), buffer, sizeof(buffer)); } while (count < 0 && errno == EINTR);
        require(count >= 0, "read helper identity input");
        if (!count) return result;
        result.append(buffer, count);
        if (result.size() > 8192) throw std::runtime_error("helper identity input exceeds budget");
    }
}
uint64_t birth(pid_t pid) {
    const auto stat = read_text("/proc/" + std::to_string(pid) + "/stat");
    const auto end = stat.rfind(')');
    if (end == std::string::npos) throw std::runtime_error("invalid process birth record");
    std::istringstream fields(stat.substr(end + 1));
    std::string value;
    for (int field = 3; field <= 22; ++field)
        if (!(fields >> value)) throw std::runtime_error("truncated process birth record");
    uint64_t result = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size())
        throw std::runtime_error("invalid process birth time");
    return result;
}
std::string pid_namespace(struct stat& identity) {
    if (stat("/proc/self/ns/pid", &identity) == 0) return "pid";
    if (errno != ENOENT) require(false, "stat helper PID namespace");
    // Android kernels may omit CONFIG_PID_NS. A procfs superblock belongs to
    // one PID view; keep its identity rather than assuming a missing namespace
    // link means that any future PID view is acceptable.
    struct statfs filesystem{};
    require(statfs("/proc", &filesystem) == 0 && stat("/proc", &identity) == 0, "stat helper procfs identity");
    if (filesystem.f_type != 0x9fa0 || !S_ISDIR(identity.st_mode))
        throw std::runtime_error("helper identity requires procfs");
    return "proc";
}
bool dead(int pidfd, std::chrono::milliseconds wait = {}) {
    const auto until = std::chrono::steady_clock::now() + wait;
    for (;;) {
        pollfd fd{pidfd, POLLIN, 0};
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(until - std::chrono::steady_clock::now()).count();
        const auto result = poll(&fd, 1, static_cast<int>(std::max<int64_t>(remaining, 0)));
        if (result < 0 && errno == EINTR) continue;
        require(result >= 0 && !(fd.revents & POLLNVAL), "wait recovered helper");
        return result && (fd.revents & (POLLIN | POLLHUP));
    }
}
void signal_process(int pidfd, int number) {
    if (syscall(SYS_pidfd_send_signal, pidfd, number, nullptr, 0) < 0 && errno != ESRCH)
        require(false, "signal recovered helper");
}
}
HelperIdentity::HelperIdentity(int directory, uid_t owner, Observer observer)
    : directory_(fcntl(directory, F_DUPFD_CLOEXEC, 3)), owner_(owner), observer_(std::move(observer)) {
    require(directory_.get() >= 0, "hold helper identity directory");
}
void HelperIdentity::arm(ChildOptions& options) {
    if (armed_ || options.before_exec) throw std::logic_error("helper identity requires a fresh launch");
    armed_ = true;
    marker_ = Fd(openat(directory_.get(), "helper.identity", O_RDONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0400));
    require(marker_.get() >= 0, "create helper identity marker");
    // Ensure this is never one of the redirected stdio descriptors.
    if (marker_.get() < 3) marker_ = Fd(fcntl(marker_.get(), F_DUPFD_CLOEXEC, 3));
    require(marker_.get() >= 3 && fchown(marker_.get(), owner_, owner_) == 0 && fchmod(marker_.get(), 0400) == 0,
        "protect helper identity marker");
    require(fsync(marker_.get()) == 0 && fsync(directory_.get()) == 0, "sync helper identity marker");
    options.preserve_fds.push_back(marker_.get());
    options.before_exec = [this](pid_t pid) {
        struct stat marker{}, ns{};
        require(fstat(marker_.get(), &marker) == 0, "stat helper identity");
        Json::Value record;
        record["namespace_kind"] = pid_namespace(ns);
        record["schema"] = 1; record["pid"] = pid; record["birth"] = Json::UInt64(birth(pid));
        record["boot"] = read_text("/proc/sys/kernel/random/boot_id");
        record["namespace_device"] = Json::UInt64(ns.st_dev); record["namespace_inode"] = Json::UInt64(ns.st_ino);
        record["marker_device"] = Json::UInt64(marker.st_dev); record["marker_inode"] = Json::UInt64(marker.st_ino);
        record["fd"] = marker_.get();
        config::JsonFile(directory_.get(), "helper.json", owner_).save(record);
        if (observer_) observer_("identity_saved");
    };
}
void HelperIdentity::recover(int directory, uid_t owner, std::chrono::milliseconds grace) {
    if (grace.count() < 0 || grace > std::chrono::seconds(10)) throw std::invalid_argument("invalid helper recovery grace");
    const auto loaded = config::JsonFile(directory, "helper.json", owner).load();
    if (!loaded) return; // no exec can have passed the persistence gate
    const auto& record = loaded->value;
    if (record["schema"] != 1 || !record["pid"].isInt() || record["pid"].asInt() <= 1 ||
        !record["birth"].isUInt64() || !record["boot"].isString() ||
        !record["namespace_device"].isUInt64() || !record["namespace_inode"].isUInt64() ||
        (record["namespace_kind"] != "pid" && record["namespace_kind"] != "proc") ||
        !record["marker_device"].isUInt64() || !record["marker_inode"].isUInt64() ||
        !record["fd"].isInt() || record["fd"].asInt() < 3)
        throw std::runtime_error("invalid persistent helper identity");
    if (record["boot"] != read_text("/proc/sys/kernel/random/boot_id")) return;
    struct stat ns{};
    const auto namespace_kind = pid_namespace(ns);
    if (record["namespace_kind"] != namespace_kind || record["namespace_device"].asUInt64() != ns.st_dev ||
        record["namespace_inode"].asUInt64() != ns.st_ino)
        throw std::runtime_error("helper PID namespace differs; recovery refused");
    const auto pid = record["pid"].asInt();
    if (pid == getpid()) throw std::runtime_error("helper journal names current owner");
    Fd process(static_cast<int>(syscall(SYS_pidfd_open, pid, 0)));
    if (process.get() < 0 && errno == ESRCH) return;
    require(process.get() >= 0, "open recovery pidfd");
    if (dead(process.get())) return;
    try {
        if (birth(pid) != record["birth"].asUInt64()) return; // PID reused
        struct stat marker{}, inherited{};
        require(fstatat(directory, "helper.identity", &marker, AT_SYMLINK_NOFOLLOW) == 0, "stat persisted helper marker");
        const auto path = "/proc/" + std::to_string(pid) + "/fd/" + std::to_string(record["fd"].asInt());
        require(stat(path.c_str(), &inherited) == 0, "stat inherited helper marker");
        if (!S_ISREG(marker.st_mode) || marker.st_nlink != 1 || marker.st_uid != owner ||
            marker.st_dev != record["marker_device"].asUInt64() || marker.st_ino != record["marker_inode"].asUInt64() ||
            marker.st_dev != inherited.st_dev || marker.st_ino != inherited.st_ino)
            throw std::runtime_error("helper marker identity changed; recovery refused");
    } catch (...) { if (dead(process.get())) return; throw; }
    // All inspection occurs after pidfd_open. Even if /proc now belongs to a
    // reused PID, this handle can only signal the originally opened process.
    signal_process(process.get(), SIGTERM);
    if (!dead(process.get(), grace)) {
        signal_process(process.get(), SIGKILL);
        if (!dead(process.get(), std::chrono::seconds(3))) throw std::runtime_error("recovered helper did not exit");
    }
}
}
