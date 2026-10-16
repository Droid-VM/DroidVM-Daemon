// SPDX-License-Identifier: GPL-3.0-or-later
#include "vm_ownership.h"
#include "common/fd.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>

namespace droidvm::config {
namespace {
constexpr std::string_view marker = "native-v1\n";
void require(bool ok, const char* operation) {
    if (!ok) throw std::runtime_error(std::string(operation) + ": " + strerror(errno));
}
void gate(int directory, uid_t owner, bool claim, const char* name) {
    Fd fd(openat(directory, name, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600));
    struct stat info{};
    require(fd.get() >= 0 && fstat(fd.get(), &info) == 0 && S_ISREG(info.st_mode) && info.st_nlink == 1,
        "open VM configuration ownership gate");
    struct flock region{};
    region.l_type = F_WRLCK;
    region.l_whence = SEEK_SET;
    // OFD locks conflict with FileChannel's POSIX locks but survive unrelated
    // closes in this process. No flock: it would not exclude Java file locks.
    require(fcntl(fd.get(), F_OFD_SETLK, &region) == 0, "lock VM configuration ownership gate");
    require(fstat(fd.get(), &info) == 0, "read locked VM configuration owner");
    require(fchown(fd.get(), owner, owner) == 0 && fchmod(fd.get(), 0600) == 0, "own VM configuration gate");
    if (!claim) {
        if (info.st_size != 0) throw std::runtime_error("VM configuration belongs to the native service; legacy startup refused");
        return;
    }
    char bytes[32];
    ssize_t count;
    do { count = pread(fd.get(), bytes, sizeof(bytes), 0); } while (count < 0 && errno == EINTR);
    require(count >= 0, "read VM configuration owner");
    // A crash during the small initial write may leave a prefix. Native can
    // finish that transition; Java rejects every nonempty marker, including it.
    if (info.st_size > static_cast<off_t>(marker.size()) ||
        std::string_view(bytes, static_cast<size_t>(count)) != marker.substr(0, static_cast<size_t>(count)))
        throw std::runtime_error("Unknown VM configuration owner; refusing takeover");
    size_t offset = static_cast<size_t>(count);
    while (offset < marker.size()) {
        auto written = pwrite(fd.get(), marker.data() + offset, marker.size() - offset, static_cast<off_t>(offset));
        if (written < 0 && errno == EINTR) continue;
        require(written > 0, "record native VM configuration ownership");
        offset += static_cast<size_t>(written);
    }
    require(fsync(fd.get()) == 0 && fsync(directory) == 0, "sync VM configuration ownership");
}
}
void claim_vm_config(int directory, uid_t owner) { gate(directory, owner, true, "vms.config-owner"); }
void require_legacy_vm_config(int directory, uid_t owner) { gate(directory, owner, false, "vms.config-owner"); }
void claim_network_config(int directory, uid_t owner) { gate(directory, owner, true, "networks.config-owner"); }
void require_legacy_network_config(int directory, uid_t owner) { gate(directory, owner, false, "networks.config-owner"); }
}
