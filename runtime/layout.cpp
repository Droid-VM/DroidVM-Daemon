// SPDX-License-Identifier: GPL-3.0-or-later
#include "layout.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <cerrno>
#include <system_error>

namespace droidvm {
namespace {
void require(bool result, const char* operation) {
    if (!result) throw std::system_error(errno, std::generic_category(), operation);
}
Fd child_directory(int parent, const char* name, uid_t owner, bool& created) {
    created = mkdirat(parent, name, 0700) == 0;
    require(created || errno == EEXIST, "create runtime directory");
    Fd result(openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    require(result.get() >= 0, "open runtime directory");
    struct stat info{};
    require(fstat(result.get(), &info) == 0, "stat runtime directory");
    if (info.st_uid != owner && info.st_uid != geteuid())
        throw std::runtime_error("runtime directory has an unexpected owner");
    return result;
}
}
RuntimeLayout::RuntimeLayout(const std::string& directory)
    : data_(open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) {
    require(data_.get() >= 0, "open data directory");
    struct stat info{};
    require(fstat(data_.get(), &info) == 0, "stat data directory");
    owner_ = info.st_uid;
    bool run_created = false;
    run_ = child_directory(data_.get(), "run", owner_, run_created);
    cache_ = child_directory(data_.get(), "cache", owner_, cache_created_);
}
void RuntimeLayout::prepare_cache() {
    // Existing app cache permissions can include Android-specific group bits.
    // Preserve them; only the log itself must be private to the app UID.
    struct stat info{};
    require(fstat(cache_.get(), &info) == 0, "stat cache directory");
    if (info.st_uid != owner_ || cache_created_)
        require(fchown(cache_.get(), owner_, owner_) == 0, "own cache directory");
    if (cache_created_) {
        require(fchmod(cache_.get(), 0700) == 0, "protect cache directory");
    }
}
}
