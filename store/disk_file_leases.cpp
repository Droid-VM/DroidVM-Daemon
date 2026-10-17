// SPDX-License-Identifier: GPL-3.0-or-later
#include "disk_file_leases.h"
#include "services/context.h"
#include <cstdlib>
#include <fcntl.h>
#include <sys/stat.h>

namespace droidvm::config {
struct DiskFileLeases::State {
    struct Use { size_t readers = 0; bool writer = false; };
    std::mutex mutex;
    std::map<std::string, Use> uses;
};
DiskFileLeases::DiskFileLeases() : state_(std::make_shared<State>()) {}
DiskFileLeases::Lease::Lease(std::shared_ptr<State> state, std::map<std::string, bool> keys, std::vector<File> files)
    : state_(std::move(state)), keys_(std::move(keys)), files_(std::move(files)) {}
DiskFileLeases::Lease::~Lease() {
    if (!state_) return;
    std::lock_guard lock(state_->mutex);
    for (const auto& [key, write] : keys_) {
        auto found = state_->uses.find(key);
        if (found == state_->uses.end()) continue;
        if (write) found->second.writer = false; else --found->second.readers;
        if (!found->second.writer && !found->second.readers) state_->uses.erase(found);
    }
}
void DiskFileLeases::Lease::verify() const {
    for (const auto& file : files_) {
        struct stat held{}, current{};
        if (fstat(file.fd.get(), &held) != 0 || stat(file.path.c_str(), &current) != 0
                || !S_ISREG(current.st_mode) || held.st_dev != current.st_dev || held.st_ino != current.st_ino)
            throw ServiceError(ErrorCode::conflict, "Disk file changed after lease admission");
    }
}
std::shared_ptr<DiskFileLeases::Lease> DiskFileLeases::acquire(const std::vector<Request>& requests) {
    std::map<std::string, bool> paths, keys, inodes;
    for (const auto& request : requests) {
        if (request.path.empty() || request.path.front() != '/' || request.path.find('\0') != std::string::npos)
            throw ServiceError(ErrorCode::invalid_argument, "Absolute disk path required");
        paths[request.path] = paths[request.path] || request.write;
    }
    std::vector<Lease::File> files;
    for (const auto& [path, write] : paths) {
        Fd file(open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC));
        struct stat identity{};
        if (file.get() < 0 || fstat(file.get(), &identity) != 0 || !S_ISREG(identity.st_mode))
            throw ServiceError(ErrorCode::io_error, "Cannot open a regular disk file for lease admission");
        const auto inode = "inode:" + std::to_string(identity.st_dev) + ":" + std::to_string(identity.st_ino);
        const auto previous = inodes.find(inode);
        if (previous != inodes.end() && (write || previous->second))
            throw ServiceError(ErrorCode::conflict, "Writable VM slots alias the same disk file");
        inodes[inode] = write;
        keys[inode] = write;
        keys["path:" + path] = keys["path:" + path] || write;
        std::unique_ptr<char, decltype(&std::free)> resolved(realpath(path.c_str(), nullptr), &std::free);
        if (!resolved) throw ServiceError(ErrorCode::io_error, "Cannot resolve disk file path");
        const std::string canonical_key = "path:" + std::string(resolved.get());
        keys[canonical_key] = keys[canonical_key] || write;
        files.push_back({path, std::move(file)});
    }
    // Allocate before publishing any use so allocation failure cannot leak reservations.
    auto lease = std::shared_ptr<Lease>(new Lease({}, std::move(keys), std::move(files)));
    lease->verify();
    std::lock_guard lock(state_->mutex);
    auto next = state_->uses;
    for (const auto& [key, write] : lease->keys_) {
        auto& use = next[key];
        if (use.writer || (write && use.readers)) throw ServiceError(ErrorCode::conflict, "Disk file is in use");
        if (write) use.writer = true; else ++use.readers;
    }
    state_->uses.swap(next);
    lease->state_ = state_;
    lease->verify();
    return lease;
}
}
