// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "common/fd.h"
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace droidvm::config {
// Process-local coordination, not an OS lock against external writers. Handles
// pin the admitted inodes; callers must still use them for actual file IO.
class DiskFileLeases {
    struct State;
public:
    struct Request { std::string path; bool write = false; };
    class Lease {
    public:
        ~Lease();
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        void verify() const;
        // Borrowed read-only descriptor, >= 3 and CLOEXEC. Keep this Lease alive
        // and explicitly preserve the descriptor when passing it to a child.
        // Use pread or reopen /proc/self/fd/N for an independent file offset.
        int read_fd(const std::string& path) const;
        // Owns an independent file offset on the admitted inode. Write access
        // requires a write lease; no create/truncate. Keep this Lease alive for
        // the entire IO lifetime, including children inheriting the returned FD.
        Fd open_file(const std::string& path, bool write = false) const;
        // After the caller has stopped all writers, fsync each admitted writable
        // inode through its retained descriptor. Read-only backing files are
        // only verified. Throws on changed paths or failed synchronization; this
        // does not replace guest filesystem unmount/sync or writer shutdown.
        void sync_writes() const;
    private:
        friend class DiskFileLeases;
        struct File { std::string path; Fd fd; bool write = false; };
        Lease(std::shared_ptr<State> state, std::map<std::string, bool> keys, std::vector<File> files);
        std::shared_ptr<State> state_;
        std::map<std::string, bool> keys_;
        std::vector<File> files_;
    };
    DiskFileLeases();
    // All-or-nothing and nonblocking. Conflicting use throws ServiceError(CONFLICT).
    std::shared_ptr<Lease> acquire(const std::vector<Request>& requests);
private:
    std::shared_ptr<State> state_;
};
}
