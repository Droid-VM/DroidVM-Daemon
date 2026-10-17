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
    private:
        friend class DiskFileLeases;
        struct File { std::string path; Fd fd; };
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
