// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <unistd.h>
#include <utility>

namespace droidvm {
class Fd {
public:
    explicit Fd(int fd = -1) : fd_(fd) {}
    ~Fd() { if (fd_ >= 0) close(fd_); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
    Fd& operator=(Fd&& other) noexcept {
        if (this != &other) { Fd old(std::exchange(fd_, std::exchange(other.fd_, -1))); }
        return *this;
    }
    int get() const { return fd_; }
private:
    int fd_;
};
}
