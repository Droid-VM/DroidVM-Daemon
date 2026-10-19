// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cerrno>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

namespace droidvm {
// Preserve the caller's signal mask and pre-existing pending SIGPIPE. A closed
// pipe reports EPIPE without changing process-wide signal disposition.
inline ssize_t pipe_write(int fd, const char* bytes, size_t size) {
    sigset_t block, previous, pending;
    sigemptyset(&block); sigaddset(&block, SIGPIPE);
    const int masked = pthread_sigmask(SIG_BLOCK, &block, &previous);
    if (masked) { errno = masked; return -1; }
    sigpending(&pending);
    const bool existed = sigismember(&pending, SIGPIPE);
    const auto count = write(fd, bytes, size);
    const int error = errno;
    if (count < 0 && error == EPIPE && !existed && !sigismember(&previous, SIGPIPE)) {
        timespec zero{};
        while (sigtimedwait(&block, nullptr, &zero) < 0 && errno == EINTR) {}
    }
    pthread_sigmask(SIG_SETMASK, &previous, nullptr);
    errno = error;
    return count;
}
}
