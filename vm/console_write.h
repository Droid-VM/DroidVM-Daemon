// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "common/pipe_write.h"
#include "services/context.h"
#include <climits>
#include <fcntl.h>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>

namespace droidvm::vm {
inline constexpr size_t console_write_limit = 512;
static_assert(console_write_limit <= PIPE_BUF);

// Caller holds the runtime's state mutex for descriptor ownership and excludes
// legacy writers while pipe flags temporarily change. This is one write attempt:
// no poll, retry, or delayed input can reach a later VM lifecycle revision.
inline size_t bounded_console_write(int fd, std::string_view bytes) {
    if (bytes.empty() || bytes.size() > console_write_limit)
        throw ServiceError(ErrorCode::invalid_argument, "Console input must contain 1 to 512 bytes");
    auto count = send(fd, bytes.data(), bytes.size(), MSG_DONTWAIT | MSG_NOSIGNAL);
    if (count < 0 && errno == ENOTSOCK) {
        struct stat info{};
        if (fstat(fd, &info) < 0 || !S_ISFIFO(info.st_mode))
            throw ServiceError(ErrorCode::unavailable, "Console writer is not a pipe or socket");
        const int flags = fcntl(fd, F_GETFL);
        if (flags < 0 || (!(flags & O_NONBLOCK) && fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0))
            throw ServiceError(ErrorCode::unavailable, "Console writer could not become nonblocking");
        count = pipe_write(fd, bytes.data(), bytes.size());
        const int error = errno;
        if (!(flags & O_NONBLOCK) && fcntl(fd, F_SETFL, flags) < 0)
            throw ServiceError(ErrorCode::io_error, "Console writer flags could not be restored");
        errno = error;
    }
    if (count >= 0) return static_cast<size_t>(count);
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
    throw ServiceError(ErrorCode::unavailable, "Console writer is unavailable");
}
}
