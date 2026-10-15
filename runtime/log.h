// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "common/fd.h"
#include <sys/types.h>
#include <mutex>
#include <string_view>

namespace droidvm {
// Bounded, synchronous lifecycle logging. No logcat process or JVM dependency.
// Keep the inode: the existing Android log viewer holds a RandomAccessFile.
class RuntimeLog {
public:
    static constexpr size_t max_bytes = 1u << 20;
    static constexpr size_t max_message = 4096;
    RuntimeLog(int cache_directory, uid_t owner);
    void write(std::string_view level, std::string_view message) noexcept;
private:
    Fd file_;
    size_t size_ = 0;
    std::mutex mutex_;
};
}
