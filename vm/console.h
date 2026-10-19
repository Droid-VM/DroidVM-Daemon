// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "common/fd.h"
#include "console_history.h"
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <vector>

namespace droidvm::vm {
// daemon/console/ConsoleStream's history: the last 1 MiB of output plus a
// persistent copy at cache/console_<vm id>_<stream>.log, reloaded when the
// stream is created. Endpoints (pipes/sockets) belong to the VM runtime.
class ConsoleLog {
public:
    static constexpr size_t capacity = ConsoleHistory::capacity;
    // An empty path is always memory-only: no load, save or unlink, even after
    // set_persistent(true). Used by trusted private runtimes.
    ConsoleLog(std::string path, uid_t owner, bool persistent = true);
    void append(std::string_view data);
    void clear(); // also deletes the persistent copy
    void close(); // the next append rewrites the copy from the buffer
    void set_persistent(bool enabled);
    std::string contents() const;
    size_t size() const;
    uint64_t mark() const;
    std::string since(uint64_t mark) const;
    LogSlice read(const std::optional<LogCursor>& cursor, bool tail) const;
    // Interactive transport must not wait behind append's persistent file IO.
    std::optional<LogSlice> try_read(const std::optional<LogCursor>& cursor, bool tail) const;
    const std::string& path() const { return path_; }
private:
    std::string path_;
    uid_t owner_;
    mutable std::mutex mutex_;
    ConsoleHistory history_;
    uint64_t appended_ = 0;
    Fd writer_;
    bool disable_save_ = false, persistent_ = true;
};
// StringUtils.urlEncodeBytesAll: every byte as %XX, uppercase.
std::string url_encode_bytes(std::string_view data);
std::string console_log_path(const std::string& cache, const std::string& vm_id, const std::string& stream);
}
