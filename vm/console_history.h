// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace droidvm::vm {
struct LogCursor { std::string generation; uint64_t offset = 0; };
struct LogSlice {
    std::string generation, bytes;
    uint64_t floor = 0, start = 0, next = 0, end = 0;
    bool reset = false;
};
// ConsoleLog owns this one ring and protects every access with its existing
// mutex. No file, thread or second history store belongs to this value.
class ConsoleHistory {
public:
    static constexpr size_t capacity = 1u << 20, chunk_bytes = 64u << 10;
    ConsoleHistory();
    void append(std::string_view data);
    void clear();
    size_t size() const { return size_; }
    std::string contents() const;
    LogSlice read(const std::optional<LogCursor>& cursor, bool tail) const;
private:
    std::string generation_;
    std::vector<char> ring_ = std::vector<char>(capacity);
    size_t head_ = 0, size_ = 0;
    uint64_t end_ = 0;
    std::string copy(size_t offset, size_t count) const;
};
}
