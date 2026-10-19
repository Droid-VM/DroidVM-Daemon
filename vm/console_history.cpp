// SPDX-License-Identifier: GPL-3.0-or-later
#include "console_history.h"
#include "common/identity.h"
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace droidvm::vm {
ConsoleHistory::ConsoleHistory() : generation_(random_id(true)) {}
void ConsoleHistory::clear() {
    auto next = random_id(true);
    generation_ = std::move(next);
    head_ = size_ = 0; end_ = 0;
}
void ConsoleHistory::append(std::string_view data) {
    if (data.size() > std::numeric_limits<uint64_t>::max() - end_) clear();
    end_ += data.size();
    if (data.size() >= capacity) { data = data.substr(data.size() - capacity); head_ = 0; size_ = 0; }
    for (size_t offset = 0; offset < data.size();) {
        const auto tail = (head_ + size_) % capacity;
        const auto chunk = std::min(data.size() - offset, capacity - tail);
        std::copy_n(data.data() + offset, chunk, ring_.begin() + static_cast<std::ptrdiff_t>(tail));
        offset += chunk; size_ += chunk;
        if (size_ > capacity) { head_ = (head_ + size_ - capacity) % capacity; size_ = capacity; }
    }
}
std::string ConsoleHistory::copy(size_t offset, size_t count) const {
    std::string result(count, '\0');
    const auto begin = (head_ + offset) % capacity;
    const auto first = std::min(count, capacity - begin);
    std::copy_n(ring_.begin() + static_cast<std::ptrdiff_t>(begin), first, result.begin());
    std::copy_n(ring_.begin(), count - first, result.begin() + static_cast<std::ptrdiff_t>(first));
    return result;
}
std::string ConsoleHistory::contents() const { return copy(0, size_); }
LogSlice ConsoleHistory::read(const std::optional<LogCursor>& cursor, bool tail) const {
    if (cursor && tail) throw std::invalid_argument("Tail cannot include a cursor");
    LogSlice result;
    result.generation = generation_; result.end = end_; result.floor = end_ - size_;
    result.start = tail ? end_ - std::min(size_, chunk_bytes) : result.floor;
    if (cursor) {
        result.reset = cursor->generation != generation_ || cursor->offset < result.floor;
        if (!result.reset) {
            if (cursor->offset > end_) throw std::invalid_argument("Log cursor is ahead of history");
            result.start = cursor->offset;
        }
    }
    const auto count = static_cast<size_t>(std::min<uint64_t>(chunk_bytes, end_ - result.start));
    result.next = result.start + count;
    result.bytes = copy(static_cast<size_t>(result.start - result.floor), count);
    return result;
}
}
