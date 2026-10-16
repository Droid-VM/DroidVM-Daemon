// SPDX-License-Identifier: GPL-3.0-or-later
#include "legacy_events.h"
#include "common/wire.h"
#include <cerrno>
#include <stdexcept>
#include <sys/eventfd.h>
#include <unistd.h>

namespace droidvm {
LegacyEvents::LegacyEvents() : ready_(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)) {
    if (ready_.get() < 0) throw std::runtime_error("create legacy event notifier failed");
}
void LegacyEvents::publish(const Json::Value& data) {
    Json::Value event;
    event["type"] = "event";
    event["data"] = data;
    auto frame = wire::frame(wire::stringify(event), true);
    {
        std::lock_guard lock(mutex_);
        if (frame.size() > max_pending - bytes_) { ++dropped_; return; }
        bytes_ += frame.size();
        pending_.push_back(std::move(frame));
    }
    const uint64_t one = 1;
    while (write(ready_.get(), &one, sizeof(one)) < 0 && errno == EINTR) {}
}
std::vector<std::string> LegacyEvents::drain() {
    uint64_t count;
    while (read(ready_.get(), &count, sizeof(count)) < 0 && errno == EINTR) {}
    std::lock_guard lock(mutex_);
    std::vector<std::string> result(std::make_move_iterator(pending_.begin()), std::make_move_iterator(pending_.end()));
    pending_.clear(); bytes_ = 0;
    return result;
}
uint64_t LegacyEvents::dropped() const { std::lock_guard lock(mutex_); return dropped_; }
}
