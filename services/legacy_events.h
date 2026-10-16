// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "common/fd.h"
#include <json/json.h>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace droidvm {
// Server.broadcastEvent: {"type":"event","data":...} to every connection,
// no subscription. Producers run on any thread; the event loop drains the
// framed payloads when fd() is readable. Unlike the legacy loop, only
// authenticated clients receive them, and a stalled loop drops new events
// beyond the pending budget instead of blocking producers.
class LegacyEvents {
public:
    static constexpr size_t max_pending = 4u << 20;
    LegacyEvents();
    void publish(const Json::Value& data);
    int fd() const { return ready_.get(); }
    std::vector<std::string> drain();
    uint64_t dropped() const;
private:
    Fd ready_;
    mutable std::mutex mutex_;
    std::deque<std::string> pending_;
    size_t bytes_ = 0;
    uint64_t dropped_ = 0;
};
}
