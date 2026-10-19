// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include "vm_display_source.h"
#include <chrono>

namespace droidvm::web {
Json::Value vm_display_list(const VmDisplaySource&, const CallContext&, const std::string&);
// Serialized by the existing stream mailbox. CHECK performs only liveness
// validation while the network owner retains an outstanding output block.
class VmDisplayChannel {
public:
    using Authorize = std::function<SessionView(const Json::Value&)>;
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;
    VmDisplayChannel(VmDisplaySource, std::string epoch, Authorize, std::shared_ptr<void> quota, Now now = Clock::now);
    ~VmDisplayChannel();
    HttpResponse next(const HttpRequest&);
private:
    VmDisplaySource source_;
    std::string epoch_;
    Authorize authorize_;
    std::shared_ptr<void> quota_;
    Now now_;
    SessionView session_;
    std::optional<VmDisplayStream> stream_;
    vm::Observation expected_;
    std::string vm_, screen_, pending_;
    bool opened_ = false, ready_ = false, closed_ = false;
    Clock::time_point created_, opening_, stalled_;
    HttpResponse advance(const HttpRequest&);
    void authorize(const Json::Value&);
    void close() noexcept;
};
}
