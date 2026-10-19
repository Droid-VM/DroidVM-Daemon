// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include "vm_terminal_source.h"
#include <chrono>

namespace droidvm::web {
// HttpApi adds its authenticated context to this bounded public projection.
Json::Value vm_terminal_list(const VmTerminalSource& source, const CallContext& caller, const std::string& id);

// The transport serializes next() calls on its existing bounded worker mailbox.
// One output chunk may be outstanding. ackOutput acknowledges client rendering
// before the read cursor advances; it never acknowledges/replays input bytes.
class VmTerminalChannel {
public:
    using Authorize = std::function<SessionView(const Json::Value&)>;
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;
    VmTerminalChannel(VmTerminalSource source, std::string daemon_epoch, Authorize authorize, Now now = Clock::now);
    HttpResponse next(const HttpRequest& input);
private:
    VmTerminalSource source_;
    std::string daemon_epoch_;
    Authorize authorize_;
    Now now_;
    SessionView session_;
    VmTerminalRead read_;
    std::optional<vm::LogCursor> awaiting_output_;
    uint64_t input_sequence_ = 0;
    bool initialized_ = false, emitted_output_ = false, closed_ = false;
    Clock::time_point sent_{};
    HttpResponse advance(const HttpRequest& input);
    HttpResponse message(Json::Value value);
    void authorize(const Json::Value& frame);
};
}
