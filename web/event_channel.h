// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "async_http.h"
#include "services/tasks.h"

namespace droidvm::web {
// Each channel owns exactly one existing journal subscription. The transport
// serializes next() calls through its bounded worker mailbox, without a thread.
class EventChannel {
public:
    using Authorize = std::function<SessionView(const Json::Value&)>;
    EventChannel(TaskService& tasks, Authorize authorize);
    ~EventChannel();
    HttpResponse next(const HttpRequest& input);
private:
    TaskService& tasks_;
    Authorize authorize_;
    SessionView session_;
    std::string subscription_;
    EventCursor cursor_;
    bool initialized_ = false;
    std::chrono::steady_clock::time_point sent_{};
    void release() noexcept;
    HttpResponse advance(const HttpRequest& input);
    HttpResponse message(const char* type, const Json::Value& resources = Json::Value(Json::arrayValue));
};
}
