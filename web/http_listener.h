// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "async_http.h"
#include <chrono>

namespace droidvm { class TaskService; }
namespace droidvm::web {
struct HttpListenConfig {
    std::string address = "127.0.0.1";
    uint16_t port = 0;
    size_t connections = 32;
    std::chrono::seconds request_timeout{15};
    // Mandatory source policy, supplied by the listener-plan owner. Called on
    // the network thread with the kernel peer address, never X-Forwarded-For.
    std::function<bool(std::string_view)> allow_peer;
    // Download progress resets this idle deadline; there is no total-file deadline.
    std::chrono::seconds stream_idle_timeout{30};
    std::function<bool(std::string_view peer, std::string_view local)> trusted_lan;
};

// Owns only its lws context/network thread. Domain work goes to the existing
// TaskService. The owner must keep workers and captured domain services alive
// until accepted work completes; stopping this listener never shuts them down.
class HttpListener {
public:
    // Validate the handshake before upgrade; return an owning per-connection
    // worker callback. Routes may provide events or a bidirectional terminal.
    using OpenEvents = std::function<AsyncHttp::Handle(const HttpRequest&)>;
    HttpListener(HttpListenConfig config, TaskService& workers, AsyncHttp::Handle handle, OpenEvents events = {});
    ~HttpListener();
    HttpListener(const HttpListener&) = delete;
    HttpListener& operator=(const HttpListener&) = delete;
    void start(); // Reports bind/startup errors synchronously. One start only.
    void stop();  // Joins only the network thread; safe to repeat.
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
