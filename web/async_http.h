// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include <cstdint>
#include <memory>

namespace droidvm::web {
struct HttpQueueLimits {
    size_t pending = 16;
    size_t response_bytes = 4u << 20;
    size_t retained_bytes = 32u << 20;
};
struct HttpTicket {
    uint64_t connection = 0, generation = 0;
    bool operator==(const HttpTicket&) const = default;
};
namespace http_detail { struct Queue; struct Reservation; }

// Move-only completion keeps its payload reservation until the network owner
// finishes sending or discards it. Never copy the response into an unbounded
// socket queue or release this owner while the payload is still retained.
class HttpCompletion {
public:
    HttpCompletion(HttpCompletion&&) noexcept = default;
    HttpCompletion& operator=(HttpCompletion&& other) noexcept;
    HttpCompletion(const HttpCompletion&) = delete;
    HttpCompletion& operator=(const HttpCompletion&) = delete;
    HttpTicket ticket() const { return ticket_; }
    const HttpResponse& response() const { return response_; }
private:
    friend class AsyncHttp;
    HttpCompletion(HttpTicket ticket, HttpResponse response, std::shared_ptr<http_detail::Reservation> reservation);
    HttpTicket ticket_;
    std::shared_ptr<http_detail::Reservation> reservation_;
    HttpResponse response_;
};

// Mailbox between one network owner and an existing bounded worker scheduler.
// Contains no sockets, threads, local-admin identity, or worker shutdown calls.
class AsyncHttp {
public:
    using Work = std::function<void(bool discarded)>;
    // Same callback/discard contract as TaskService::post. A throwing post must
    // not retain or execute work; accepted work must eventually be called once.
    using Post = std::function<void(Work)>;
    using Handle = std::function<HttpResponse(const HttpRequest&)>;
    // Handle must OWN all web state it captures; shared domain services must
    // outlive accepted work, just as for existing TaskService::post callbacks.
    AsyncHttp(Post post, Handle handle, HttpQueueLimits limits = {});
    ~AsyncHttp();
    AsyncHttp(const AsyncHttp&) = delete;
    AsyncHttp& operator=(const AsyncHttp&) = delete;
    HttpTicket submit(uint64_t connection, HttpRequest request, Handle handle = {});
    void cancel(HttpTicket ticket);
    std::vector<HttpCompletion> drain();
    // Nonblocking: reject submissions, drop results and skip queued handlers.
    // Already-running handlers may finish; this does not roll back mutations.
    void stop();
private:
    Post post_;
    std::shared_ptr<http_detail::Queue> queue_;
};
}
