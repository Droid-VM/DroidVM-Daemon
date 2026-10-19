// SPDX-License-Identifier: GPL-3.0-or-later
#include "requests.h"
#include "common/wire.h"
#include <sys/eventfd.h>
#include <cerrno>

namespace droidvm {
namespace {
constexpr size_t max_pending = 64, max_reserved = 32u << 20;
Json::Value failure(ErrorCode code, const char* message) {
    Json::Value value;
    value["success"] = false;
    value["message"] = message;
    value["error"]["code"] = error_code_name(code);
    value["error"]["message"] = message;
    return value;
}
}
RequestQueue::RequestQueue(RequestDispatcher& dispatcher)
    : dispatcher_(dispatcher), ready_(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)) {
    if (ready_.get() < 0) throw std::runtime_error("create request completion event failed");
    done_.reserve(max_pending);
}
RequestQueue::~RequestQueue() {
    dispatcher_.stop_web(); // Stop admission before joining shared workers.
    // Callbacks refer to this queue and to services owned by main. Joining here
    // keeps both alive until all callbacks/discards have released their captures.
    dispatcher_.workers().shutdown();
}
void RequestQueue::submit(uint64_t client, const ClientSession& session, std::string command, Json::Value request, size_t input_bytes) {
    if (!session.caller.authorized) throw ServiceError(ErrorCode::unauthenticated, "client is not authorized to perform this action");
    if (input_bytes > (1u << 20)) throw ServiceError(ErrorCode::resource_exhausted, "Request exceeds the worker input limit");
    const size_t output_limit = command == "network_create" || command == "network_modify" ? 1024 : (2u << 20) - 5;
    const size_t reservation = input_bytes + output_limit + 5;
    {
        std::lock_guard lock(mutex_);
        auto found = clients_.find(client);
        if (pending_ >= max_pending || reservation > max_reserved - reserved_ || (found != clients_.end() && found->second >= 8))
            throw ServiceError(ErrorCode::resource_exhausted, "Request capacity exhausted");
        ++clients_[client];
        ++pending_;
        reserved_ += reservation;
    }
    try {
        // Authentication is captured when the request is accepted, never read
        // from a socket/session that may disappear or be reused by another peer.
        const CallContext caller{"local-admin", session.caller.authorized, true, true};
        dispatcher_.workers().post({"transport", true, true, true},
            [this, client, command = std::move(command), request = std::move(request), caller, reservation, output_limit](bool discarded) {
                std::string frame;
                try {
                    auto response = discarded ? failure(ErrorCode::unavailable, "Daemon is stopping") : dispatcher_.execute_background(caller, command, request);
                    response["type"] = "response";
                    response["request_id"] = request["request_id"];
                    try { frame = wire::frame(wire::stringify_bounded(response, output_limit), true); }
                    catch (...) {
                        response = failure(ErrorCode::resource_exhausted, "Response exceeds the connection output limit");
                        response["type"] = "response";
                        response["request_id"] = request["request_id"];
                        frame = wire::frame(wire::stringify_bounded(response, 1024), true);
                    }
                } catch (...) { /* An empty completion closes this exact connection. */ }
                {
                    std::lock_guard lock(mutex_);
                    // Reserved capacity covers all pending callbacks, including
                    // disconnected clients. No worker touches a client socket.
                    done_.push_back({client, std::move(frame), reservation});
                }
                const uint64_t one = 1;
                ssize_t count;
                do { count = write(ready_.get(), &one, sizeof(one)); } while (count < 0 && errno == EINTR);
            });
    } catch (...) {
        std::lock_guard lock(mutex_);
        --pending_; reserved_ -= reservation;
        if (--clients_.at(client) == 0) clients_.erase(client);
        throw;
    }
}
std::vector<RequestQueue::Completion> RequestQueue::drain() {
    uint64_t count;
    while (read(ready_.get(), &count, sizeof(count)) < 0 && errno == EINTR) {}
    std::lock_guard lock(mutex_);
    std::vector<Completion> result;
    result.reserve(max_pending);
    result.swap(done_);
    return result;
}
void RequestQueue::release(const Completion& item) {
    // Keep reservations while drained frames are still owned by the caller;
    // release only after moving to the bounded socket queue or discarding them.
    std::lock_guard lock(mutex_);
    --pending_; reserved_ -= item.reservation;
    if (--clients_.at(item.client) == 0) clients_.erase(item.client);
}
}
