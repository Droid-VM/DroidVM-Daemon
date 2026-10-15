// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <chrono>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace droidvm::network {
enum class HttpMethod { get, post, put, remove };
enum class ControlFailure { invalid_request, io, timeout, cancelled, protocol, limit };
class ControlError : public std::runtime_error {
public:
    ControlError(ControlFailure reason, const char* detail) : std::runtime_error(detail), reason(reason) {}
    const ControlFailure reason;
};
struct ControlResponse {
    int code;
    std::string body;
    bool success() const { return code >= 200 && code < 300; }
};
struct ControlOptions {
    // One activity-time budget for connect, write, headers and body together.
    std::chrono::milliseconds timeout{10000};
    std::function<bool()> cancelled;
};
// The helpers' existing HTTP/1.x protocol over filesystem Unix sockets only.
// One fresh connection per call; never retry mutations after an ambiguous
// failure. Callers must reconcile with helper state after timeout/disconnect.
// Run on a worker, not the daemon's epoll thread. No automatic redirects,
// decompression, credentials in errors, or unsolicited response logging.
class ControlHttp {
public:
    static constexpr size_t request_limit = 1u << 20, response_limit = 2u << 20;
    static constexpr size_t header_limit = 16u << 10, framing_limit = 64u << 10;
    ControlHttp(std::string socket_path, std::string token);
    ControlResponse request(HttpMethod method, std::string_view path,
        std::optional<std::string_view> body = {}, ControlOptions options = {}) const;
    // Encode a single opaque path component, including UTF-8, '%' and '/'.
    static std::string component(std::string_view value);
private:
    std::string socket_path_, token_;
};
}
