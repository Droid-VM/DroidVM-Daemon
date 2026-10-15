// SPDX-License-Identifier: GPL-3.0-or-later
#include "control_http.h"
#include "common/fd.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>

namespace droidvm::network {
namespace {
[[noreturn]] void fail(ControlFailure reason, const char* text) { throw ControlError(reason, text); }
bool alpha(unsigned char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
bool digit(unsigned char c) { return c >= '0' && c <= '9'; }
bool token_char(unsigned char c) {
    return alpha(c) || digit(c) || std::string_view("!#$%&'*+-.^_`|~").find(c) != std::string_view::npos;
}
std::string lower(std::string_view text) {
    std::string result(text);
    for (auto& c : result) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
    return result;
}
std::string_view trim(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1);
    return text;
}
size_t number(std::string_view text, unsigned base, size_t maximum) {
    if (text.empty()) fail(ControlFailure::protocol, "empty HTTP length");
    size_t value = 0;
    for (unsigned char c : text) {
        unsigned d = digit(c) ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 :
            c >= 'A' && c <= 'F' ? c - 'A' + 10 : 99;
        if (d >= base) fail(ControlFailure::protocol, "invalid HTTP length");
        if (d > maximum || value > (maximum - d) / base) fail(ControlFailure::limit, "HTTP body exceeds limit");
        value = value * base + d;
    }
    return value;
}
class Stream {
public:
    Stream(const std::string& path, const ControlOptions& options) : options_(options),
        deadline_(std::chrono::steady_clock::now() + options.timeout),
        fd_(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)) {
        checkpoint();
        if (fd_.get() < 0) fail(ControlFailure::io, "control socket creation failed");
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
        if (connect(fd_.get(), reinterpret_cast<sockaddr*>(&address),
                    offsetof(sockaddr_un, sun_path) + path.size() + 1) == 0) return;
        // Linux AF_UNIX EAGAIN means a full listen queue, not EINPROGRESS.
        // No transparent reconnect: all retries belong to the state machine.
        if (errno != EINPROGRESS) fail(ControlFailure::io, "control socket connect failed");
        wait(POLLOUT);
        int error = 0; socklen_t size = sizeof(error);
        if (getsockopt(fd_.get(), SOL_SOCKET, SO_ERROR, &error, &size) != 0 || error)
            fail(ControlFailure::io, "control socket connect failed");
    }
    void send(std::string_view bytes) {
        while (!bytes.empty()) {
            checkpoint();
            auto count = ::send(fd_.get(), bytes.data(), bytes.size(), MSG_NOSIGNAL);
            if (count > 0) bytes.remove_prefix(static_cast<size_t>(count));
            else if (count < 0 && errno == EINTR) continue;
            else if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) wait(POLLOUT);
            else fail(ControlFailure::io, "control socket write failed");
        }
    }
    std::string line(size_t& budget) {
        std::string result;
        for (;;) {
            const char c = byte();
            if (budget == 0) fail(ControlFailure::limit, "HTTP framing exceeds limit");
            --budget;
            if (c == '\r') {
                if (budget == 0) fail(ControlFailure::limit, "HTTP framing exceeds limit");
                --budget;
                if (byte() != '\n') fail(ControlFailure::protocol, "invalid HTTP line ending");
                return result;
            }
            if (c == '\n' || c == 0) fail(ControlFailure::protocol, "invalid HTTP line ending");
            if (result.size() == 8192) fail(ControlFailure::limit, "HTTP line exceeds limit");
            result += c;
        }
    }
    void append(std::string& body, size_t size) {
        if (size > ControlHttp::response_limit - body.size()) fail(ControlFailure::limit, "HTTP body exceeds limit");
        while (size) {
            if (!fill()) fail(ControlFailure::protocol, "incomplete HTTP body");
            const auto count = std::min(size, end_ - begin_);
            body.append(buffer_.data() + begin_, count);
            begin_ += count; size -= count;
        }
    }
    void until_eof(std::string& body) {
        while (fill()) append(body, end_ - begin_);
    }
    char byte() {
        if (!fill()) fail(ControlFailure::protocol, "incomplete HTTP response");
        return buffer_[begin_++];
    }
private:
    const ControlOptions& options_;
    std::chrono::steady_clock::time_point deadline_;
    Fd fd_;
    std::array<char, 4096> buffer_{};
    size_t begin_ = 0, end_ = 0;
    void checkpoint() const {
        if (options_.cancelled && options_.cancelled()) fail(ControlFailure::cancelled, "control request cancelled");
        if (std::chrono::steady_clock::now() >= deadline_) fail(ControlFailure::timeout, "control request timed out");
    }
    void wait(short events) const {
        for (;;) {
            checkpoint();
            const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(deadline_ - std::chrono::steady_clock::now()).count();
            pollfd fd{fd_.get(), events, 0};
            const int result = poll(&fd, 1, static_cast<int>(std::clamp<int64_t>(remaining, 1, 50)));
            if (result > 0) return; // read/write reports EOF, HUP and real errno
            if (result < 0 && errno != EINTR) fail(ControlFailure::io, "control socket poll failed");
        }
    }
    bool fill() {
        checkpoint();
        if (begin_ != end_) return true;
        for (;;) {
            checkpoint();
            auto count = recv(fd_.get(), buffer_.data(), buffer_.size(), 0);
            if (count > 0) { begin_ = 0; end_ = static_cast<size_t>(count); return true; }
            if (count == 0) return false;
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) wait(POLLIN);
            else fail(ControlFailure::io, "control socket read failed");
        }
    }
};
struct Headers { std::optional<size_t> length; bool chunked = false; };
Headers headers(Stream& stream, size_t& budget, bool trailer = false) {
    Headers result;
    for (;;) {
        const auto line = stream.line(budget);
        if (line.empty()) return result;
        const auto colon = line.find(':');
        if (colon == std::string::npos || colon == 0 ||
            !std::all_of(line.begin(), line.begin() + colon, token_char))
            fail(ControlFailure::protocol, "invalid HTTP header");
        const auto key = lower(std::string_view(line).substr(0, colon));
        const auto value = trim(std::string_view(line).substr(colon + 1));
        for (unsigned char c : value) if ((c < 32 && c != '\t') || c == 127)
            fail(ControlFailure::protocol, "invalid HTTP header value");
        if (trailer && (key == "content-length" || key == "transfer-encoding" || key == "connection" || key == "host"))
            fail(ControlFailure::protocol, "invalid HTTP trailer");
        if (key == "content-length") {
            if (result.length) fail(ControlFailure::protocol, "duplicate HTTP content length");
            result.length = number(value, 10, ControlHttp::response_limit);
        } else if (key == "transfer-encoding") {
            if (result.chunked || lower(value) != "chunked") fail(ControlFailure::protocol, "unsupported HTTP transfer encoding");
            result.chunked = true;
        } else if (key == "content-encoding" && lower(value) != "identity") {
            fail(ControlFailure::protocol, "unsupported HTTP content encoding");
        }
        if (result.length && result.chunked) fail(ControlFailure::protocol, "ambiguous HTTP framing");
    }
}
void extensions(std::string_view text) {
    while (!text.empty()) {
        if (text.front() != ';') fail(ControlFailure::protocol, "invalid HTTP chunk extension");
        text.remove_prefix(1); text = trim(text);
        size_t n = 0;
        while (n < text.size() && token_char(text[n])) ++n;
        if (!n) fail(ControlFailure::protocol, "invalid HTTP chunk extension");
        text.remove_prefix(n); text = trim(text);
        if (!text.empty() && text.front() == '=') {
            text.remove_prefix(1); text = trim(text);
            if (!text.empty() && text.front() == '"') {
                text.remove_prefix(1);
                bool closed = false;
                while (!text.empty()) {
                    unsigned char c = text.front(); text.remove_prefix(1);
                    if (c == '"') { closed = true; break; }
                    if (c == '\\') {
                        if (text.empty()) fail(ControlFailure::protocol, "invalid HTTP chunk extension");
                        c = text.front(); text.remove_prefix(1);
                    }
                    if ((c < 32 && c != '\t') || c == 127) fail(ControlFailure::protocol, "invalid HTTP chunk extension");
                }
                if (!closed) fail(ControlFailure::protocol, "invalid HTTP chunk extension");
            } else {
                n = 0;
                while (n < text.size() && token_char(text[n])) ++n;
                if (!n) fail(ControlFailure::protocol, "invalid HTTP chunk extension");
                text.remove_prefix(n);
            }
            text = trim(text);
        }
    }
}
}
ControlHttp::ControlHttp(std::string socket_path, std::string token) :
    socket_path_(std::move(socket_path)), token_(std::move(token)) {
    if (socket_path_.empty() || socket_path_[0] != '/' || socket_path_.size() >= sizeof(sockaddr_un::sun_path) ||
        socket_path_.find('\0') != std::string::npos)
        fail(ControlFailure::invalid_request, "invalid control socket path");
    if (token_.empty() || token_.size() > 256 || token_.front() == '=') fail(ControlFailure::invalid_request, "invalid control token");
    bool padding = false;
    for (unsigned char c : token_) {
        if (c == '=') { padding = true; continue; }
        if (padding || !(alpha(c) || digit(c) || std::string_view("-._~+/").find(c) != std::string_view::npos))
            fail(ControlFailure::invalid_request, "invalid control token");
    }
}
ControlResponse ControlHttp::request(HttpMethod method, std::string_view path,
        std::optional<std::string_view> body, ControlOptions options) const {
    const char* verb = nullptr;
    switch (method) {
        case HttpMethod::get: verb = "GET"; break;
        case HttpMethod::post: verb = "POST"; break;
        case HttpMethod::put: verb = "PUT"; break;
        case HttpMethod::remove: verb = "DELETE"; break;
    }
    if (!verb || path.empty() || path.front() != '/' || path.size() > 4096 ||
        options.timeout.count() <= 0 || options.timeout > std::chrono::seconds(60))
        fail(ControlFailure::invalid_request, "invalid control request");
    for (unsigned char c : path) if (c <= 32 || c >= 127 || c == '#' || c == '\\')
        fail(ControlFailure::invalid_request, "invalid control request path");
    if (body && body->size() > request_limit) fail(ControlFailure::limit, "HTTP request body exceeds limit");
    std::string request = std::string(verb) + " " + std::string(path) + " HTTP/1.1\r\nHost: gvswitch\r\nAuthorization: Bearer " +
        token_ + "\r\nConnection: close\r\n";
    if (body) request += "Content-Type: application/json\r\nContent-Length: " + std::to_string(body->size()) + "\r\n";
    else request += "Content-Length: 0\r\n";
    request += "\r\n";
    Stream stream(socket_path_, options);
    stream.send(request);
    if (body) stream.send(*body);
    size_t header_budget = header_limit, framing_budget = framing_limit;
    for (unsigned interim = 0;;) {
        const auto status = stream.line(header_budget);
        if (status.size() < 13 || (status.substr(0, 9) != "HTTP/1.1 " && status.substr(0, 9) != "HTTP/1.0 ") ||
            !digit(status[9]) || !digit(status[10]) || !digit(status[11]) || status[12] != ' ')
            fail(ControlFailure::protocol, "invalid HTTP status");
        for (unsigned char c : status) if ((c < 32 && c != '\t') || c == 127)
            fail(ControlFailure::protocol, "invalid HTTP status");
        const int code = (status[9] - '0') * 100 + (status[10] - '0') * 10 + status[11] - '0';
        if (code < 100 || code > 599 || code == 101) fail(ControlFailure::protocol, "unsupported HTTP status");
        const auto fields = headers(stream, header_budget);
        if (code < 200 || code == 204) {
            if (fields.length || fields.chunked) fail(ControlFailure::protocol, "unexpected HTTP body framing");
            if (code < 200) {
                if (++interim > 8) fail(ControlFailure::limit, "too many interim HTTP responses");
                continue;
            }
        }
        ControlResponse response{code, {}};
        if (code == 204 || code == 304) return response;
        if (fields.chunked) {
            for (;;) {
                const auto line = stream.line(framing_budget);
                const auto semicolon = line.find(';');
                const auto size = number(std::string_view(line).substr(0, semicolon), 16, response_limit - response.body.size());
                if (semicolon != std::string::npos) extensions(std::string_view(line).substr(semicolon));
                if (size == 0) { headers(stream, header_budget, true); break; }
                stream.append(response.body, size);
                if (!stream.line(framing_budget).empty()) fail(ControlFailure::protocol, "invalid HTTP chunk ending");
            }
        } else if (fields.length) stream.append(response.body, *fields.length);
        else stream.until_eof(response.body);
        return response;
    }
}
std::string ControlHttp::component(std::string_view value) {
    if (value.size() > 1024) fail(ControlFailure::invalid_request, "control path component exceeds limit");
    const char* hex = "0123456789ABCDEF";
    std::string result;
    for (unsigned char c : value) {
        if (alpha(c) || digit(c) || c == '-' || c == '_' || c == '.' || c == '~') result += c;
        else { result += '%'; result += hex[c >> 4]; result += hex[c & 15]; }
    }
    return result;
}
}
