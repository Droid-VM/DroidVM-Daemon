// SPDX-License-Identifier: GPL-3.0-or-later
#include "http_listener.h"
#include "services/tasks.h"
#include <libwebsockets.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <cstring>
#include <deque>
#include <future>
#include <limits>
#include <map>
#include <set>
#include <thread>
#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#endif

namespace droidvm::web {
namespace {
constexpr size_t header_limit = 8192, body_limit = 4096, chunk_bytes = 16384;
constexpr size_t download_bytes = 256u << 10;
constexpr lws_usec_t tick_us = 50000;
HttpResponse failure(int status, const char* code) {
    return {status, {{"Content-Type", "application/json"}, {"Cache-Control", "no-store"}, {"X-Content-Type-Options", "nosniff"}},
        std::string("{\"error\":{\"code\":\"") + code + "\"}}"};
}
std::string lower(std::string text) {
    for (auto& c : text) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    return text;
}
struct HeaderReader {
    lws* socket;
    Headers fields;
    std::set<std::string> custom;
    size_t bytes = 0;
    bool failed = false;
    void add(std::string name, std::string value) {
        if (fields.size() >= 64 || name.size() > header_limit - bytes) { failed = true; return; }
        bytes += name.size();
        if (value.size() > header_limit - bytes) { failed = true; return; }
        bytes += value.size();
        fields.emplace_back(lower(std::move(name)), std::move(value));
    }
    static void unknown(const char* name, int length, void* opaque) noexcept {
        auto& self = *static_cast<HeaderReader*>(opaque);
        try {
            if (self.failed) return;
            if (length <= 1 || length > static_cast<int>(header_limit) || name[length - 1] != ':') { self.failed = true; return; }
            std::string key(name, static_cast<size_t>(length - 1));
            if (!self.custom.insert(lower(key)).second) { self.failed = true; return; }
            std::array<char, header_limit + 1> value{};
            const int copied = lws_hdr_custom_copy(self.socket, value.data(), static_cast<int>(value.size()), name, length);
            if (copied < 0) { self.failed = true; return; }
            self.add(std::move(key), std::string(value.data(), static_cast<size_t>(copied)));
        } catch (...) { self.failed = true; }
    }
    Headers read() {
        // Preserve fragments (including empty/duplicate fields); concatenating
        // Cookie would hide duplicate header lines from the API boundary.
        std::array<char, header_limit + 1> value{};
        for (int token = 0; token < WSI_TOKEN_COUNT; ++token) {
            const auto index = static_cast<lws_token_indexes>(token);
            const auto* raw_name = lws_token_to_string(index);
            if (!raw_name) continue;
            std::string name(reinterpret_cast<const char*>(raw_name));
            if (name.empty() || name.back() != ':') continue; // method/URI pseudo tokens
            name.pop_back();
            for (int fragment = 0;; ++fragment) {
                const int copied = lws_hdr_copy_fragment(socket, value.data(), static_cast<int>(value.size()), index, fragment);
                if (copied == -1) break;
                if (copied < 0) { failed = true; break; }
                add(name, std::string(value.data(), static_cast<size_t>(copied)));
                if (failed) break;
            }
            if (failed) break;
        }
        if (!failed && lws_hdr_custom_name_foreach(socket, unknown, this)) failed = true;
        if (failed) throw ServiceError(ErrorCode::invalid_argument, "Invalid headers");
        return std::move(fields);
    }
};
}
struct HttpListener::Impl {
    struct Connection {
        uint64_t id;
        lws* socket;
        HttpRequest input;
        std::optional<HttpTicket> ticket;
        std::optional<HttpCompletion> completion;
        std::optional<HttpResponse> local;
        std::optional<HttpTicket> download_ticket;
        std::optional<HttpCompletion> download_completion;
        uint64_t download_sent = 0;
        size_t expected = 0, sent = 0;
        bool headers_sent = false, close = false, head = false;
        bool websocket = false, subscribed = false, terminal = false, display = false;
        struct Frame { std::string body; bool binary = false; };
        std::deque<Frame> frames;
        size_t frame_bytes = 0;
        std::optional<HttpTicket> display_check;
        std::chrono::steady_clock::time_point next_check{};
        AsyncHttp::Handle events;
        std::chrono::steady_clock::time_point next_poll{};
        std::chrono::steady_clock::time_point deadline;
        const HttpResponse* response() const { return completion ? &completion->response() : local ? &*local : nullptr; }
    };
    struct Timer { lws_sorted_usec_list_t timer{}; Impl* owner; } timer{{}, this};
    HttpListenConfig config;
    AsyncHttp queue;
    AsyncHttp stream_queue;
    AsyncHttp download_queue;
    OpenEvents open_events;
    std::mutex context_mutex;
    lws_context* context = nullptr;
    std::thread thread;
    std::atomic<bool> stopping{false};
    bool started = false;
    bool ipv6 = false;
    uint64_t sequence = 0;
    std::map<lws*, std::unique_ptr<Connection>> connections;
    std::map<uint64_t, lws*> identities;
    lws_protocols protocols[5]{};

    Impl(HttpListenConfig next, TaskService& workers, AsyncHttp::Handle handle, OpenEvents events)
        : config(std::move(next)), queue([&workers](AsyncHttp::Work work) {
            // Scheduling permission is not the request's service identity.
            workers.post({"web-transport", true, true, false}, std::move(work));
        }, std::move(handle)), stream_queue([&workers](AsyncHttp::Work work) {
            workers.post({"web-events", true, true, false}, std::move(work));
        }, [](const HttpRequest&) { return failure(503, "unavailable"); }, {32, 128u << 10, 5u << 20}),
        download_queue([&workers](AsyncHttp::Work work) {
            workers.post({"web-download", true, true, false}, std::move(work));
        }, [](const HttpRequest&) { return failure(503, "unavailable"); }, {16, download_bytes + 512, 5u << 20}),
        open_events(std::move(events)) {
        if (!config.port || config.address.empty() || !config.allow_peer || !config.connections || config.connections > 64 ||
            config.request_timeout < std::chrono::seconds(1) || config.request_timeout > std::chrono::seconds(60)
            || config.stream_idle_timeout < std::chrono::seconds(1) || config.stream_idle_timeout > std::chrono::seconds(300))
            throw std::invalid_argument("Invalid HTTP listener configuration");
        // Only literal bind addresses. Interface selection / scopes belong to
        // the network policy owner; never resolve an untrusted host name here.
        unsigned char parsed[16];
        ipv6 = inet_pton(AF_INET6, config.address.c_str(), parsed) == 1;
        if (!ipv6 && inet_pton(AF_INET, config.address.c_str(), parsed) != 1)
            throw std::invalid_argument("HTTP listener requires a literal address");
        protocols[0].name = "http";
        protocols[0].callback = callback;
        protocols[0].rx_buffer_size = body_limit;
        if (open_events) {
            protocols[1].name = "droidvm.events.v1";
            protocols[1].callback = callback;
            protocols[1].rx_buffer_size = body_limit;
            protocols[1].tx_packet_size = chunk_bytes;
            protocols[2].name = "droidvm.terminal.v1";
            protocols[2].callback = callback;
            protocols[2].rx_buffer_size = body_limit;
            protocols[2].tx_packet_size = chunk_bytes;
            protocols[3].name = "droidvm.display.v1";
            protocols[3].callback = callback;
            protocols[3].rx_buffer_size = 64u << 10;
            protocols[3].tx_packet_size = chunk_bytes;
        }
    }
    void remove(lws* socket) {
        const auto found = connections.find(socket);
        if (found == connections.end()) return;
        if (found->second->ticket) (found->second->websocket ? stream_queue : queue).cancel(*found->second->ticket);
        if (found->second->download_ticket) download_queue.cancel(*found->second->download_ticket);
        if (found->second->display_check) stream_queue.cancel(*found->second->display_check);
        identities.erase(found->second->id);
        connections.erase(found);
    }
    void reject(Connection& connection, int status, const char* code) {
        connection.local = failure(status, code);
        connection.close = true;
        lws_rx_flow_control(connection.socket, 1);
        lws_callback_on_writable(connection.socket);
    }
    void submit(Connection& connection) {
        if (connection.ticket || connection.response()) return;
        try { connection.ticket = queue.submit(connection.id, std::move(connection.input)); }
        catch (const ServiceError& error) {
            reject(connection, error.code() == ErrorCode::resource_exhausted ? 429 : 503,
                error.code() == ErrorCode::resource_exhausted ? "resource_exhausted" : "unavailable");
        }
        if (!connection.response()) lws_rx_flow_control(connection.socket, 0);
    }
    int begin(lws* socket, bool websocket = false) {
        if (stopping || connections.contains(socket) || connections.size() >= config.connections || sequence == std::numeric_limits<uint64_t>::max()) return -1;
        char peer[128]{};
        if (!lws_get_peer_simple(socket, peer, sizeof(peer)) || !config.allow_peer(peer)) return -1;
        auto item = std::make_unique<Connection>();
        if (config.trusted_lan) {
            sockaddr_storage local_address{};
#ifdef _WIN32
            int length = sizeof(local_address);
#else
            socklen_t length = sizeof(local_address);
#endif
            char local[128]{};
            if (getsockname(lws_get_socket_fd(socket), reinterpret_cast<sockaddr*>(&local_address), &length) == 0 &&
                    getnameinfo(reinterpret_cast<sockaddr*>(&local_address), length, local, sizeof(local), nullptr, 0, NI_NUMERICHOST) == 0)
                item->input.trusted_lan = config.trusted_lan(peer, local);
        }
        item->id = ++sequence; item->socket = socket;
        item->deadline = std::chrono::steady_clock::now() + config.request_timeout;
        auto& connection = *item;
        connection.websocket = websocket;
        identities.emplace(item->id, socket);
        connections.emplace(socket, std::move(item));
        char* uri = nullptr; int uri_size = 0;
        const int method = lws_http_get_uri_and_method(socket, &uri, &uri_size);
        constexpr const char* methods[] = {"GET", "POST", "OPTIONS", "PUT", "PATCH", "DELETE", "CONNECT", "HEAD"};
        if (method < 0 || static_cast<size_t>(method) >= std::size(methods) || !uri || uri_size <= 0 || uri_size > 2048) {
            reject(connection, 400, "invalid_argument"); return 0;
        }
        connection.input.method = methods[method];
        connection.head = method == LWSHUMETH_HEAD;
        connection.input.path.assign(uri, static_cast<size_t>(uri_size));
        // API credentials and options are never accepted in URL arguments.
        char query[1];
        if (lws_hdr_copy_fragment(socket, query, 1, WSI_TOKEN_HTTP_URI_ARGS, 0) != -1) {
            reject(connection, 400, "invalid_argument"); return 0;
        }
        try { connection.input.headers = HeaderReader{socket, {}, {}, 0, false}.read(); }
        catch (...) { reject(connection, 400, "invalid_argument"); return 0; }
        bool has_length = false;
        for (const auto& [name, value] : connection.input.headers) {
            if (name == "transfer-encoding" || name == "expect") { reject(connection, 400, "invalid_argument"); return 0; }
            if (name != "content-length") continue;
            if (has_length || value.empty()) { reject(connection, 400, "invalid_argument"); return 0; }
            has_length = true;
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(), connection.expected);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) { reject(connection, 400, "invalid_argument"); return 0; }
        }
        if (connection.expected > HttpApi::request_limit(connection.input.path)) { reject(connection, 413, "payload_too_large"); return 0; }
        if (connection.input.method != "POST" && connection.expected) { reject(connection, 400, "invalid_argument"); return 0; }
        if (websocket) {
            connection.display = connection.input.path == "/api/v1/display";
            connection.terminal = connection.input.path == "/api/v1/terminal"
                || connection.input.path == "/api/v1/agent-rescue-terminal";
            if (connection.input.method != "GET" || (!connection.display && !connection.terminal && connection.input.path != "/api/v1/events") || connection.expected) return -1;
            size_t protocols_found = 0;
            for (const auto& [name, value] : connection.input.headers) if (name == "sec-websocket-protocol") {
                if (++protocols_found != 1 || value != (connection.display ? "droidvm.display.v1" : connection.terminal ? "droidvm.terminal.v1" : "droidvm.events.v1")) return -1;
            }
            if (protocols_found != 1 || !open_events) return -1;
            connection.events = open_events(connection.input);
            if (!connection.events) return -1;
        } else if (!connection.expected) submit(connection);
        return 0;
    }
    void poll_stream(Connection& connection) {
        HttpRequest input;
        if (connection.display) input.path = "/api/v1/display";
        if (!connection.frames.empty()) {
            input.body = std::move(connection.frames.front().body); input.binary = connection.frames.front().binary;
            connection.frame_bytes -= input.body.size(); connection.frames.pop_front();
            // RFB is a byte stream: coalesce adjacent binary messages so high
            // frequency pointer events do not require a worker job each.
            while (connection.display && input.binary && !connection.frames.empty() && connection.frames.front().binary
                && connection.frames.front().body.size() <= (64u << 10) - input.body.size()) {
                connection.frame_bytes -= connection.frames.front().body.size(); input.body += connection.frames.front().body; connection.frames.pop_front();
            }
        }
        connection.ticket = stream_queue.submit(connection.id, std::move(input), connection.events);
        connection.deadline = std::chrono::steady_clock::now() + config.request_timeout;
    }
    int stream_writable(Connection& connection) {
        const auto* response = connection.response();
        if (!response) return 0;
        if (response->status != 200 || response->body.empty()) {
            const auto reason = response->status == 401 || response->status == 403 ? LWS_CLOSE_STATUS_POLICY_VIOLATION :
                response->status == 400 ? LWS_CLOSE_STATUS_PROTOCOL_ERR : LWS_CLOSE_STATUS_UNEXPECTED_CONDITION;
            lws_close_reason(connection.socket, reason, nullptr, 0);
            return -1;
        }
        std::array<unsigned char, LWS_PRE + chunk_bytes> buffer{};
        const size_t count = std::min(chunk_bytes, response->body.size() - connection.sent);
        std::memcpy(buffer.data() + LWS_PRE, response->body.data() + connection.sent, count);
        const bool final = connection.sent + count == response->body.size();
        const auto flags = static_cast<lws_write_protocol>((connection.sent ? LWS_WRITE_CONTINUATION : response->binary ? LWS_WRITE_BINARY : LWS_WRITE_TEXT) |
            (final ? 0 : LWS_WRITE_NO_FIN));
        if (lws_write(connection.socket, buffer.data() + LWS_PRE, count, flags) != static_cast<int>(count)) return -1;
        connection.sent += count;
        if (final) {
            connection.completion.reset(); connection.ticket.reset(); connection.sent = 0;
            connection.next_poll = std::chrono::steady_clock::now() + std::chrono::milliseconds(connection.display ? 0 : connection.terminal ? 20 : 500);
            connection.deadline = connection.next_poll + config.request_timeout;
        } else lws_callback_on_writable(connection.socket);
        return 0;
    }
    void download_progress(Connection& connection) {
        connection.deadline = std::chrono::steady_clock::now() + config.stream_idle_timeout;
        // The transport's monotonic idle deadline replaces libwebsockets' short
        // generic request timeout while this response is making progress.
        lws_set_timeout(connection.socket, NO_PENDING_TIMEOUT, 0);
    }
    void read_download(Connection& connection) {
        const auto* response = connection.response();
        if (!response || !response->stream || connection.download_ticket || connection.download_completion) return;
        const auto stream = response->stream;
        const auto offset = connection.download_sent;
        const auto count = static_cast<size_t>(std::min<uint64_t>(stream->chunk_bytes, stream->length - offset));
        if (!count) return;
        connection.download_ticket = download_queue.submit(connection.id, {}, [stream, offset, count](const HttpRequest&) {
            auto bytes = stream->read(offset, count);
            if (bytes.size() != count) throw ServiceError(ErrorCode::io_error, "Download source ended unexpectedly");
            return HttpResponse{200, {}, std::move(bytes)};
        });
    }
    int download_writable(Connection& connection, const HttpStreamBody& stream) {
        if (!connection.download_completion) { read_download(connection); return 0; }
        const auto& block = connection.download_completion->response().body;
        std::array<unsigned char, LWS_PRE + chunk_bytes> buffer{};
        const auto count = std::min(chunk_bytes, block.size() - connection.sent);
        std::memcpy(buffer.data() + LWS_PRE, block.data() + connection.sent, count);
        const bool final = connection.download_sent + count == stream.length;
        if (lws_write(connection.socket, buffer.data() + LWS_PRE, count, final ? LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP) != static_cast<int>(count)) return -1;
        connection.sent += count; connection.download_sent += count;
        download_progress(connection);
        if (connection.sent == block.size()) {
            connection.download_completion.reset(); connection.download_ticket.reset(); connection.sent = 0;
            if (final) {
                if (connection.close) return -1;
                return lws_http_transaction_completed(connection.socket) ? -1 : 0;
            }
            read_download(connection);
        } else lws_callback_on_writable(connection.socket);
        return 0;
    }
    int writable(Connection& connection) {
        const auto* response = connection.response();
        if (!response) return 0;
        if (!connection.headers_sent) {
            std::array<unsigned char, LWS_PRE + header_limit + 1024> buffer{};
            auto* start = buffer.data() + LWS_PRE; auto* cursor = start; auto* end = buffer.data() + buffer.size();
            if (lws_add_http_header_status(connection.socket, static_cast<unsigned int>(response->status), &cursor, end)) return -1;
            const auto length = response->stream ? response->stream->length : static_cast<uint64_t>(response->body.size());
            if (length > static_cast<uint64_t>(std::numeric_limits<lws_filepos_t>::max())) return -1;
            if (response->status != 204 && response->status != 304 &&
                lws_add_http_header_content_length(connection.socket, static_cast<lws_filepos_t>(length), &cursor, end)) return -1;
            for (const auto& [name, value] : response->headers) {
                const auto field = lower(name) + ":";
                if (lws_add_http_header_by_name(connection.socket, reinterpret_cast<const unsigned char*>(field.c_str()),
                    reinterpret_cast<const unsigned char*>(value.data()), static_cast<int>(value.size()), &cursor, end)) return -1;
            }
            if (connection.close && lws_add_http_header_by_name(connection.socket, reinterpret_cast<const unsigned char*>("connection:"),
                reinterpret_cast<const unsigned char*>("close"), 5, &cursor, end)) return -1;
            if (lws_finalize_write_http_header(connection.socket, start, &cursor, end)) return -1;
            connection.headers_sent = true;
            if (!length || connection.head) {
                if (connection.close) return -1;
                lws_rx_flow_control(connection.socket, 1);
                return lws_http_transaction_completed(connection.socket) ? -1 : 0;
            }
            if (response->stream) { download_progress(connection); read_download(connection); return 0; }
            lws_callback_on_writable(connection.socket); return 0;
        }
        if (response->stream) return download_writable(connection, *response->stream);
        std::array<unsigned char, LWS_PRE + chunk_bytes> buffer{};
        const size_t count = std::min(chunk_bytes, response->body.size() - connection.sent);
        std::memcpy(buffer.data() + LWS_PRE, response->body.data() + connection.sent, count);
        const bool final = connection.sent + count == response->body.size();
        if (lws_write(connection.socket, buffer.data() + LWS_PRE, count, final ? LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP) != static_cast<int>(count)) return -1;
        connection.sent += count;
        if (final) {
            if (connection.close) return -1;
            lws_rx_flow_control(connection.socket, 1);
            return lws_http_transaction_completed(connection.socket) ? -1 : 0;
        }
        lws_callback_on_writable(connection.socket); return 0;
    }
    static int callback(lws* socket, lws_callback_reasons reason, void* user, void* input, size_t length) noexcept {
        auto* self = static_cast<Impl*>(lws_context_user(lws_get_context(socket)));
        if (!self) return 0;
        try {
            if (reason == LWS_CALLBACK_HTTP_CONFIRM_UPGRADE) {
                if (!input || std::string_view(static_cast<const char*>(input)) != "websocket") return -1;
                if (self->begin(socket, true)) return -1;
                const auto& connection = *self->connections.at(socket);
                return connection.events && !connection.local ? 0 : -1;
            }
            if (reason == LWS_CALLBACK_HTTP) return self->begin(socket);
            if (reason == LWS_CALLBACK_CLOSED_HTTP || reason == LWS_CALLBACK_CLOSED || reason == LWS_CALLBACK_WSI_DESTROY) { self->remove(socket); return 0; }
            if (reason == LWS_CALLBACK_HTTP_DROP_PROTOCOL) {
                const auto found = self->connections.find(socket);
                if (found != self->connections.end() && !found->second->websocket) self->remove(socket);
                return 0;
            }
            const auto found = self->connections.find(socket);
            if (found == self->connections.end()) return lws_callback_http_dummy(socket, reason, user, input, length);
            auto& connection = *found->second;
            switch (reason) {
            case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
                return connection.websocket && connection.events ? 0 : -1;
            case LWS_CALLBACK_ESTABLISHED: return connection.websocket ? 0 : -1;
            case LWS_CALLBACK_RECEIVE:
                if (!connection.websocket || (connection.subscribed && !connection.terminal && !connection.display)) return -1;
                if (connection.display) {
                    const bool binary = lws_frame_is_binary(socket) != 0;
                    if ((!connection.subscribed && binary) || (connection.subscribed && !binary)) return -1;
                    if (!connection.input.body.empty() && connection.input.binary != binary) return -1;
                    connection.input.binary = binary;
                    const size_t maximum = binary ? 64u << 10 : 4096;
                    if (length > maximum - connection.input.body.size() || length > (256u << 10) - connection.frame_bytes - connection.input.body.size()) return -1;
                } else if (lws_frame_is_binary(socket) || length > 4096 - connection.input.body.size()) return -1;
                connection.input.body.append(static_cast<const char*>(input), length);
                if (lws_is_final_fragment(socket) && !lws_remaining_packet_payload(socket)) {
                    connection.subscribed = true;
                    if (connection.frames.size() >= (connection.display ? 128u : 4u) || connection.input.body.empty()) return -1;
                    connection.frame_bytes += connection.input.body.size();
                    connection.frames.push_back({std::exchange(connection.input.body, {}), connection.input.binary});
                    if (!connection.ticket && !connection.response() && !connection.display_check) self->poll_stream(connection);
                }
                return 0;
            case LWS_CALLBACK_SERVER_WRITEABLE: return self->stream_writable(connection);
            case LWS_CALLBACK_HTTP_BODY:
                if (!length) return 0;
                // A rejected request may already have sent body bytes. Discard
                // those bytes while the scheduled error response is flushed;
                // closing here would turn e.g. 413 into an unexplained reset.
                if (connection.local && connection.close) return 0;
                if (connection.ticket || connection.response() || length > connection.expected - connection.input.body.size()) return -1;
                connection.input.body.append(static_cast<const char*>(input), length); return 0;
            case LWS_CALLBACK_HTTP_BODY_COMPLETION:
                if (connection.ticket || connection.response()) return 0;
                if (connection.input.body.size() != connection.expected) return -1;
                self->submit(connection); return 0;
            case LWS_CALLBACK_HTTP_WRITEABLE: return self->writable(connection);
            default: return lws_callback_http_dummy(socket, reason, user, input, length);
            }
        } catch (...) { return -1; } // No C++ exception crosses a C callback.
    }
    static void tick(lws_sorted_usec_list_t* raw) noexcept {
        auto& self = *reinterpret_cast<Timer*>(raw)->owner;
        try {
            for (auto& done : self.queue.drain()) {
                const auto identity = self.identities.find(done.ticket().connection);
                if (identity == self.identities.end()) continue;
                auto& connection = *self.connections.at(identity->second);
                if (!connection.ticket || *connection.ticket != done.ticket()) continue;
                connection.completion.emplace(std::move(done));
                if (connection.response()->stream) self.download_progress(connection);
                // This lws h1 implementation suppresses POLLOUT as well as RX
                // while flow-controlled. Resume before scheduling the response.
                lws_rx_flow_control(connection.socket, 1);
                lws_callback_on_writable(connection.socket);
            }
            for (auto& done : self.stream_queue.drain()) {
                const auto identity = self.identities.find(done.ticket().connection);
                if (identity == self.identities.end()) continue;
                auto& connection = *self.connections.at(identity->second);
                if (connection.display_check && *connection.display_check == done.ticket()) {
                    connection.display_check.reset();
                    if (done.response().status != 204) {
                        lws_close_reason(connection.socket, done.response().status == 401 || done.response().status == 403 ? LWS_CLOSE_STATUS_POLICY_VIOLATION : LWS_CLOSE_STATUS_UNEXPECTED_CONDITION, nullptr, 0);
                        lws_set_timeout(connection.socket, PENDING_TIMEOUT_USER_OK, LWS_TO_KILL_ASYNC);
                    }
                    connection.next_check = std::chrono::steady_clock::now() + std::chrono::milliseconds(250);
                    continue;
                }
                if (!connection.websocket || !connection.ticket || *connection.ticket != done.ticket()) continue;
                if (done.response().status == 204) {
                    connection.ticket.reset();
                    connection.next_poll = std::chrono::steady_clock::now() + std::chrono::milliseconds(connection.display ? 0 : connection.terminal ? 100 : 500);
                    connection.deadline = connection.next_poll + self.config.request_timeout;
                } else {
                    connection.completion.emplace(std::move(done));
                    lws_callback_on_writable(connection.socket);
                }
            }
            for (auto& done : self.download_queue.drain()) {
                const auto identity = self.identities.find(done.ticket().connection);
                if (identity == self.identities.end()) continue;
                auto& connection = *self.connections.at(identity->second);
                if (!connection.download_ticket || *connection.download_ticket != done.ticket()) continue;
                if (done.response().status != 200 || done.response().stream || done.response().body.empty()) {
                    // Headers may already be visible. Never append a JSON error
                    // to the file or turn an unknown read into a transparent retry.
                    lws_set_timeout(connection.socket, PENDING_TIMEOUT_USER_OK, LWS_TO_KILL_ASYNC);
                    continue;
                }
                connection.download_completion.emplace(std::move(done));
                self.download_progress(connection);
                lws_callback_on_writable(connection.socket);
            }
            const auto now = std::chrono::steady_clock::now();
            for (const auto& [socket, connection] : self.connections) {
                if (now >= connection->deadline) lws_set_timeout(socket, PENDING_TIMEOUT_USER_OK, LWS_TO_KILL_ASYNC);
                else if (connection->display && connection->response() && !connection->display_check && now >= connection->next_check) {
                    try {
                        HttpRequest check; check.method = "CHECK"; check.path = "/api/v1/display";
                        connection->display_check = self.stream_queue.submit(connection->id, std::move(check), connection->events);
                    } catch (...) { lws_set_timeout(socket, PENDING_TIMEOUT_USER_OK, LWS_TO_KILL_ASYNC); }
                }
                else if (connection->websocket && connection->subscribed && !connection->ticket && !connection->response() && !connection->display_check &&
                         (!connection->frames.empty() || (connection->input.body.empty() && now >= connection->next_poll))) {
                    try { self.poll_stream(*connection); }
                    catch (...) { lws_set_timeout(socket, PENDING_TIMEOUT_USER_OK, LWS_TO_KILL_ASYNC); }
                }
            }
            if (!self.stopping) lws_sul_schedule(self.context, 0, &self.timer.timer, tick, tick_us);
        } catch (...) { self.stopping = true; lws_cancel_service(self.context); }
    }
    void run(std::promise<void> ready) noexcept {
        lws_context* owned = nullptr;
        bool reported = false;
        try {
            lws_context_creation_info info{};
            info.port = config.port; info.iface = config.address.c_str(); info.protocols = protocols; info.user = this;
            // Separate v4/v6 endpoints may share a port. Do not let an IPv6
            // wildcard also bind IPv4 or make IPv4 depend on kernel IPv6 support.
            info.options = ipv6 ? LWS_SERVER_OPTION_IPV6_V6ONLY_MODIFY | LWS_SERVER_OPTION_IPV6_V6ONLY_VALUE :
                LWS_SERVER_OPTION_DISABLE_IPV6;
            info.fd_limit_per_thread = static_cast<unsigned int>(config.connections + 8);
            info.max_http_header_data = header_limit; info.max_http_header_pool = static_cast<unsigned short>(config.connections);
            info.timeout_secs = static_cast<unsigned int>(config.request_timeout.count());
            owned = lws_create_context(&info);
            if (!owned) throw std::runtime_error("HTTP listener could not bind");
            { std::lock_guard lock(context_mutex); context = owned; }
            lws_sul_schedule(owned, 0, &timer.timer, tick, tick_us);
            ready.set_value(); reported = true;
            while (!stopping) if (lws_service(owned, 0) < 0) break;
        } catch (...) { if (!reported) ready.set_exception(std::current_exception()); }
        queue.stop();
        stream_queue.stop();
        download_queue.stop();
        { std::lock_guard lock(context_mutex); context = nullptr; }
        if (owned) { lws_sul_cancel(&timer.timer); lws_context_destroy(owned); }
        connections.clear(); identities.clear();
    }
    void stop() {
        stopping = true;
        { std::lock_guard lock(context_mutex); if (context) lws_cancel_service(context); }
        if (thread.joinable()) thread.join();
    }
};
HttpListener::HttpListener(HttpListenConfig config, TaskService& workers, AsyncHttp::Handle handle, OpenEvents events)
    : impl_(std::make_unique<Impl>(std::move(config), workers, std::move(handle), std::move(events))) {}
HttpListener::~HttpListener() { stop(); }
void HttpListener::start() {
    if (impl_->started || impl_->stopping) throw std::logic_error("HTTP listener already started or stopped");
    impl_->started = true;
    std::promise<void> ready; auto result = ready.get_future();
    impl_->thread = std::thread([state = impl_.get(), ready = std::move(ready)]() mutable { state->run(std::move(ready)); });
    try { result.get(); } catch (...) { impl_->stop(); throw; }
}
void HttpListener::stop() { impl_->stop(); }
}
