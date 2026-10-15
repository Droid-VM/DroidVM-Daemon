// SPDX-License-Identifier: GPL-3.0-or-later
#include "server.h"
#include "common/fd.h"
#include "common/wire.h"
#include "runtime/instance.h"
#include "runtime/log.h"
#include "dispatcher.h"
#include "requests.h"
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <array>
#include <cctype>
#include <cerrno>
#include <deque>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <unordered_map>

namespace droidvm {
namespace {
constexpr size_t max_clients = 64, max_input = 32u << 20, max_output = 16u << 20;
constexpr size_t per_client_output = 2u << 20, io_budget = 64u << 10;
struct Client {
    Fd fd;
    ClientSession session{{random_id(true), false}, {}, 0};
    std::string incoming;
    uint32_t payload = 0;
    size_t queued = 0, sent = 0;
    std::deque<std::string> outgoing;
    bool eof = false;
    size_t pending = 0;
    explicit Client(int socket) : fd(socket) {}
};
void watch(int epoll, int operation, int fd, uint64_t id, uint32_t flags) {
    epoll_event event{};
    event.events = flags;
    event.data.u64 = id;
    if (epoll_ctl(epoll, operation, fd, &event)) throw std::runtime_error("epoll_ctl failed");
}
std::string request_id(const Json::Value& request) {
    if (!request["request_id"].isString()) return {};
    auto id = request["request_id"].asString();
    if (id.size() != 36) return {};
    for (size_t i = 0; i < id.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (id[i] != '-') return {}; }
        else if (!std::isxdigit(static_cast<unsigned char>(id[i]))) return {};
        id[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(id[i])));
    }
    return id;
}
}
int serve(Instance& instance, RequestDispatcher& service, const char* token, int signal_fd, RuntimeLog* log) {
    Fd epoll(epoll_create1(EPOLL_CLOEXEC));
    Fd listener(socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    if (epoll.get() < 0 || listener.get() < 0) throw std::runtime_error("create listener failed");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) || listen(listener.get(), 32))
        throw std::runtime_error("bind listener failed");
    socklen_t length = sizeof(address);
    if (getsockname(listener.get(), reinterpret_cast<sockaddr*>(&address), &length))
        throw std::runtime_error("read listener port failed");
    watch(epoll.get(), EPOLL_CTL_ADD, listener.get(), 1, EPOLLIN);
    watch(epoll.get(), EPOLL_CTL_ADD, signal_fd, 2, EPOLLIN);
    RequestQueue requests(service);
    watch(epoll.get(), EPOLL_CTL_ADD, requests.fd(), 3, EPOLLIN);
    instance.publish_discovery(ntohs(address.sin_port), token);
    std::cout << "droidvmd ready pid=" << getpid() << " port=" << ntohs(address.sin_port) << std::endl;
    if (log) log->write("INFO", "ready pid=" + std::to_string(getpid()) + " port=" + std::to_string(ntohs(address.sin_port)));
    std::unordered_map<uint64_t, std::unique_ptr<Client>> clients;
    uint64_t next_id = 4;
    size_t input_reserved = 0, output_reserved = 0;
    std::array<epoll_event, 32> events{};
    bool subscribed = false;
    while (true) {
        // Only subscribed connections need a bounded tail-poll interval. Signals
        // and network IO still wake epoll immediately; workers run no transport code.
        int count = epoll_wait(epoll.get(), events.data(), events.size(), subscribed ? 25 : -1);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) throw std::runtime_error("epoll_wait failed");
        for (int i = 0; i < count; ++i) {
            const auto id = events[i].data.u64;
            const auto flags = events[i].events;
            if (id == 2) {
                signalfd_siginfo signal{};
                if (read(signal_fd, &signal, sizeof(signal)) == sizeof(signal)) {
                    for (auto& [key, client] : clients) service.disconnected(client->session);
                    return 128 + signal.ssi_signo;
                }
                continue;
            }
            if (id == 1) {
                // Bound accept work so a connection flood cannot starve signals.
                for (unsigned accepted = 0; accepted < 16; ++accepted) {
                    Fd socket(accept4(listener.get(), nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC));
                    if (socket.get() < 0) break;
                    if (clients.size() >= max_clients) continue;
                    int enabled = 1;
                    setsockopt(socket.get(), IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
                    int send_buffer = 64 << 10;
                    setsockopt(socket.get(), SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer));
                    auto client = std::make_unique<Client>(-1);
                    client->fd = std::move(socket);
                    const uint64_t key = next_id++;
                    watch(epoll.get(), EPOLL_CTL_ADD, client->fd.get(), key, EPOLLIN | EPOLLRDHUP);
                    clients.emplace(key, std::move(client));
                }
                continue;
            }
            if (id == 3) {
                for (auto& completion : requests.drain()) {
                    auto found = clients.find(completion.client);
                    if (found == clients.end()) {
                        std::string().swap(completion.frame);
                        requests.release(completion);
                        continue;
                    }
                    auto& client = *found->second;
                    --client.pending;
                    auto& frame = completion.frame;
                    if (frame.empty() || frame.size() > per_client_output - client.queued || frame.size() > max_output - output_reserved) {
                        service.disconnected(client.session);
                        input_reserved -= client.payload;
                        output_reserved -= client.queued;
                        epoll_ctl(epoll.get(), EPOLL_CTL_DEL, client.fd.get(), nullptr);
                        clients.erase(found);
                        std::string().swap(frame);
                        requests.release(completion);
                        continue;
                    }
                    client.queued += frame.size();
                    output_reserved += frame.size();
                    client.outgoing.push_back(std::move(frame));
                    requests.release(completion);
                    watch(epoll.get(), EPOLL_CTL_MOD, client.fd.get(), completion.client,
                        (client.eof ? 0u : unsigned(EPOLLIN | EPOLLRDHUP)) | EPOLLOUT);
                }
                continue;
            }
            auto found = clients.find(id);
            if (found == clients.end()) continue;
            auto& client = *found->second;
            bool alive = !(flags & EPOLLERR);
            try {
                if (alive && (flags & (EPOLLIN | EPOLLRDHUP | EPOLLHUP)) && !client.eof) {
                    size_t budget = io_budget;
                    while (budget) {
                        const size_t target = client.payload ? client.payload : 4;
                        char buffer[16384];
                        const size_t need = std::min({target - client.incoming.size(), sizeof(buffer), budget});
                        const auto received = recv(client.fd.get(), buffer, need, 0);
                        if (received < 0 && errno == EINTR) continue;
                        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
                        if (received <= 0) { client.eof = true; break; }
                        budget -= static_cast<size_t>(received);
                        client.incoming.append(buffer, static_cast<size_t>(received));
                        if (client.incoming.size() != target) continue;
                        if (!client.payload) {
                            const auto size = wire::payload_size(client.incoming.data());
                            if (size > max_input - input_reserved) { alive = false; break; }
                            input_reserved += size;
                            client.payload = size;
                            client.incoming.clear();
                            continue;
                        }
                        Json::Value request;
                        try { request = wire::parse(client.incoming); } catch (const std::exception&) { /* Java continues after bad JSON. */ }
                        const auto input_bytes = client.payload;
                        input_reserved -= client.payload;
                        client.payload = 0;
                        std::string().swap(client.incoming);
                        if (!request.isObject() || request.get("type", Json::Value()) != "request" || !request["command"].isString()) continue;
                        const auto correlation = request_id(request);
                        if (correlation.empty()) continue;
                        Json::Value response;
                        auto command = request["command"].asString();
                        if (service.background(command)) {
                            try {
                                request["request_id"] = correlation;
                                requests.submit(id, client.session, command, std::move(request), input_bytes);
                                ++client.pending;
                                continue;
                            } catch (const ServiceError& error) {
                                response["success"] = false;
                                response["message"] = error.what();
                                response["error"]["code"] = error_code_name(error.code());
                                response["error"]["message"] = error.what();
                            }
                        } else response = service.execute(client.session, command, request);
                        response["type"] = "response";
                        response["request_id"] = correlation;
                        auto frame = wire::frame(wire::stringify(response), true);
                        if (frame.size() > per_client_output - client.queued || frame.size() > max_output - output_reserved) {
                            alive = false; break;
                        }
                        client.queued += frame.size();
                        output_reserved += frame.size();
                        client.outgoing.push_back(std::move(frame));
                    }
                }
                if (alive && !client.outgoing.empty()) {
                    size_t budget = io_budget;
                    while (budget && !client.outgoing.empty()) {
                        auto& front = client.outgoing.front();
                        const auto sent = send(client.fd.get(), front.data() + client.sent,
                            std::min(budget, front.size() - client.sent), MSG_NOSIGNAL);
                        if (sent < 0 && errno == EINTR) continue;
                        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
                        if (sent <= 0) { alive = false; break; }
                        budget -= static_cast<size_t>(sent);
                        client.sent += static_cast<size_t>(sent);
                        // Account allocated queue memory until the whole frame is freed.
                        if (client.sent == front.size()) {
                            client.queued -= front.size();
                            output_reserved -= front.size();
                            client.outgoing.pop_front();
                            client.sent = 0;
                        }
                    }
                }
                if (client.eof && client.outgoing.empty() && !client.pending) alive = false;
                if (alive) watch(epoll.get(), EPOLL_CTL_MOD, client.fd.get(), id,
                    (client.eof ? 0u : unsigned(EPOLLIN | EPOLLRDHUP)) | (client.outgoing.empty() ? 0u : unsigned(EPOLLOUT)));
            } catch (const std::exception&) { alive = false; }
            if (!alive) {
                service.disconnected(client.session);
                input_reserved -= client.payload;
                output_reserved -= client.queued;
                epoll_ctl(epoll.get(), EPOLL_CTL_DEL, client.fd.get(), nullptr);
                clients.erase(found);
            }
        }
        subscribed = false;
        for (auto it = clients.begin(); it != clients.end();) {
            auto& client = *it->second;
            bool alive = true;
            try {
                if (!client.eof && !client.session.subscription.empty()) {
                    if (auto value = service.events(client.session)) {
                        auto frame = wire::frame(wire::stringify(*value), true);
                        if (frame.size() > per_client_output - client.queued || frame.size() > max_output - output_reserved) alive = false;
                        else {
                            client.queued += frame.size();
                            output_reserved += frame.size();
                            client.outgoing.push_back(std::move(frame));
                            watch(epoll.get(), EPOLL_CTL_MOD, client.fd.get(), it->first, EPOLLIN | EPOLLRDHUP | EPOLLOUT);
                        }
                    }
                }
            } catch (const std::exception&) { alive = false; }
            if (alive) {
                subscribed |= !client.eof && !client.session.subscription.empty();
                ++it;
            } else {
                service.disconnected(client.session);
                input_reserved -= client.payload;
                output_reserved -= client.queued;
                epoll_ctl(epoll.get(), EPOLL_CTL_DEL, client.fd.get(), nullptr);
                it = clients.erase(it);
            }
        }
    }
}
}
