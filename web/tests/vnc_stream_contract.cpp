// SPDX-License-Identifier: GPL-3.0-or-later
#include "vm/vnc_stream.h"
#include "services/context.h"
#include <chrono>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace droidvm;
namespace {
void require(bool value) { if (!value) throw std::runtime_error("VNC stream contract failed"); }
template<class Function> void error(ErrorCode code, Function operation) {
    try { operation(); }
    catch (const ServiceError& actual) { require(actual.code() == code); return; }
    throw std::runtime_error("VNC stream accepted invalid operation");
}
template<class Function> void until(Function condition) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!condition()) {
        require(std::chrono::steady_clock::now() < deadline);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}
#ifdef _WIN32
using Socket = SOCKET;
constexpr Socket invalid_socket = INVALID_SOCKET;
using Length = int;
void close_socket(Socket socket) { closesocket(socket); }
void nonblock(Socket socket) { u_long value = 1; require(ioctlsocket(socket, FIONBIO, &value) == 0); }
#else
using Socket = int;
constexpr Socket invalid_socket = -1;
using Length = socklen_t;
void close_socket(Socket socket) { ::close(socket); }
void nonblock(Socket socket) { require(fcntl(socket, F_SETFL, O_NONBLOCK) == 0); }
#endif
struct OwnedSocket {
    Socket value = invalid_socket;
    ~OwnedSocket() { if (value != invalid_socket) close_socket(value); }
};
struct Server {
    OwnedSocket listener;
    uint16_t port = 0;
    Server() {
        (void)vm::local_vnc_address("127.0.0.1"); // Initializes Winsock on Windows.
        listener.value = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        require(listener.value != invalid_socket);
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        require(bind(listener.value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
        require(listen(listener.value, 32) == 0);
        Length size = sizeof(address);
        require(getsockname(listener.value, reinterpret_cast<sockaddr*>(&address), &size) == 0);
        port = ntohs(address.sin_port); nonblock(listener.value);
    }
    Socket accept_peer() {
        Socket peer = invalid_socket;
        until([&] { peer = accept(listener.value, nullptr, nullptr); return peer != invalid_socket; });
        nonblock(peer);
        return peer;
    }
};
void local_stream_and_revocation() {
    require(vm::local_vnc_address("") == "127.0.0.1");
    require(vm::local_vnc_address("0.0.0.0") == "127.0.0.1");
    require(vm::local_vnc_address("::") == "::1");
    for (const auto* address : {"localhost", "198.51.100.251", "2001:db8::251", "127.0.0.1:5900"})
        error(ErrorCode::invalid_argument, [&] { (void)vm::local_vnc_address(address); });
    Server server;
    bool current = true;
    size_t guards = 0;
    vm::VncStream stream("127.0.0.1", server.port, [&](const auto& operation) {
        ++guards;
        if (!current) throw ServiceError(ErrorCode::conflict, "Runtime changed");
        operation();
    });
    OwnedSocket peer{server.accept_peer()};
    until([&] { return stream.connected(); });
    require(stream.read().empty());
    const std::string incoming("RFB\0pixels", 10);
    require(send(peer.value, incoming.data(), static_cast<int>(incoming.size()), 0) == static_cast<int>(incoming.size()));
    std::string received;
    until([&] { received += stream.read(3); return received.size() == incoming.size(); });
    require(received == incoming);
    const std::string input("key\0pointer", 11);
    size_t accepted = 0;
    until([&] { accepted += stream.write(std::string_view(input).substr(accepted)); return accepted == input.size(); });
    received.clear();
    until([&] {
        char bytes[32]; const auto count = recv(peer.value, bytes, sizeof(bytes), 0);
        if (count > 0) received.append(bytes, static_cast<size_t>(count));
        return received.size() == input.size();
    });
    require(received == input && guards >= 5);
    error(ErrorCode::invalid_argument, [&] { stream.read(vm::VncStream::chunk_limit + 1); });
    current = false;
    error(ErrorCode::conflict, [&] { stream.write("must not reach peer"); });
    until([&] { char byte; return recv(peer.value, &byte, 1, 0) == 0; });
    stream.close(); // Idempotent after failed guarded I/O.
}
void quota_and_peer_close() {
    Server server;
    const auto guard = [](const auto& operation) { operation(); };
    std::vector<std::shared_ptr<vm::VncStream>> streams;
    std::vector<std::unique_ptr<OwnedSocket>> peers;
    for (size_t i = 0; i < vm::VncStream::connection_limit; ++i) {
        streams.push_back(std::make_shared<vm::VncStream>("127.0.0.1", server.port, guard));
        peers.push_back(std::make_unique<OwnedSocket>());
        peers.back()->value = server.accept_peer();
        until([&] { return streams.back()->connected(); });
    }
    error(ErrorCode::resource_exhausted, [&] { vm::VncStream excess("127.0.0.1", server.port, guard); });
    peers.front().reset();
    bool closed = false;
    until([&] {
        try { (void)streams.front()->read(); }
        catch (const ServiceError& actual) { require(actual.code() == ErrorCode::unavailable); closed = true; }
        return closed;
    });
    vm::VncStream replacement("127.0.0.1", server.port, guard); // EOF released the quota.
    replacement.close();
    for (const auto& stream : streams) stream->close();
}
}
int main() {
    try {
        local_stream_and_revocation(); std::cout << "PASS local binary stream and runtime revocation\n";
        quota_and_peer_close(); std::cout << "PASS global stream quota and EOF cleanup\n";
        return 0;
    } catch (const std::exception& failure) { std::cerr << failure.what() << '\n'; return 1; }
}
