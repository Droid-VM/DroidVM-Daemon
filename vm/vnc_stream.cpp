// SPDX-License-Identifier: GPL-3.0-or-later
#include "vnc_stream.h"
#include "services/context.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <vector>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <ifaddrs.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace droidvm::vm {
namespace {
[[noreturn]] void unavailable() { throw ServiceError(ErrorCode::unavailable, "Display connection unavailable"); }
[[noreturn]] void invalid_endpoint() { throw ServiceError(ErrorCode::invalid_argument, "Display requires a local numeric endpoint"); }
#ifdef _WIN32
using Socket = SOCKET;
constexpr Socket invalid_socket = INVALID_SOCKET;
void socket_init() {
    struct Winsock {
        Winsock() { WSADATA data{}; if (WSAStartup(MAKEWORD(2, 2), &data)) unavailable(); }
        ~Winsock() { WSACleanup(); }
    };
    static Winsock winsock;
    (void)winsock;
}
int socket_error() { return WSAGetLastError(); }
bool would_block(int error) { return error == WSAEWOULDBLOCK || error == WSAEINPROGRESS || error == WSAEALREADY; }
bool interrupted(int error) { return error == WSAEINTR; }
void close_socket(Socket socket) { closesocket(socket); }
using SocketLength = int;
#else
using Socket = int;
constexpr Socket invalid_socket = -1;
void socket_init() {}
int socket_error() { return errno; }
bool would_block(int error) { return error == EAGAIN || error == EWOULDBLOCK || error == EINPROGRESS || error == EALREADY; }
bool interrupted(int error) { return error == EINTR; }
void close_socket(Socket socket) { ::close(socket); }
using SocketLength = socklen_t;
#endif
bool matches(const sockaddr* address, int family, const void* bytes) {
    if (!address || address->sa_family != family) return false;
    return family == AF_INET
        ? std::memcmp(&reinterpret_cast<const sockaddr_in*>(address)->sin_addr, bytes, sizeof(in_addr)) == 0
        : std::memcmp(&reinterpret_cast<const sockaddr_in6*>(address)->sin6_addr, bytes, sizeof(in6_addr)) == 0;
}
bool assigned_address(int family, const void* bytes) {
#ifdef _WIN32
    ULONG size = 16u << 10;
    std::vector<unsigned char> storage(size);
    for (int attempt = 0; attempt < 2; ++attempt) {
        auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
        const auto result = GetAdaptersAddresses(AF_UNSPEC,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr, adapters, &size);
        if (result == ERROR_BUFFER_OVERFLOW && size <= (256u << 10)) { storage.resize(size); continue; }
        if (result != NO_ERROR) unavailable();
        size_t count = 0;
        for (auto* adapter = adapters; adapter; adapter = adapter->Next)
            for (auto* item = adapter->FirstUnicastAddress; item; item = item->Next) {
                if (++count > 4096) unavailable();
                if (matches(item->Address.lpSockaddr, family, bytes)) return true;
            }
        return false;
    }
    unavailable();
#else
    ifaddrs* raw = nullptr;
    if (getifaddrs(&raw)) unavailable();
    const std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> addresses(raw, freeifaddrs);
    size_t count = 0;
    for (auto* item = raw; item; item = item->ifa_next) {
        if (++count > 4096) unavailable();
        if (matches(item->ifa_addr, family, bytes)) return true;
    }
    return false;
#endif
}
std::atomic<size_t> active_connections{0};
void acquire_connection() {
    auto count = active_connections.load();
    do {
        if (count >= VncStream::connection_limit)
            throw ServiceError(ErrorCode::resource_exhausted, "Display connection limit reached");
    } while (!active_connections.compare_exchange_weak(count, count + 1));
}
}
std::string local_vnc_address(const std::string& input) {
    socket_init();
    if (input.empty() || input == "0.0.0.0") return "127.0.0.1";
    if (input == "::") return "::1";
    if (input.size() > 64 || input.find('\0') != std::string::npos) invalid_endpoint();
    in_addr v4{};
    if (inet_pton(AF_INET, input.c_str(), &v4) == 1) {
        if ((ntohl(v4.s_addr) >> 24) == 127 || assigned_address(AF_INET, &v4)) return input;
        invalid_endpoint();
    }
    in6_addr v6{};
    if (inet_pton(AF_INET6, input.c_str(), &v6) == 1) {
        if (IN6_IS_ADDR_UNSPECIFIED(&v6)) return "::1";
        if (IN6_IS_ADDR_LOOPBACK(&v6) || assigned_address(AF_INET6, &v6)) return input;
        invalid_endpoint();
    }
    invalid_endpoint();
}

struct VncStream::Impl {
    std::mutex mutex;
    Guard guard;
    Socket socket = invalid_socket;
    bool acquired = false, ready = false;
    const std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    explicit Impl(Guard value) : guard(std::move(value)) {}
    ~Impl() { release(); }
    void release() noexcept {
        if (socket != invalid_socket) { close_socket(socket); socket = invalid_socket; }
        if (acquired) { --active_connections; acquired = false; }
    }
    bool poll() {
        if (socket == invalid_socket) unavailable();
        if (ready) return true;
        if (std::chrono::steady_clock::now() >= deadline) unavailable();
#ifdef _WIN32
        WSAPOLLFD item{socket, POLLWRNORM, 0};
        const int result = WSAPoll(&item, 1, 0);
#else
        pollfd item{socket, POLLOUT, 0};
        const int result = ::poll(&item, 1, 0);
#endif
        if (result < 0) { if (interrupted(socket_error())) return false; unavailable(); }
        if (!result) return false;
        int error = 0;
        SocketLength size = sizeof(error);
        if (getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size) || error) unavailable();
        if (item.revents & (POLLERR | POLLHUP | POLLNVAL)) unavailable();
        ready = true;
        return true;
    }
    void guarded(const std::function<void()>& operation) {
        try { guard(operation); }
        catch (...) { release(); throw; }
    }
};
VncStream::VncStream(const std::string& address, int64_t port, Guard guard)
    : impl_(std::make_unique<Impl>(std::move(guard))) {
    if (!impl_->guard || port < 1 || port > 65535) invalid_endpoint();
    const auto local = local_vnc_address(address);
    sockaddr_storage storage{};
    SocketLength length;
    if (auto* v4 = reinterpret_cast<sockaddr_in*>(&storage); inet_pton(AF_INET, local.c_str(), &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET; v4->sin_port = htons(static_cast<uint16_t>(port)); length = sizeof(*v4);
    } else {
        auto* v6 = reinterpret_cast<sockaddr_in6*>(&storage);
        if (inet_pton(AF_INET6, local.c_str(), &v6->sin6_addr) != 1) invalid_endpoint();
        v6->sin6_family = AF_INET6; v6->sin6_port = htons(static_cast<uint16_t>(port)); length = sizeof(*v6);
    }
    acquire_connection(); impl_->acquired = true;
#ifdef _WIN32
    impl_->socket = WSASocket(storage.ss_family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
#else
    impl_->socket = ::socket(storage.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
#endif
    if (impl_->socket == invalid_socket) unavailable();
#ifdef _WIN32
    u_long nonblocking = 1;
    if (ioctlsocket(impl_->socket, FIONBIO, &nonblocking)) unavailable();
#endif
    const int result = ::connect(impl_->socket, reinterpret_cast<const sockaddr*>(&storage), length);
    if (!result) impl_->ready = true;
    else { const int error = socket_error(); if (!would_block(error) && !interrupted(error)) unavailable(); }
}
VncStream::~VncStream() = default;
bool VncStream::connected() {
    std::lock_guard lock(impl_->mutex);
    bool ready = false;
    impl_->guarded([&] { ready = impl_->poll(); });
    return ready;
}
std::string VncStream::read(size_t maximum) {
    if (!maximum || maximum > chunk_limit)
        throw ServiceError(ErrorCode::invalid_argument, "Display read exceeds chunk limit");
    std::lock_guard lock(impl_->mutex);
    std::string output;
    impl_->guarded([&] {
        if (!impl_->poll()) return;
        output.resize(maximum);
        const auto count = recv(impl_->socket, output.data(), static_cast<int>(output.size()), 0);
        if (count < 0) {
            const int error = socket_error();
            if (would_block(error) || interrupted(error)) { output.clear(); return; }
            unavailable();
        }
        if (!count) unavailable();
        output.resize(static_cast<size_t>(count));
    });
    return output;
}
size_t VncStream::write(std::string_view bytes) {
    if (bytes.empty() || bytes.size() > chunk_limit)
        throw ServiceError(ErrorCode::invalid_argument, "Display write exceeds chunk limit");
    std::lock_guard lock(impl_->mutex);
    size_t accepted = 0;
    impl_->guarded([&] {
        if (!impl_->poll()) return;
#ifdef _WIN32
        constexpr int flags = 0;
#else
        constexpr int flags = MSG_NOSIGNAL;
#endif
        const auto count = send(impl_->socket, bytes.data(), static_cast<int>(bytes.size()), flags);
        if (count < 0) {
            const int error = socket_error();
            if (would_block(error) || interrupted(error)) return;
            unavailable();
        }
        if (!count) unavailable();
        accepted = static_cast<size_t>(count);
    });
    return accepted;
}
void VncStream::close() noexcept {
    std::lock_guard lock(impl_->mutex);
    impl_->release();
}
}
