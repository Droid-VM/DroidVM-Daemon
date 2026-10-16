// SPDX-License-Identifier: GPL-3.0-or-later
#include "netlink.h"
#include "common/fd.h"
#include "services/context.h"
#include <chrono>
#include <poll.h>
#include <sys/socket.h>
#include <system_error>

namespace droidvm::network {
namespace {
void require(bool ok, const char* operation) {
    if (!ok) throw std::system_error(errno, std::generic_category(), operation);
}
[[noreturn]] void invalid(const char* detail) { throw ServiceError(ErrorCode::io_error, detail); }
}
std::vector<std::vector<char>> netlink_exchange(const nlmsghdr& request, uint16_t dump_type) {
    Fd fd(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE));
    require(fd.get() >= 0, "open routing netlink socket");
    sockaddr_nl local{}; local.nl_family = AF_NETLINK;
    require(bind(fd.get(), reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0, "bind routing netlink socket");
    sockaddr_nl kernel{}; kernel.nl_family = AF_NETLINK;
    ssize_t sent;
    do { sent = sendto(fd.get(), &request, request.nlmsg_len, 0, reinterpret_cast<sockaddr*>(&kernel), sizeof(kernel)); }
    while (sent < 0 && errno == EINTR);
    require(sent == request.nlmsg_len, "send routing netlink request");
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    std::vector<std::vector<char>> result;
    size_t total = 0;
    for (;;) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) throw ServiceError(ErrorCode::unavailable, "routing netlink deadline; effect may have occurred");
        pollfd descriptor{fd.get(), POLLIN, 0};
        const int ready = poll(&descriptor, 1, static_cast<int>(remaining));
        if (ready < 0 && errno == EINTR) continue;
        require(ready >= 0, "poll routing netlink reply");
        if (!ready) continue;
        alignas(nlmsghdr) char buffer[65536];
        sockaddr_nl sender{};
        iovec io{buffer, sizeof(buffer)};
        msghdr envelope{};
        envelope.msg_name = &sender; envelope.msg_namelen = sizeof(sender);
        envelope.msg_iov = &io; envelope.msg_iovlen = 1;
        auto length = recvmsg(fd.get(), &envelope, 0);
        if (length < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        require(length >= 0, "read routing netlink reply");
        if (sender.nl_pid != 0) continue;
        if (envelope.msg_flags & MSG_TRUNC) invalid("truncated routing netlink reply");
        for (auto* h = reinterpret_cast<nlmsghdr*>(buffer); NLMSG_OK(h, length); h = NLMSG_NEXT(h, length)) {
            if (h->nlmsg_seq != request.nlmsg_seq) continue;
            if (h->nlmsg_flags & NLM_F_DUMP_INTR) invalid("interrupted routing netlink snapshot");
            if (h->nlmsg_type == NLMSG_ERROR) {
                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(nlmsgerr))) invalid("invalid routing netlink error");
                const int error = reinterpret_cast<const nlmsgerr*>(NLMSG_DATA(h))->error;
                if (error) throw std::system_error(-error, std::generic_category(), "routing netlink operation");
                if (!dump_type) return result;
                continue;
            }
            if (dump_type && h->nlmsg_type == NLMSG_DONE) {
                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(int))) invalid("invalid routing dump completion");
                int error; memcpy(&error, NLMSG_DATA(h), sizeof(error));
                if (error) throw std::system_error(-error, std::generic_category(), "routing netlink dump");
                return result;
            }
            if (!dump_type || h->nlmsg_type != dump_type) invalid("unexpected routing netlink reply");
            total += h->nlmsg_len;
            if (total > (4u << 20) || result.size() >= 8192)
                throw ServiceError(ErrorCode::resource_exhausted, "routing netlink snapshot exceeds budget");
            const auto* begin = reinterpret_cast<const char*>(h);
            result.emplace_back(begin, begin + h->nlmsg_len);
            if (!(request.nlmsg_flags & NLM_F_DUMP)) return result;
        }
        if (length) invalid("malformed routing netlink reply");
    }
}
}
