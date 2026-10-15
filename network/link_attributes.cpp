// SPDX-License-Identifier: GPL-3.0-or-later
#include "link_attributes.h"
#include "common/fd.h"
#include "services/context.h"
#include <array>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <system_error>

namespace droidvm::network {
namespace {
void require(bool ok, const char* operation) {
    if (!ok) throw std::system_error(errno, std::generic_category(), operation);
}
struct Message {
    nlmsghdr header{};
    ifinfomsg link{};
    std::array<char, 256> attributes{};
    Message() {
        header.nlmsg_len = NLMSG_LENGTH(sizeof(link));
        header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        header.nlmsg_seq = 1;
    }
    size_t attribute(uint16_t type, const void* bytes, size_t size) {
        const size_t offset = NLMSG_ALIGN(header.nlmsg_len);
        const size_t count = RTA_LENGTH(size);
        if (offset + RTA_ALIGN(count) > sizeof(*this)) throw std::logic_error("network attribute overflow");
        auto* attr = reinterpret_cast<rtattr*>(reinterpret_cast<char*>(this) + offset);
        attr->rta_type = type; attr->rta_len = count;
        if (size) memcpy(RTA_DATA(attr), bytes, size);
        header.nlmsg_len = offset + RTA_ALIGN(count);
        return offset;
    }
    void finish(size_t offset) { reinterpret_cast<rtattr*>(reinterpret_cast<char*>(this) + offset)->rta_len = header.nlmsg_len - offset; }
};
void send(Message& message) {
    Fd fd(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE));
    require(fd.get() >= 0, "open link attribute netlink socket");
    sockaddr_nl local{}; local.nl_family = AF_NETLINK;
    require(bind(fd.get(), reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0, "bind link attribute netlink socket");
    sockaddr_nl kernel{}; kernel.nl_family = AF_NETLINK;
    ssize_t sent;
    do { sent = sendto(fd.get(), &message, message.header.nlmsg_len, 0, reinterpret_cast<sockaddr*>(&kernel), sizeof(kernel)); }
    while (sent < 0 && errno == EINTR);
    require(sent == message.header.nlmsg_len, "send link attribute netlink request");
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    for (;;) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) throw ServiceError(ErrorCode::unavailable, "link attribute acknowledgement timed out; effect may have occurred");
        pollfd descriptor{fd.get(), POLLIN, 0};
        int ready = poll(&descriptor, 1, static_cast<int>(remaining));
        if (ready < 0 && errno == EINTR) continue;
        require(ready >= 0, "poll link attribute acknowledgement");
        if (!ready) continue;
        alignas(nlmsghdr) char buffer[4096];
        sockaddr_nl sender{};
        iovec io{buffer, sizeof(buffer)};
        msghdr envelope{};
        envelope.msg_name = &sender; envelope.msg_namelen = sizeof(sender);
        envelope.msg_iov = &io; envelope.msg_iovlen = 1;
        const auto received = recvmsg(fd.get(), &envelope, 0);
        if (received < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        require(received >= 0, "read link attribute acknowledgement");
        if (sender.nl_pid != 0) continue;
        if (envelope.msg_flags & MSG_TRUNC) throw ServiceError(ErrorCode::io_error, "truncated link attribute acknowledgement");
        auto length = received;
        for (auto* header = reinterpret_cast<nlmsghdr*>(buffer); NLMSG_OK(header, length); header = NLMSG_NEXT(header, length)) {
            if (header->nlmsg_seq != message.header.nlmsg_seq) continue;
            if (header->nlmsg_type != NLMSG_ERROR || header->nlmsg_len < NLMSG_LENGTH(sizeof(nlmsgerr)))
                throw ServiceError(ErrorCode::io_error, "invalid link attribute acknowledgement");
            const auto* error = reinterpret_cast<const nlmsgerr*>(NLMSG_DATA(header));
            if (error->error) throw std::system_error(-error->error, std::generic_category(), "set bridge attribute");
            return;
        }
    }
}
}
void bridge_flag(const std::string& name, BridgeFlag flag, bool enabled) {
    try {
        auto index = if_nametoindex(name.c_str());
        require(index != 0, "resolve bridge attribute interface");
        Message message;
        message.link.ifi_index = static_cast<int>(index);
        if (flag == BridgeFlag::stp) {
            message.header.nlmsg_type = RTM_NEWLINK;
            message.link.ifi_family = AF_UNSPEC;
            const auto info = message.attribute(IFLA_LINKINFO | NLA_F_NESTED, nullptr, 0);
            constexpr char kind[] = "bridge";
            message.attribute(IFLA_INFO_KIND, kind, sizeof(kind));
            const auto data = message.attribute(IFLA_INFO_DATA | NLA_F_NESTED, nullptr, 0);
            const uint32_t value = enabled;
            message.attribute(IFLA_BR_STP_STATE, &value, sizeof(value));
            message.finish(data); message.finish(info);
        } else {
            message.header.nlmsg_type = RTM_SETLINK;
            message.link.ifi_family = AF_BRIDGE;
            const auto info = message.attribute(IFLA_PROTINFO | NLA_F_NESTED, nullptr, 0);
            const uint8_t value = enabled;
            message.attribute(flag == BridgeFlag::isolated ? IFLA_BRPORT_ISOLATED : IFLA_BRPORT_LOCKED, &value, sizeof(value));
            message.finish(info);
        }
        send(message);
    } catch (const std::system_error& error) { throw ServiceError(ErrorCode::io_error, error.what()); }
}
}
