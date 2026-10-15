// SPDX-License-Identifier: GPL-3.0-or-later
#include "link_attributes.h"
#include "netbox.h"
#include "common/fd.h"
#include "services/context.h"
#include <array>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <charconv>
#include <fcntl.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
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
    require(fd.get() >= 0, "open link netlink socket");
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
            if (error->error) throw std::system_error(-error->error, std::generic_category(), "network link operation");
            return;
        }
    }
}
void create_marked(const std::string& name, const std::string& tag, uint32_t parent, uint16_t vid) {
    Netbox::interface_name(name);
    const auto mark = creation_mark(tag);
    if (parent && (parent > INT32_MAX || vid < 1 || vid > 4094))
        throw ServiceError(ErrorCode::invalid_argument, "invalid owned link identity");
    Message message;
    message.header.nlmsg_type = RTM_NEWLINK;
    message.header.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
    message.link.ifi_family = AF_UNSPEC;
    message.attribute(IFLA_IFNAME, name.c_str(), name.size() + 1);
    message.attribute(IFLA_IFALIAS, tag.c_str(), tag.size() + 1);
    // Some Android kernels ignore IFLA_IFALIAS on NEWLINK creation. A random
    // staging name and group established before registration jointly carry 80
    // random bits. Unlike a temporary MAC, this preserves VLAN inheritance.
    if (name != mark.name) throw ServiceError(ErrorCode::invalid_argument, "owned link must use its staging name");
    message.attribute(IFLA_GROUP, &mark.group, sizeof(mark.group));
    if (parent) message.attribute(IFLA_LINK, &parent, sizeof(parent));
    const auto info = message.attribute(IFLA_LINKINFO | NLA_F_NESTED, nullptr, 0);
    const std::string kind = parent ? "vlan" : "bridge";
    message.attribute(IFLA_INFO_KIND, kind.c_str(), kind.size() + 1);
    if (parent) {
        const auto data = message.attribute(IFLA_INFO_DATA | NLA_F_NESTED, nullptr, 0);
        message.attribute(IFLA_VLAN_ID, &vid, sizeof(vid));
        message.finish(data);
    }
    message.finish(info);
    try { send(message); }
    catch (const std::system_error& error) {
        throw ServiceError(error.code().value() == EEXIST ? ErrorCode::conflict : ErrorCode::io_error, error.what());
    }
}
}
CreationMark creation_mark(const std::string& tag) {
    if (tag.size() != 40 || !tag.starts_with("droidvm:") || tag.substr(8).find_first_not_of("0123456789abcdef") != std::string::npos)
        throw ServiceError(ErrorCode::invalid_argument, "invalid creation identity");
    CreationMark mark{"dv" + tag.substr(8, 12), 0};
    std::from_chars(tag.data() + 32, tag.data() + 40, mark.group, 16);
    return mark;
}
void create_marked_bridge(const std::string& name, const std::string& tag) { create_marked(name, tag, 0, 0); }
void create_marked_vlan(const std::string& name, const std::string& tag, uint32_t parent, uint16_t vid) {
    if (!parent) throw ServiceError(ErrorCode::invalid_argument, "missing owned VLAN parent index");
    create_marked(name, tag, parent, vid);
}
void clear_creation_group(uint32_t index) {
    if (!index || index > INT32_MAX) throw ServiceError(ErrorCode::invalid_argument, "invalid owned link index");
    Message message;
    message.header.nlmsg_type = RTM_NEWLINK;
    message.link.ifi_index = static_cast<int>(index);
    const uint32_t group = 0;
    message.attribute(IFLA_GROUP, &group, sizeof(group));
    try { send(message); }
    catch (const std::system_error& error) { throw ServiceError(ErrorCode::io_error, error.what()); }
}
void rename_owned_link(uint32_t index, const std::string& name) {
    Netbox::interface_name(name);
    if (!index || index > INT32_MAX) throw ServiceError(ErrorCode::invalid_argument, "invalid owned link index");
    Message message;
    message.header.nlmsg_type = RTM_NEWLINK;
    message.link.ifi_index = static_cast<int>(index);
    message.attribute(IFLA_IFNAME, name.c_str(), name.size() + 1);
    try { send(message); }
    catch (const std::system_error& error) {
        throw ServiceError(error.code().value() == EEXIST ? ErrorCode::conflict : ErrorCode::io_error, error.what());
    }
}
void delete_link_index(uint32_t index) {
    if (!index || index > INT32_MAX) throw ServiceError(ErrorCode::invalid_argument, "invalid owned link index");
    Message message;
    message.header.nlmsg_type = RTM_DELLINK;
    message.link.ifi_index = static_cast<int>(index);
    try { send(message); }
    catch (const std::system_error& error) {
        if (error.code().value() != ENODEV) throw ServiceError(ErrorCode::io_error, error.what());
    }
}
Fd open_transient_tap(const std::string& name) {
    Netbox::interface_name(name);
    try {
        // Android commonly symlinks /dev/net/tun to /dev/tun. Validate the
        // opened device rather than rejecting that kernel-managed layout.
        Fd fd(open("/dev/net/tun", O_RDWR | O_CLOEXEC));
        require(fd.get() >= 0, "open transient TAP");
        struct stat device{};
        require(fstat(fd.get(), &device) == 0, "stat transient TAP device");
        if (!S_ISCHR(device.st_mode) || major(device.st_rdev) != 10 || minor(device.st_rdev) != 200)
            throw ServiceError(ErrorCode::io_error, "unexpected TUN device identity");
        ifreq request{};
        memcpy(request.ifr_name, name.c_str(), name.size() + 1);
        request.ifr_flags = static_cast<short>(IFF_TAP | IFF_NO_PI | IFF_VNET_HDR | IFF_TUN_EXCL);
        require(ioctl(fd.get(), TUNSETIFF, &request) == 0, "create exclusive transient TAP");
        return fd;
    } catch (const std::system_error& error) {
        throw ServiceError(error.code().value() == EBUSY || error.code().value() == EEXIST ? ErrorCode::conflict : ErrorCode::io_error, error.what());
    }
}
void persist_tap(int fd) {
    try { require(ioctl(fd, TUNSETPERSIST, 1) == 0, "persist owned TAP"); }
    catch (const std::system_error& error) { throw ServiceError(ErrorCode::io_error, error.what()); }
}
void bridge_flag(const std::string& name, BridgeFlag flag, bool enabled) {
    Netbox::interface_name(name);
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
