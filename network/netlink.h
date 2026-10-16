// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <array>
#include <cstring>
#include <linux/rtnetlink.h>
#include <span>
#include <stdexcept>
#include <vector>

namespace droidvm::network {
// Shared bounded Linux UAPI transport. Kernel errors remain system_error so
// each resource adapter can distinguish EEXIST/ENOENT from uncertain effects.
std::vector<std::vector<char>> netlink_exchange(const nlmsghdr& request, uint16_t dump_type = 0);
template<class Payload, size_t Capacity = 1024> struct NetlinkMessage {
    nlmsghdr header{};
    Payload payload{};
    std::array<char, Capacity> attributes{};
    NetlinkMessage() {
        header.nlmsg_len = NLMSG_LENGTH(sizeof(payload));
        header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        header.nlmsg_seq = 1;
    }
    size_t attribute(uint16_t type, const void* bytes, size_t size) {
        const size_t offset = NLMSG_ALIGN(header.nlmsg_len), count = RTA_LENGTH(size);
        if (offset + RTA_ALIGN(count) > sizeof(*this)) throw std::logic_error("network attribute overflow");
        auto* attr = reinterpret_cast<rtattr*>(reinterpret_cast<char*>(this) + offset);
        attr->rta_type = type; attr->rta_len = count;
        if (size) memcpy(RTA_DATA(attr), bytes, size);
        header.nlmsg_len = offset + RTA_ALIGN(count);
        return offset;
    }
    void finish(size_t offset) {
        reinterpret_cast<rtattr*>(reinterpret_cast<char*>(this) + offset)->rta_len = header.nlmsg_len - offset;
    }
};
}
