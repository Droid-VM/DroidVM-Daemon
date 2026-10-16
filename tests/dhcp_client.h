// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "contracts.h"
#include <array>
#include <algorithm>
#include <poll.h>
#include <vector>

namespace droidvm::test {
// Minimal DHCPv4 client on the test's owned TAP. No host IP/socket binding or
// external network is used; real Ethernet/IP/UDP packets exercise the helper.
inline std::string acquire_dhcp4(int tap) {
    constexpr std::array<uint8_t, 6> mac{2, 0, 0, 0x12, 0x34, 0x99};
    constexpr std::array<uint8_t, 4> xid{0x4d, 0xa9, 0x12, 0xef};
    std::array<uint8_t, 4> offered{}, server{};
    auto send = [&](uint8_t type) {
        std::vector<uint8_t> packet(14 + 20 + 8 + 240, 0);
        auto u16 = [&](size_t at, uint16_t value) { packet[at] = value >> 8; packet[at + 1] = value & 255; };
        std::fill_n(packet.begin(), 6, 255); std::copy(mac.begin(), mac.end(), packet.begin() + 6);
        u16(12, 0x0800);
        packet[14] = 0x45; packet[22] = 64; packet[23] = 17;
        std::fill_n(packet.begin() + 30, 4, 255);
        u16(34, 68); u16(36, 67);
        constexpr size_t boot = 42;
        packet[boot] = 1; packet[boot + 1] = 1; packet[boot + 2] = 6;
        std::copy(xid.begin(), xid.end(), packet.begin() + boot + 4);
        packet[boot + 10] = 0x80;
        std::copy(mac.begin(), mac.end(), packet.begin() + boot + 28);
        packet[boot + 236] = 99; packet[boot + 237] = 130; packet[boot + 238] = 83; packet[boot + 239] = 99;
        packet.insert(packet.end(), {53, 1, type});
        if (type == 3) {
            packet.insert(packet.end(), {50, 4}); packet.insert(packet.end(), offered.begin(), offered.end());
            packet.insert(packet.end(), {54, 4}); packet.insert(packet.end(), server.begin(), server.end());
        }
        packet.insert(packet.end(), {55, 3, 1, 3, 6, 255});
        u16(16, packet.size() - 14); u16(38, packet.size() - 34);
        uint32_t sum = 0;
        for (size_t at = 14; at < 34; at += 2) sum += (packet[at] << 8) | packet[at + 1];
        while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
        u16(24, static_cast<uint16_t>(~sum));
        check(write(tap, packet.data(), packet.size()) == static_cast<ssize_t>(packet.size()), "inject DHCP client frame into owned TAP");
    };
    auto receive = [&](uint8_t expected) {
        const auto deadline = std::chrono::steady_clock::now() + 5s;
        while (std::chrono::steady_clock::now() < deadline) {
            pollfd fd{tap, POLLIN, 0};
            if (poll(&fd, 1, 100) <= 0) continue;
            std::array<uint8_t, 2048> bytes{};
            const auto n = read(tap, bytes.data(), bytes.size());
            if (n < 282 || bytes[12] != 8 || bytes[13] != 0 || bytes[14] != 0x45 || bytes[23] != 17 || bytes[37] != 68) continue;
            constexpr size_t boot = 42;
            if (bytes[boot] != 2 || !std::equal(xid.begin(), xid.end(), bytes.begin() + boot + 4)) continue;
            bool matched = false;
            for (size_t at = boot + 240; at < static_cast<size_t>(n);) {
                const auto option = bytes[at++];
                if (option == 255) break;
                if (!option) continue;
                if (at == static_cast<size_t>(n)) break;
                const auto length = bytes[at++];
                if (at + length > static_cast<size_t>(n)) break;
                if (option == 53 && length == 1) matched = bytes[at] == expected;
                if (option == 54 && length == 4) std::copy_n(bytes.begin() + at, 4, server.begin());
                at += length;
            }
            if (!matched) continue;
            std::copy_n(bytes.begin() + boot + 16, 4, offered.begin());
            return;
        }
        throw std::runtime_error(expected == 2 ? "real DHCP offer deadline" : "real DHCP ACK deadline");
    };
    send(1); receive(2); send(3); receive(5);
    return std::to_string(offered[0]) + "." + std::to_string(offered[1]) + "." + std::to_string(offered[2]) + "." + std::to_string(offered[3]);
}
}
