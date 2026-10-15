// SPDX-License-Identifier: GPL-3.0-or-later
#include "identity.h"
#include <sys/random.h>
#include <array>
#include <cerrno>
#include <stdexcept>

namespace droidvm {
std::string random_id(bool uuid) {
    std::array<unsigned char, 16> bytes{};
    size_t offset = 0;
    while (offset < bytes.size()) {
        auto count = getrandom(bytes.data() + offset, bytes.size() - offset, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw std::runtime_error("getrandom failed");
        offset += static_cast<size_t>(count);
    }
    bytes[6] = (bytes[6] & 15) | 0x40;
    bytes[8] = (bytes[8] & 63) | 0x80;
    constexpr char hex[] = "0123456789abcdef";
    std::string value;
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (uuid && (i == 4 || i == 6 || i == 8 || i == 10)) value += '-';
        value += hex[bytes[i] >> 4];
        value += hex[bytes[i] & 15];
    }
    return value;
}
}
