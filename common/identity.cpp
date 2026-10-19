// SPDX-License-Identifier: GPL-3.0-or-later
#include "identity.h"
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#else
#include <sys/random.h>
#endif
#include <array>
#include <cerrno>
#include <stdexcept>

namespace droidvm {
namespace {
template<size_t Size>
std::array<unsigned char, Size> random_bytes() {
    std::array<unsigned char, Size> bytes{};
#ifdef _WIN32
    if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        throw std::runtime_error("BCryptGenRandom failed");
#else
    size_t offset = 0;
    while (offset < bytes.size()) {
        auto count = getrandom(bytes.data() + offset, bytes.size() - offset, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw std::runtime_error("getrandom failed");
        offset += static_cast<size_t>(count);
    }
#endif
    return bytes;
}
}
std::string random_id(bool uuid) {
    auto bytes = random_bytes<16>();
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
std::string random_secret() {
    const auto bytes = random_bytes<32>();
    constexpr char hex[] = "0123456789abcdef";
    std::string value;
    value.reserve(bytes.size() * 2);
    for (auto byte : bytes) { value += hex[byte >> 4]; value += hex[byte & 15]; }
    return value;
}
}
