// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace droidvm::vm {
// Produced alongside the backend command, never accepted from a browser.
struct VncEndpoint {
    std::string screen, host;
    int64_t port = -1;
    std::string password;
    bool input_enabled = true;
    std::string unavailable_reason;
};
// Only local numeric addresses are accepted. Wildcards select loopback; no
// name resolution is performed and remote literals are rejected.
std::string local_vnc_address(const std::string& bind_address);

// A bounded, threadless TCP stream. Guard executes the operation while its
// runtime's state lock still protects the expected incarnation and revision.
// Calls are serialized internally; close does not acquire the runtime lock.
class VncStream {
public:
    static constexpr size_t chunk_limit = 64u << 10;
    static constexpr size_t connection_limit = 16;
    using Guard = std::function<void(const std::function<void()>&)>;
    VncStream(const std::string& local_address, int64_t port, Guard guard);
    ~VncStream();
    VncStream(const VncStream&) = delete;
    VncStream& operator=(const VncStream&) = delete;
    bool connected();
    std::string read(size_t maximum = chunk_limit);
    size_t write(std::string_view bytes);
    void close() noexcept;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
