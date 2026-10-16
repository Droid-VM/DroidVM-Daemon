// SPDX-License-Identifier: GPL-3.0-or-later
#include "helper_ready.h"
#include "common/wire.h"

namespace droidvm::network {
void await_helper(ManagedProcess& process, const ControlHttp& client, const std::string& endpoint,
        const std::function<bool(const Json::Value&)>& ready) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        if (!process.status().running) throw std::runtime_error("network helper exited before readiness");
        try {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
            if (remaining.count() <= 0) break;
            const auto response = client.request(HttpMethod::get, endpoint, {},
                {std::min(remaining, std::chrono::milliseconds(200)), {}});
            if (!response.success()) throw std::runtime_error("network helper readiness API rejected request");
            if (ready(wire::parse(response.body)) && process.status().running) return;
        } catch (const ControlError& error) {
            if (error.reason != ControlFailure::io && error.reason != ControlFailure::timeout) throw;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    throw std::runtime_error("network helper readiness deadline exceeded");
}
}
