// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "agent/scripts.h"
#include <json/json.h>
#include <array>
#include <cstddef>
#include <string>
#include <string_view>

namespace droidvm::agent {
inline constexpr size_t password_limit = 128;
inline constexpr std::string_view password_symbols = "!@#%^*+-=_.,:?";
inline constexpr std::string_view operation_stream = "uart";
inline constexpr std::string_view operation_device = "/dev/ttyAMA0";

// Shared with the protocol owner. Exactly the App's ASCII allowlist, with a
// bounded length at this native boundary; no locale-dependent character tests.
bool valid_password(std::string_view password) noexcept;

class Request {
public:
    Request(const Request&) = delete;
    Request& operator=(const Request&) = delete;
    Request(Request&& other) noexcept;
    Request& operator=(Request&& other) noexcept;
    ~Request();

    ActionKind action() const noexcept { return action_; }
    const std::string& disk_id() const noexcept { return disk_id_; }
    bool normal_users() const noexcept { return normal_users_; }
    // Trusted protocol owner only: never persist, log, or expose in status.
    std::string_view password() const noexcept { return {password_.data(), password_size_}; }
    void clear_password() noexcept;
    Json::Value public_json() const;
private:
    friend Request parse_request(const Json::Value& value);
    Request(ActionKind action, std::string disk_id, bool normal_users, std::string_view password);
    ActionKind action_;
    std::string disk_id_;
    bool normal_users_;
    std::array<char, password_limit> password_{};
    size_t password_size_ = 0;
};

// An action payload, not an authenticated HTTP request. Only action/diskId and
// chpasswd's password/normalUsers are accepted. The caller owns and must discard
// the original JSON/body copy after parsing; this object cannot scrub that copy.
Request parse_request(const Json::Value& value);

struct RescueVmInputs {
    std::string vm_id;
    std::string name;
    std::string kernel;
    std::string initrd;
    std::string disk_path;
};
// Trusted adapter inputs: kernel/initrd come from installed built-in assets and
// disk_path from the existing disk registry. This pure builder does not discover
// files, grant leases, start a VM or write persistent VM configuration. Its caller
// must use the existing disk/VM services for admission and temporary VM lifetime.
// Unlike App AgentVM (agent_mode=false), agent_mode=true selects native QEMU's
// writeback agent path and adds its internal virtconsole. Automation still uses
// the explicit human UART above; it must not write through the agent channel.
Json::Value build_rescue_vm(const RescueVmInputs& inputs);
}
