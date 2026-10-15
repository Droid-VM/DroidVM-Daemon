// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <string>
#include <functional>
#include <optional>
#include <mutex>

namespace droidvm {
// The service has no socket, Android Context, or transport ownership.
struct Caller { std::string client_id; bool authorized = false; };
class SystemService {
public:
    SystemService(std::function<bool()> token_exists, std::function<std::string()> read_token, std::string apk_hash);
    Json::Value execute(Caller& caller, const std::string& command, const Json::Value& request) const;
private:
    std::function<bool()> token_exists_;
    std::function<std::string()> read_token_;
    mutable std::mutex auth_mutex_;
    mutable std::optional<std::string> token_;
    std::string apk_hash_, epoch_;
};
}
