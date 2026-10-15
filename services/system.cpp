// SPDX-License-Identifier: GPL-3.0-or-later
#include "system.h"
#include "build_metadata.h"

namespace droidvm {
namespace {
Json::Value failure(const char* message) {
    Json::Value result;
    result["success"] = false;
    result["message"] = message;
    return result;
}
}
SystemService::SystemService(std::function<bool()> token_exists, std::function<std::string()> read_token, std::string apk_hash, std::string epoch)
    : token_exists_(std::move(token_exists)), read_token_(std::move(read_token)),
      apk_hash_(std::move(apk_hash)), epoch_(std::move(epoch)) {}
Json::Value SystemService::execute(Caller& caller, const std::string& command, const Json::Value& request) const {
    Json::Value result(Json::objectValue);
    result["success"] = true;
    if (command == "auth") {
        if (!request["token"].isString()) return failure("internal error");
        std::lock_guard lock(auth_mutex_);
        if (!token_exists_()) return failure("Token file not found");
        if (!token_) {
            try {
                auto value = read_token_();
                if (value.size() != 32) return failure("Invalid token file");
                token_ = std::move(value);
            } catch (const std::exception&) { return failure("internal error"); }
        }
        const auto supplied = request["token"].asString();
        unsigned difference = static_cast<unsigned>(supplied.size() != token_->size());
        for (size_t i = 0; i < token_->size(); ++i)
            difference |= static_cast<unsigned>((*token_)[i] ^ (i < supplied.size() ? supplied[i] : 0));
        if (difference) return failure("Token mismatch");
        caller.authorized = true;
    } else if (command == "ping") {
        result["response"] = request["request"].isString() && request["request"].asString() == "PING" ? "PONG" : "HELLO";
    } else if (command == "version") {
        result["client_id"] = caller.client_id;
        result["version"] = DROIDVM_VERSION_NAME;
        result["version_code"] = DROIDVM_VERSION_CODE;
        result["pkg_name"] = DROIDVM_PACKAGE_NAME;
        result["build_type"] = DROIDVM_BUILD_TYPE;
        result["daemon_hash"] = apk_hash_;
    } else if (command == "capabilities") {
        if (!caller.authorized) return failure("client is not authorized to perform this action");
        result["epoch"] = epoch_;
        result["service_api_major"] = 1;
        result["service_api_minor"] = 0;
        result["production_ready"] = false;
        auto& commands = result["commands"] = Json::Value(Json::arrayValue);
        for (const char* name : {"auth", "ping", "version", "capabilities"}) commands.append(name);
    } else {
        return failure(("command handler " + command + " not found").c_str());
    }
    return result;
}
}
