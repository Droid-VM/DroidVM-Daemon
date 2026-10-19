// SPDX-License-Identifier: GPL-3.0-or-later
#include "qmp_control.h"
#include "common/wire.h"
#include <memory>

namespace droidvm::vm {
bool qmp_control(const Json::Value& command, const std::function<bool(std::string_view)>& send,
                 const std::function<std::string()>& receive) {
    if (!command.isObject() || !command["execute"].isString() || !send || !receive) return false;
    std::string pending;
    Json::CharReaderBuilder builder;
    Json::CharReaderBuilder::strictMode(&builder.settings_);
    builder["stackLimit"] = 16;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    size_t bytes = 0, messages = 0;
    auto next = [&]() -> Json::Value {
        if (++messages > 128) return {};
        for (;;) {
            const auto end = pending.find('\n');
            if (end != std::string::npos) {
                Json::Value value;
                if (!reader->parse(pending.data(), pending.data() + end, &value, nullptr)) return {};
                pending.erase(0, end + 1);
                return value;
            }
            auto chunk = receive();
            if (chunk.empty() || chunk.size() > 65536 - bytes) return {};
            bytes += chunk.size();
            pending += chunk;
        }
    };
    auto reply = [&](const char* id) {
        for (;;) {
            auto value = next();
            if (!value.isObject()) return false;
            if (value["event"].isString() && !value.isMember("id") && !value.isMember("return") && !value.isMember("error")) continue;
            return value["id"] == id && value["return"].isObject() && !value.isMember("error");
        }
    };
    try {
        const auto greeting = next();
        if (!greeting.isObject() || !greeting["QMP"].isObject()) return false;
        Json::Value caps; caps["execute"] = "qmp_capabilities"; caps["id"] = "capabilities";
        if (!send(wire::stringify(caps) + "\n") || !reply("capabilities")) return false;
        auto request = command; request["id"] = "command";
        return send(wire::stringify(request) + "\n") && reply("command");
    } catch (...) { return false; } // Caller reports an unconfirmed control outcome.
}
}
