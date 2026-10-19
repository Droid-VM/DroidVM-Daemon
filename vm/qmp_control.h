// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <functional>
#include <string>
#include <string_view>

namespace droidvm::vm {
// One QMP greeting/capabilities/command exchange. Transport callbacks enforce
// one absolute deadline, send all bytes, and return empty on EOF/read failure.
// Protocol framing has independent byte/message bounds; events cannot be ACKs.
bool qmp_control(const Json::Value& command,
    const std::function<bool(std::string_view)>& send,
    const std::function<std::string()>& receive);
}
