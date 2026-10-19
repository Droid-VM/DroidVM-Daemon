// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include "services/tasks.h"

namespace droidvm::web {
struct WebServiceBindings {
    std::function<Json::Value(const CallContext&)> read;
    std::function<Json::Value(const CallContext&, const Json::Value&)> change;
};
// Browser operations keep the authenticated caller. They never impersonate
// local-admin or use the local IPC pairing/configuration command surface.
WebServiceOperations web_service_operations(TaskService& tasks, WebServiceBindings bindings);
Json::Value project_web_service_result(const Json::Value& value);
}
