// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include "services/tasks.h"

namespace droidvm::web {
struct AndroidDisplayBindings {
    std::function<Json::Value(const CallContext&)> read;
    std::function<TaskView(const CallContext&, const Json::Value&)> start;
    std::function<TaskView(const CallContext&, const std::string&)> status;
};
Json::Value android_display_catalog(const Json::Value& native);
Json::Value project_android_display_result(const Json::Value& native, bool cancelled = false);
WebServiceOperations android_display_operations(AndroidDisplayBindings source);
}
