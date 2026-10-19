// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include "services/tasks.h"

namespace droidvm::web {
struct HugepageBindings {
    std::function<Json::Value(const CallContext&)> snapshot;
    std::function<TaskView(const CallContext&, const Json::Value&)> start;
    std::function<TaskView(const CallContext&, const std::string&)> status;
};
Json::Value hugepage_snapshot(const Json::Value& native);
Json::Value project_hugepage_result(const Json::Value& native);
HugepageOperations hugepage_operations(HugepageBindings source);
}
