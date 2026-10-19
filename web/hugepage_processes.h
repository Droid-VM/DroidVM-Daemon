// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include "services/tasks.h"

namespace droidvm::web {
struct HugepageProcessBindings {
    std::function<Json::Value(const CallContext&, const std::string&)> list;
    std::function<Json::Value(const CallContext&, const Json::Value&)> stack;
    std::function<TaskView(const CallContext&, const Json::Value&)> start;
    std::function<TaskView(const CallContext&, const std::string&)> status;
};
Json::Value hugepage_process_catalog(const Json::Value& native);
Json::Value project_hugepage_process_result(const Json::Value& native, bool cancelled = false);
HugepageProcessOperations hugepage_process_operations(HugepageProcessBindings source);
}
