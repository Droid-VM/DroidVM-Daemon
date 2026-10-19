// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include "services/tasks.h"
#include "services/host_preferences.h"

namespace droidvm::web {
struct HostPreferenceBindings {
    std::function<Json::Value(const CallContext&)> read;
    std::function<TaskView(const CallContext&, const Json::Value&)> start;
    std::function<TaskView(const CallContext&, const std::string&)> status;
};
Json::Value host_preference_catalog(const Json::Value& native, HostPreferenceDomain domain = HostPreferenceDomain::vm_start);
Json::Value project_host_preference_result(const Json::Value& native, bool cancelled = false, HostPreferenceDomain domain = HostPreferenceDomain::vm_start);
WebServiceOperations host_preference_operations(HostPreferenceBindings source, HostPreferenceDomain domain = HostPreferenceDomain::vm_start);
}
