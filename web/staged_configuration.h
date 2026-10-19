// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include "services/tasks.h"

namespace droidvm::web {
// Every participant binds the same ConfigUploads quota manager. Only the
// domain commit result differs; HTTP never owns an upload registry.
template<class Result> struct ConfigurationStaging {
    std::function<std::string(const CallContext&, const std::string&, size_t)> begin;
    std::function<size_t(const CallContext&, const std::string&, size_t, std::string_view)> append;
    std::function<Result(const CallContext&, const std::string&)> commit;
    std::function<void(const CallContext&, const std::string&)> abort;
};
using JsonConfigurationStaging = ConfigurationStaging<Json::Value>;
ConfigOperations staged_configuration(TaskService& tasks, JsonConfigurationStaging staging,
    std::string kind, std::string resource, size_t document_limit);
namespace configuration_input {
void access(const CallContext& caller);
std::string id(const Json::Value& value);
size_t count(const Json::Value& value, size_t maximum);
[[noreturn]] void invalid();
}
}
