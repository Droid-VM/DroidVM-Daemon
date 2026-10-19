// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include "services/tasks.h"

namespace droidvm::web {
struct UsbAcmBindings {
    std::function<Json::Value(const CallContext&)> read;
    std::function<TaskView(const CallContext&, const Json::Value&)> start;
    std::function<TaskView(const CallContext&, const std::string&)> status;
};
Json::Value usb_acm_catalog(const Json::Value& native);
Json::Value project_usb_acm_result(const Json::Value& native, bool cancelled = false);
WebServiceOperations usb_acm_operations(UsbAcmBindings source);
}
