// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include "services/tasks.h"
#include "vm/observation.h"

namespace droidvm::web {
struct UsbOperation {
    std::string request_id, device_id, sysfs;
    Json::Value expected, target;
    std::optional<vm::Observation> vm_observation;
};
using ApplyUsbOperation = std::function<void(const CallContext&, const UsbOperation&)>;
UsbOperations usb_operations(TaskService& tasks, ApplyUsbOperation apply);
// Called inside UsbService's serial mutation entry on a freshly projected view.
void require_usb_observation(const UsbOperation& operation, const Json::Value& catalogue);
Json::Value usb_observation(const Json::Value& device);
}
