// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "tasks.h"
#include "vm/acm_control.h"
#include <functional>
#include <memory>
#include <optional>

namespace droidvm {
struct UsbAcmLoaded { Json::Value document; bool recovered = false; };
enum class UsbAcmSave { saved, not_saved, installed_uncertain };
struct UsbAcmOptions {
    std::function<std::optional<UsbAcmLoaded>()> load;
    std::function<UsbAcmSave(const Json::Value&)> save;
    vm::AcmControl* pool = nullptr; // Outlives the service and its tasks.
};
class UsbAcmService {
public:
    static constexpr const char* capability = "usb-acm-v1";
    UsbAcmService(TaskService&, UsbAcmOptions);
    ~UsbAcmService();
    Json::Value snapshot(const CallContext&) const;
    Json::Value sync_legacy(const CallContext&, const Json::Value&);
    TaskView start(const CallContext&, const Json::Value&);
    TaskView status(const CallContext&, const std::string& request_id);
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
