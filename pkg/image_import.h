// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "services/configuration.h"
#include "services/tasks.h"
#include <functional>
#include <mutex>
#include <string>

namespace droidvm::pkg {
// Register existing host files, without copying, deleting or rewriting them.
// The trusted adapter retains previews in its existing scoped TaskService.
class ImageImportService {
public:
    static constexpr size_t max_plan_bytes = 240u << 10;
    ImageImportService(ConfigurationService& configuration, std::string qemu_img,
        std::function<void(const std::string&, int)> persistent_source = {})
        : configuration_(configuration), qemu_img_(std::move(qemu_img)), persistent_source_(std::move(persistent_source)) {}
    Json::Value preview(const CallContext& caller, const std::string& source,
        std::function<bool()> cancelled = {});
    TaskCompletion commit(const CallContext& caller, const Json::Value& retained_plan, TaskControl& control);
private:
    ConfigurationService& configuration_;
    std::string qemu_img_;
    std::function<void(const std::string&, int)> persistent_source_;
    std::mutex mutex_;
};
}
