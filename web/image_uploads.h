// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "package_transfers.h"

namespace droidvm::web {
struct ImageUploadBindings {
    std::function<Json::Value(const CallContext&, const std::string&, const PackageTransferFile&)> begin_upload;
    std::function<Json::Value(const CallContext&, const std::string&)> status, finish;
    std::function<Json::Value(const CallContext&, const std::string&, uint64_t, std::string_view)> append;
    std::function<void(const CallContext&, const std::string&)> erase;
    std::function<TaskCompletion(const CallContext&, const std::string&, const std::string&, const std::string&, TaskControl&)> install;
};
ImageUploadOperations image_uploads(TaskService& tasks, ImageUploadBindings bindings);
Json::Value project_image_install(const Json::Value& value);
}
