// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include "services/tasks.h"

namespace droidvm::web {
struct PackageTransferFile { std::string name; uint64_t size = 0; };
struct PackageTransferBindings {
    std::function<Json::Value(const CallContext&, const std::string&, const std::vector<PackageTransferFile>&)> begin_upload;
    std::function<Json::Value(const CallContext&, const std::string&)> status, finish;
    std::function<Json::Value(const CallContext&, const std::string&, size_t, uint64_t, std::string_view)> append;
    std::function<void(const CallContext&, const std::string&)> erase;
    std::function<Json::Value(const CallContext&, const std::string&, const Json::Value&)> prepare_download;
    std::function<std::shared_ptr<HttpStreamBody>(const CallContext&, const std::string&, size_t)> open_download;
};
PackageTransferOperations package_transfers(TaskService& tasks, PackageTransferBindings bindings);
Json::Value project_package_transfer(const Json::Value& value, const std::string& kind);
Json::Value project_image_upload(const Json::Value& value);
}
