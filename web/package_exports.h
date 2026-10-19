// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include "pkg/service.h"

namespace droidvm::web {
using GetPackageExportPlan = std::function<Json::Value(const CallContext&, const std::string&)>;
using SubmitPackageExport = std::function<TaskRef(const CallContext&, const Json::Value&,
    const pkg::ExportConfirmation&, const std::string&)>;
// The package service submits directly to the shared TaskService. This adapter
// only validates browser input and projects native plans/task results.
PackageExportOperations package_exports(TaskService& tasks, GetPackageExportPlan plan, SubmitPackageExport submit);
Json::Value project_package_export(const Json::Value& result);
}
