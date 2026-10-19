// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include "services/tasks.h"

namespace droidvm::web {
using SubmitPackageImportPlan = std::function<TaskRef(const CallContext&, const std::string&, const std::string&)>;
using SubmitPackageImport = std::function<TaskRef(const CallContext&, const Json::Value&, const std::string&, const std::string&)>;
// Native callbacks submit once to the shared task service. Import references a
// retained caller-owned preview task; the browser never supplies a manifest.
PackageImportOperations package_imports(TaskService& tasks, SubmitPackageImportPlan plan, SubmitPackageImport submit);
Json::Value project_package_import_plan(const Json::Value& value);
Json::Value project_package_import(const Json::Value& value);
}
