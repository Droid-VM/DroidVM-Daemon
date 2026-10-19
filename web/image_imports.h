// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include "services/tasks.h"

namespace droidvm::web {
struct ImageImportBindings {
    std::function<Json::Value(const CallContext&, const std::string&, const std::function<bool()>&)> preview;
    std::function<TaskCompletion(const CallContext&, const Json::Value&, TaskControl&)> commit;
};
ImageImportOperations image_imports(TaskService& tasks, ImageImportBindings bindings);
Json::Value project_image_import_plan(const Json::Value& value);
Json::Value project_image_import(const Json::Value& value);
}
