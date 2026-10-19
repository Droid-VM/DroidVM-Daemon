// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "http_api.h"
#include "services/tasks.h"

namespace droidvm::web {
// References the daemon's existing owner; no registry, workers or task lifetime
// are tied to a browser connection. The TaskService must outlive accepted work.
TaskOperations task_operations(TaskService& tasks);
Json::Value task_view(const TaskView& task);
}
