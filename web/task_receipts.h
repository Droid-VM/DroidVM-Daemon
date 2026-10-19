// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "services/tasks.h"

namespace droidvm::web {
struct TaskReceiptPersistence {
    std::function<Json::Value()> load;
    std::function<void(const Json::Value&)> save;
};
// Bounded, projected result receipts only. The backing store is the daemon's
// existing JsonFile; neither credentials, raw requests nor signatures enter it.
void bind_task_receipts(TaskService& tasks, TaskReceiptPersistence persistence);
}
