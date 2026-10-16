// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <atomic>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include "services/tasks.h"

namespace droidvm {
class VmService;
class NetworkConfigService;
class LegacyEvents;
}
namespace droidvm::pkg {
// A RequestException: its text is the legacy response message.
class RequestError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};
struct PkgContext {
    VmService* vms = nullptr;
    NetworkConfigService* networks = nullptr;
    LegacyEvents* events = nullptr;
    TaskService* tasks = nullptr;
    std::string data_dir; // Constants.DATA_DIR; empty = /data/data/<package>
    std::function<void(const char* level, const std::string& text)> log = [](const char*, const std::string&) {};
};
// Shared task records and a bounded background pool, with the existing legacy
// broadcasts preserved. The returned ID also works with task_get/task_cancel.
class PkgService {
public:
    static constexpr size_t max_tasks = 8;
    explicit PkgService(PkgContext context);
    ~PkgService();
    PkgService(const PkgService&) = delete;
    PkgService& operator=(const PkgService&) = delete;
    // {"task_id": ...}. Throws RequestError for legacy RequestException texts;
    // anything else is the legacy "internal error".
    Json::Value vm_export(const CallContext& caller, const Json::Value& request);
    Json::Value vm_import(const CallContext& caller, const Json::Value& request);
    // Request block-level shutdown; the owning TaskService joins before domain teardown.
    void shutdown();
private:
    PkgContext context_;
    std::shared_ptr<std::atomic<bool>> stopping_ = std::make_shared<std::atomic<bool>>(false);
    std::shared_ptr<std::atomic<size_t>> active_ = std::make_shared<std::atomic<size_t>>(0);
    TaskRef launch(const CallContext& caller, const char* kind, TaskService::Work body, TaskService::Discarded discarded);
};
}
