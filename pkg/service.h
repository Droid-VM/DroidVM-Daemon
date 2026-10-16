// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <atomic>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

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
    std::string data_dir; // Constants.DATA_DIR; empty = /data/data/<package>
    std::function<void(const char* level, const std::string& text)> log = [](const char*, const std::string&) {};
};
// ExportHandler/ImportHandler with VMExportTask/VMImportTask. Each accepted
// request runs on a thread of its own and reports only through the legacy
// vm_export_status/vm_import_status broadcasts, keyed by the returned
// task_id; there is no status or cancel command, as before.
class PkgService {
public:
    static constexpr size_t max_tasks = 8;
    explicit PkgService(PkgContext context);
    ~PkgService();
    PkgService(const PkgService&) = delete;
    PkgService& operator=(const PkgService&) = delete;
    // {"task_id": ...}. Throws RequestError for legacy RequestException texts;
    // anything else is the legacy "internal error".
    Json::Value vm_export(const Json::Value& request);
    Json::Value vm_import(const Json::Value& request);
    // Running tasks stop at their next block, clean up as on failure and are joined.
    void shutdown();
private:
    struct Running { std::thread thread; std::shared_ptr<std::atomic<bool>> finished; };
    PkgContext context_;
    std::shared_ptr<std::atomic<bool>> stopping_ = std::make_shared<std::atomic<bool>>(false);
    std::mutex mutex_;
    std::list<Running> running_;
    void launch(std::function<void()> body);
};
}
