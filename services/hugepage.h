// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "tasks.h"
#include "vm/hugepage.h"
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace droidvm {
struct HugepageCommandResult {
    int exit_code = -1;
    bool uncertain = false;
    std::string output, error;
};
struct HugepageOptions {
    std::string parameters = "/sys/module/gh_hugepage_reserve/parameters";
    std::string module_directory = "/data/adb/modules/gh-hugepage-reserve";
    // Trusted composition only. No HTTP/IPC input controls paths, argv, or hooks.
    std::function<bool(const std::string&)> exists;
    // A mode-bit capability observation, not a guarantee that a later kernel
    // write succeeds. Unknown permissions must return false.
    std::function<bool(const std::string&)> writable;
    std::function<std::string(const std::string&)> identity;
    std::function<std::optional<std::string>(const std::string&, size_t)> read;
    std::function<bool(const std::string&, const std::string&)> write;
    std::function<void(const std::string&, const std::string&)> publish;
    std::function<void(const std::string&, bool)> marker;
    std::function<HugepageCommandResult(const std::vector<std::string>&)> run;
    std::function<void(int64_t)> manual_changed;
    // Optional lifecycle line for the daemon log (droidvmd.log); null in tests.
    std::function<void(const char*, const std::string&)> log;
};
// One typed owner shared by local IPC and HTTP adapters. PoolReservations is
// also used by every Gunyah runtime; no transport-specific mutation mutex.
// Lifetime: stop TaskService before destroying this service or its pool.
class HugepageService {
public:
    static constexpr const char* capability = "coordinated-hugepages-v1";
    HugepageService(TaskService&, vm::PoolReservations&, HugepageOptions = {});
    ~HugepageService();
    Json::Value snapshot(const CallContext&);
    TaskView start(const CallContext&, const Json::Value& request);
    TaskView status(const CallContext&, const std::string& request_id);
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
