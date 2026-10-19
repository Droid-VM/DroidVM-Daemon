// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "tasks.h"
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace droidvm {
// Called only while VmRuntime::inspect_process pins its owned Child. Reading a
// PID alone must never establish a VM or a historical kernel-owner identity.
std::optional<std::string> hugepage_process_start_ticks(int pid);
struct HugepageVmProcess {
    std::string id, name;
    int pid = -1;
    std::string start_ticks, runtime_instance;
    uint64_t runtime_revision = 0;
};
enum class HugepageProcessReadState { present, missing, denied, failed };
struct HugepageProcessRead {
    HugepageProcessReadState state = HugepageProcessReadState::missing;
    std::string text;
    bool truncated = false;
};
class HugepageProcessHandle {
public:
    virtual ~HugepageProcessHandle() = default;
    virtual bool alive() = 0;
    // Send exactly one requested signal; false means the held process exited.
    virtual bool signal(int number) = 0;
};
struct HugepageProcessOptions {
    std::string parameters = "/sys/module/gh_hugepage_reserve/parameters";
    std::string proc_directory = "/proc";
    size_t max_entries = 256;
    // Trusted providers, never reconstructed from client-supplied VM JSON.
    std::function<std::vector<HugepageVmProcess>()> running_vms;
    // Must revalidate runtime instance/revision and owned Child under its
    // lifecycle locks. TERM is not a request to call generic VM stop().
    std::function<bool(const HugepageVmProcess&, int)> signal_vm;
    std::function<HugepageProcessRead(const std::string&, size_t)> read;
    std::function<std::unique_ptr<HugepageProcessHandle>(int)> open_process;
    std::function<uint64_t()> wall_ms;
    // Optional authoritative module integration. It must bind a KO record to
    // its original process birth; consulting current /proc/PID/stat is NOT a
    // valid implementation. Existing released KO records do not supply this.
    std::function<std::optional<std::string>(int)> owner_start_ticks;
    int daemon_pid = 0; // zero selects this process
};
class HugepageProcessService {
public:
    static constexpr const char* capability = "hugepage-processes-v1";
    HugepageProcessService(TaskService&, HugepageProcessOptions = {});
    ~HugepageProcessService();
    Json::Value snapshot(const CallContext&, const std::string& source = "auto");
    Json::Value stack(const CallContext&, const Json::Value& expected);
    TaskView start(const CallContext&, const Json::Value& request);
    TaskView status(const CallContext&, const std::string& request_id);
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
