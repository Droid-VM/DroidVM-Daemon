// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "vm/boot_plan.h"
#include "vm/console.h"
#include "vm/hugepage.h"
#include "network/switch_runtime.h"
#include "runtime/child.h"
#include <json/json.h>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace droidvm { class LegacyEvents; }
namespace droidvm::vm {
enum class State { stopped, starting, running, suspended, stopping, rebooting };
const char* state_name(State state); // VMState.name()
struct RuntimeContext {
    network::SwitchRuntime* identities = nullptr; // recoverable VM process identities
    LegacyEvents* events = nullptr;
    PoolReservations* pool = nullptr;
    HugepagePool hugepages;
    uid_t owner = 0; // app uid owning logs and data
    std::string data_dir; // HostFacts.data_dir; empty = compile-time /data/data/<package>
    std::string cache_dir, run_dir; // console logs and boot cache; control sockets
    std::string lbx;
    std::function<bool()> shutting_down = [] { return false; };
    std::function<bool()> optimize_sdcard = [] { return true; };
    // NetworkInstance.attachNic/detachNic; attach throws with the legacy text.
    std::function<void(const std::string& network, const Json::Value& nic, const std::string& tap)> attach_nic, detach_nic;
    std::function<void(const std::string&)> warn = [](const std::string&) {}; // daemon log
};
// One VMInstance: its config, console streams and at most one VMM process.
// Lifecycle calls serialize on one lock like startLock; the process is
// watched on a worker thread that publishes every transition as an event.
class VmRuntime : public std::enable_shared_from_this<VmRuntime> {
public:
    struct StreamInfo { std::string type; bool readable = false, writable = false; int read_fd = -1, write_fd = -1; bool fd_pipe = false; };
    VmRuntime(std::string id, Json::Value config, const RuntimeContext& context);
    ~VmRuntime();
    const std::string& id() const { return id_; }
    State state() const;
    int64_t pid() const;
    Json::Value config() const;
    void replace(Json::Value config); // stopped only (vm_modify)
    bool start(std::optional<std::string> boot_entry = {});
    bool stop();
    bool reboot();
    bool suspend();
    bool resume();
    bool control(const std::string& command);
    void clear_logs();
    std::vector<std::string> streams() const;
    ConsoleLog* log(const std::string& stream) const;
    std::optional<StreamInfo> stream_info(const std::string& stream) const;
    bool write(const std::string& stream, const std::string& data);
    // stopAll: stop and wait for the worker to publish STOPPED.
    void shutdown(std::chrono::milliseconds timeout = std::chrono::seconds(30));
private:
    struct Serial { std::string stream; Fd local_read, local_write, remote_write, remote_read; };
    const std::string id_;
    RuntimeContext context_;
    mutable std::mutex lock_; // VMInstance.startLock
    mutable std::mutex state_mutex_;
    std::condition_variable idle_;
    Json::Value config_;
    State state_ = State::stopped;
    std::map<std::string, std::unique_ptr<ConsoleLog>> logs_;
    std::vector<std::string> order_;
    std::unique_ptr<Child> process_;
    std::atomic<int64_t> pid_{-1};
    std::optional<std::string> control_socket_, boot_entry_;
    std::vector<Serial> serials_;
    network::SwitchRuntime::Allocation identity_;
    std::atomic<bool> stopped_by_user_{false}, reboot_requested_{false}, reading_{true};
    bool pin_retry_used_ = false, worker_ = false;
    int exit_code_ = -1;
    void set_state(State next);
    void fire(const std::string& event, const Json::Value& extra = Json::Value());
    void create_streams();
    bool start_locked(bool relaunch);
    bool setup_taps();
    void cleanup_taps();
    void run();
    bool launch(const Json::Value& config, const BootPlan& plan, std::string& failure);
    void reap_and_cleanup();
    void finish_stopped(int code);
    void cleanup_backend();
    void read_stream(int fd, std::string name, bool also_stdio);
    int send_control(const std::string& command);
    void kill_process();
};
}
