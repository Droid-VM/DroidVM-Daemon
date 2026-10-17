// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "vm/boot_plan.h"
#include "vm/console.h"
#include "vm/input_bridge.h"
#include "vm/hugepage.h"
#include "vm/usb_acm.h"
#include "network/switch_runtime.h"
#include "runtime/child.h"
#include "services/config_gate.h"
#include "store/disk_file_leases.h"
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
    std::shared_ptr<ConfigurationGate> configuration_gate;
    // Shared holder bound once during coordinator startup, before gate recovery.
    std::shared_ptr<std::function<void(const Json::Value&)>> validate_start;
    using AcquireDisks = std::function<std::shared_ptr<config::DiskFileLeases::Lease>(const Json::Value&)>;
    std::shared_ptr<AcquireDisks> acquire_disks;
    network::SwitchRuntime* identities = nullptr; // recoverable VM process identities
    LegacyEvents* events = nullptr;
    PoolReservations* pool = nullptr;
    AcmPool* acm = nullptr; // null: USB_ACM ports degrade to a sink
    HugepagePool hugepages;
    uid_t owner = 0; // app uid owning logs and data
    std::string data_dir; // HostFacts.data_dir; empty = compile-time /data/data/<package>
    std::string cache_dir, run_dir; // console logs and boot cache; control sockets
    std::string lbx;
    std::function<bool()> shutting_down = [] { return false; };
    std::function<bool()> optimize_sdcard = [] { return true; };
    std::function<Json::Value()> app_config = [] { return Json::Value(Json::objectValue); }; // ServerContext.appConfig
    // NetworkInstance.attachNic/detachNic; attach throws with the legacy text.
    std::function<void(const std::string& network, const Json::Value& nic, const std::string& tap)> attach_nic, detach_nic;
    std::function<void(const std::string&)> warn = [](const std::string&) {}; // daemon log
    // KeyboardGrabManager.onVmState on every transition; onGuestStatus for keyboard status records.
    std::function<void(const std::string& id, const std::string& name, State state)> state_changed;
    std::function<void(const std::string& id, const std::string& screen, std::string records)> input_status;
};
// One VMInstance: its config, console streams and at most one VMM process.
// Lifecycle calls serialize on one lock like startLock; the process is
// watched on a worker thread that publishes every transition as an event.
class VmRuntime : public std::enable_shared_from_this<VmRuntime> {
public:
    // Nonblocking admission prevents inventory -> lifecycle -> network ->
    // inventory lock inversion. A valid lease pins a fully stopped instance
    // and excludes starts until configuration publication succeeds or aborts.
    class StoppedLease {
    public:
        StoppedLease(StoppedLease&&) = default;
        StoppedLease& operator=(StoppedLease&&) = delete;
        explicit operator bool() const { return lock_.owns_lock(); }
        void retire(); // commit: stale references can never start this instance
    private:
        friend class VmRuntime;
        explicit StoppedLease(std::shared_ptr<VmRuntime> target);
        std::shared_ptr<VmRuntime> target_; // outlives lock_, including on moves
        std::unique_lock<std::mutex> lock_;
    };
    StoppedLease try_edit();
    struct StreamInfo { std::string type; bool readable = false, writable = false; int read_fd = -1, write_fd = -1; bool fd_pipe = false, ready = false; };
    VmRuntime(std::string id, Json::Value config, const RuntimeContext& context);
    ~VmRuntime();
    const std::string& id() const { return id_; }
    State state() const;
    int64_t pid() const;
    Json::Value config() const;
    // DeleteHandler edits the live item in place; streams are kept.
    void set_networks(Json::Value networks) { std::lock_guard lock(state_mutex_); config_["networks"] = std::move(networks); }
    // Internal session overrides: readonly_disks (slot indices), pseudo_unprotected (true).
    // Kept across guest reboots, restored after final stop or failed admission.
    bool start(std::optional<std::string> boot_entry = {}, const Json::Value& overrides = Json::Value(), bool clear_logs = false);
    bool stop();
    bool reboot();
    bool suspend();
    bool resume();
    bool control(const std::string& command);
    bool write_input(const std::string& screen, int channel, std::string_view data) { return input_.write(screen, channel, data); }
    // getControlSocketPath(): crosvm's control socket while it has a backend;
    // nullopt for QEMU, whose socket is QMP.
    std::optional<std::string> crosvm_control_socket() const { std::lock_guard lock(state_mutex_); return qemu_ ? std::nullopt : control_socket_; }
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
    bool retired_ = false; // protected by lock_; removed/replaced inventory entry
    mutable std::mutex state_mutex_;
    std::condition_variable idle_;
    Json::Value config_;
    std::shared_ptr<config::DiskFileLeases::Lease> disk_lease_; // state_mutex_; retained across reboot
    std::optional<Json::Value> session_base_; // state_mutex_; never persisted
    State state_ = State::stopped;
    std::map<std::string, std::unique_ptr<ConsoleLog>> logs_;
    std::vector<std::string> order_;
    std::unique_ptr<Child> process_;
    std::atomic<int64_t> pid_{-1};
    std::optional<std::string> control_socket_, boot_entry_;
    bool qemu_ = false; // control_socket_ is a QMP socket
    std::vector<std::string> sockets_; // QEMU chardev sockets removed at cleanup
    std::vector<Serial> serials_;
    std::vector<std::string> acm_owners_; // ResolvedSerial.acmDevPath holders
    InputBridge input_;
    network::SwitchRuntime::Allocation identity_;
    std::atomic<bool> stopped_by_user_{false}, reboot_requested_{false}, reading_{true};
    bool pin_retry_used_ = false, worker_ = false;
    int exit_code_ = -1;
    void set_state(State next);
    void fire(const std::string& event, const Json::Value& extra = Json::Value());
    void create_streams();
    bool start_locked(bool relaunch, bool clear_logs = false);
    bool setup_taps();
    void cleanup_taps();
    void run();
    bool launch(const Json::Value& config, const BootPlan& plan, std::string& failure);
    bool launch_qemu(const Json::Value& config, const BootPlan& plan, std::string& failure);
    bool spawn(const std::vector<std::string>& argv, const std::vector<std::pair<std::string, std::string>>& env,
               const std::optional<std::string>& strace_dir, const char* label, std::string& failure);
    int send_qmp(const std::string& command);
    void reap_and_cleanup();
    void finish_stopped(int code);
    void release_disks();
    void cleanup_backend();
    void read_stream(int fd, std::string name, bool also_stdio);
    int send_control(const std::string& command);
    void kill_process();
};
}
