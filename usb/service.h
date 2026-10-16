// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "usb/control.h"
#include "usb/device.h"
#include "usb/engine.h"
#include "usb/host.h"
#include "usb/rules_file.h"
#include "usb/watch.h"
#include "usb/worker.h"
#include <json/json.h>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

// Port of daemon/usb/UsbPassthroughManager and the ipc/usb handlers.
namespace droidvm::usb {
// What the service needs to know about one VM, read fresh on every call.
struct UsbVm {
    std::string id;   // VMInstance.getId().toString()
    std::string name; // VMInstance.getName()
    VmState state = VmState::stopped;
    // getControlSocketPath(): the crosvm control socket while a backend
    // instance exists; nullopt for QEMU (its socket is QMP) and when stopped.
    std::optional<std::string> control_socket;
    Json::Value config; // the migrated item: its peripherals list the xHCI controllers
};
class UsbVms {
public:
    virtual ~UsbVms() = default;
    // VMInstanceStore.findById(String): nullopt for an unknown or malformed id.
    virtual std::optional<UsbVm> find(const std::string& id) const = 0;
    virtual std::vector<UsbVm> list() const = 0; // store order
    // The "stderr" console stream: ConsoleStream.mark() and since(mark).
    // nullopt when the VM has no such stream.
    virtual std::optional<uint64_t> stderr_mark(const std::string&) const { return std::nullopt; }
    virtual std::string stderr_since(const std::string&, uint64_t) const { return {}; }
};
// VMXhciConfig.findController: the controller [wanted] names, the first
// when it is null; its id ("" for an id-less entry), nullopt when none.
std::optional<std::string> find_controller(const Json::Value& config, const std::optional<std::string>& wanted);

struct UsbTiming {
    std::chrono::milliseconds quiet_period{300};          // UsbHostInventory.QUIET_PERIOD_MS
    std::chrono::milliseconds auto_attach_debounce{400};  // AUTO_ATTACH_DEBOUNCE_MS
    std::chrono::milliseconds usbfs_release_timeout{10000}, usbfs_poll{200};
    std::chrono::milliseconds interfaces_timeout{3000}, interfaces_poll{100}; // UsbProbe
    std::chrono::milliseconds vmm_log_grace{100};
    std::chrono::milliseconds ready_poll{1000};
    int ready_max_polls = 60;
    std::chrono::milliseconds retry_delay{2000};
    int max_retries = 3;
    std::chrono::milliseconds shutdown_wait{5000};
};
struct UsbOptions {
    std::string sys_root = "/sys";          // bus/usb/{devices,drivers,drivers_probe,drivers_autoprobe}
    std::string dev_root = "/dev/bus/usb";  // only builds node paths
    std::string files_dir;                  // <DATA_DIR>/files; empty = rules are not persisted
    UsbVms* vms = nullptr;
    UsbControl* control = nullptr;
    std::unique_ptr<UsbWatch> watch;        // null = no inventory watch
    std::shared_ptr<SysfsWriter> writer;    // null = real writes
    std::function<void(const Json::Value& data)> publish; // LegacyEvents::publish
    std::function<void(const char* level, const std::string& message)> log;
    UsbTiming timing;
};

class UsbService {
public:
    explicit UsbService(UsbOptions options);
    ~UsbService();
    UsbService(const UsbService&) = delete;
    UsbService& operator=(const UsbService&) = delete;
    // UsbPassthroughManager.start: rules, the autoprobe gate, the watch, the
    // authorized=0 migration and the daemon-start pass (which recovers what
    // a killed daemon left idle). Never throws.
    void start();
    // Only the first step of start(): read usb_rules.json into the engine.
    void load_rules();
    // shutdown(): reopens the gate, stops the watch, drains the worker.
    void shutdown();
    // The eight handlers. [params] is the request object; the result holds
    // the response fields besides success. RequestError carries the legacy
    // message; any other exception is the legacy "internal error".
    Json::Value usb_attach(const Json::Value& params);
    Json::Value usb_detach(const Json::Value& params);
    Json::Value usb_host_list(const Json::Value& params);
    Json::Value usb_rules_get(const Json::Value& params);
    Json::Value usb_rules_set(const Json::Value& params);
    Json::Value usb_rules_test(const Json::Value& params);
    Json::Value usb_set_target(const Json::Value& params);
    Json::Value usb_vm_list(const Json::Value& params);
    // VMInstance.setState hook: call after every transition, once find()
    // reports the new state. Never throws.
    void on_vm_state(const std::string& vm_id, VmState state);
    // Test hook: waits for the inventory and the worker to go idle.
    bool settle(std::chrono::milliseconds timeout);

    struct Attachment {
        std::string vm_id, vm_name;
        int port = 0;
        std::string sysfs, vid, pid, node;
        std::optional<std::string> controller;
        std::optional<Decision> rule; // null for a manual attach
        const char* source() const { return rule ? "auto" : "manual"; }
    };
    // Rows exactly as hostList / testRules / vmList build them.
    static Json::Value host_row(const HostDevice& device, const Attachment* attachment, bool locked);
    static Json::Value test_row(const HostDevice& device, const Attachment* attachment, bool locked, const std::optional<Decision>& decision);
    static Json::Value rule_json(const Decision& decision);
    static Json::Value decision_json(const Decision& decision);
private:
    enum class Claim { none, host, vmm };
    struct PassResult { int applied = 0; bool unreachable = false; };
    UsbOptions options_;
    std::string devices_, drivers_, probe_path_, autoprobe_path_;
    RulesFile rules_file_;
    std::shared_ptr<SysfsWriter> writer_;
    Worker worker_{"usb-manager"};
    Worker inventory_worker_{"usb-inventory"};
    Probe probe_;
    mutable std::mutex lock_; // UsbPassthroughManager.lock
    std::map<std::string, Attachment> attachments_;
    // HashMap iteration order of attachments: (bucket, insertion) at the
    // capacity the map has grown to.
    std::map<std::string, uint64_t> attach_order_;
    uint64_t attach_sequence_ = 0;
    uint32_t attach_capacity_ = 16;
    bool started_ = false, shut_down_ = false;
    std::map<std::string, int> stop_epochs_;
    Leftovers leftovers_;
    RuleEngine engine_;
    Worker::Cancel pending_auto_;
    // UsbHostInventory
    std::mutex rescan_mutex_, watch_mutex_;
    std::vector<HostDevice> snapshot_;
    bool buses_moved_ = false, watching_ = false;
    Worker::Cancel pending_rescan_;

    void put_attachment(Attachment attachment);
    void erase_attachment(const std::string& sysfs);
    std::vector<Attachment> ordered_attachments() const;
    void log(const char* level, const std::string& message) const { if (options_.log) options_.log(level, message); }
    std::optional<UsbVm> find_vm(const std::string& id) const;
    std::optional<VmState> state_of(const std::string& vm) const;
    bool vm_has_controller(const std::string& vm, const std::optional<std::string>& controller) const;
    StateOf state_fn() const { return [this](const std::string& vm) { return state_of(vm); }; }
    HasController controller_fn() const { return [this](const std::string& vm, const std::optional<std::string>& c) { return vm_has_controller(vm, c); }; }
    Scheduler scheduler();
    void schedule(std::function<void()> task, std::chrono::milliseconds delay = std::chrono::milliseconds(0));
    // inventory
    std::vector<HostDevice> scan() const;
    std::vector<HostDevice> rescan_now();
    void schedule_rescan(bool buses_moved);
    void on_inventory_changed(const Diff& diff);
    // manager
    void set_autoprobe(bool autoprobe);
    bool set_authorized(const std::string& sysfs);
    std::vector<std::string> authorize_what_an_older_build_hid();
    void await_interfaces(const std::vector<std::string>& devices);
    Json::Value host_list();
    Json::Value test_rules();
    Json::Value vm_list(const std::string& vm_id) const;
    std::optional<std::string> attached_controller(const std::string& sysfs) const;
    int set_rules(const Json::Value& json);
    int attach(const UsbVm& vm, const std::string& sysfs);
    int attach(const UsbVm& vm, const std::string& sysfs, const std::optional<std::string>& wanted, const std::optional<Decision>& rule);
    HostDevice read_unlisted_device(const std::string& sysfs) const;
    std::optional<HostDevice> fresh_device_at(const std::string& sysfs) const;
    int stop_epoch(const std::string& vm_id) const;
    void detach(const UsbVm& vm, const std::optional<std::string>& sysfs, std::optional<int> port);
    void drop_attachment(const Attachment& attachment, const UsbVm& vm);
    Json::Value set_target(const std::string& sysfs, Target target, const std::optional<UsbVm>& vm, const std::optional<std::string>& controller);
    void set_target_host(const HostDevice& device, const std::optional<Attachment>& previous);
    void set_target_sink(const HostDevice& device, const std::optional<Attachment>& previous);
    int set_target_vm(const UsbVm& vm, const HostDevice& device, const std::optional<std::string>& controller, const std::optional<Attachment>& previous, bool was_locked);
    void drop_from_holder(const Attachment& attachment);
    void release_all(const std::string& vm_id, const std::string& vm_name);
    std::vector<HostDevice> scan_host();
    void notice_leftovers(const std::vector<HostDevice>& devices);
    int recover_leftovers(const std::vector<std::string>& ifaces, const std::string& reason);
    bool vm_gone(const std::string& vm_id) const;
    void schedule_auto_attach(const std::string& reason);
    void queue_auto_attach_when_ready(const UsbVm& vm);
    int run_auto_attach_and_wait(const std::string& reason);
    int release_everything_and_wait();
    int release_everything();
    int run_pass(const std::string& reason, bool daemon_start);
    void run_pass_quietly(const std::string& reason, bool daemon_start);
    std::optional<PassResult> run_auto_attach_or_null(const std::string& reason, bool daemon_start);
    PassResult run_auto_attach(const std::string& reason, bool daemon_start);
    void broadcast_auto(const char* event, const UsbVm& vm, const Decision& decision, const std::optional<std::string>& error);
    void release_unplugged(const Attachment& attachment);
    int unbind_host_drivers(const std::string& sysfs);
    std::vector<std::string> driverless_root_hubs() const;
    bool needs_host_drivers(const std::string& sysfs) const;
    void drivers_probe(const std::string& name);
    void lock_device(const std::string& sysfs);
    void lock_device(const std::string& sysfs, int devnum);
    bool still_free(const std::string& sysfs, int devnum) const;
    bool rules_leave_it_idle(const std::string& sysfs);
    void restore_host_drivers(const std::string& sysfs, const std::string& vm_id);
    std::vector<std::string> restore_interfaces(const std::vector<std::pair<std::string, std::string>>& iface_to_vm, bool recovery);
    void await_vmm_released(const std::string& sysfs);
    Claim await_released(const std::string& iface);
    std::string vmm_log_since(const std::string& vm_id, std::optional<uint64_t> mark);
    void broadcast_host();
    void broadcast_vm(const std::string& vm_id, const std::optional<std::string>& vm_name);
    void broadcast(const char* event, Json::Value data);
};
}
