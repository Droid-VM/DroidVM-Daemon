// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "context.h"
#include "vm/runtime.h"
#include "network/helper_config.h"
#include <map>
#include <json/json.h>
#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace droidvm {
using VmState = vm::State;
inline const char* vm_state_name(VmState state) { return vm::state_name(state); }
// VMInstanceStore semantics. vms.json is read once at startup and never
// written: the app owns it and re-sends a config (vm_create/vm_modify)
// before every start. Each entry owns its runtime (console streams, VMM).
class VmService {
public:
    // A file that fails to load as a whole starts empty, as DataStore.load.
    VmService(int files_directory, vm::RuntimeContext context);
    explicit VmService(vm::RuntimeContext context = vm::RuntimeContext());
    ~VmService();
    Json::Value list(const CallContext& caller) const;
    Json::Value get(const CallContext& caller, const std::string& id) const;
    bool exists(const CallContext& caller, const std::string& id) const;
    VmState state(const CallContext& caller, const std::string& id) const;
    std::string create(const CallContext& caller, Json::Value config);
    // Rejects a VM that is not stopped. A rejected rename keeps the old entry.
    std::string modify(const CallContext& caller, Json::Value config);
    bool remove(const CallContext& caller, const std::string& id); // false when unknown
    // The VM's runtime; not_found carries the legacy "VM not found: <id>".
    std::shared_ptr<vm::VmRuntime> runtime(const CallContext& caller, const std::string& id) const;
    void stop_all(); // stopAll: refuses further starts
    // VMInstanceStore.autoUpAsync: starts auto_up VMs in store order on a thread of its own.
    void auto_up_async();
    Json::Value boot_scan(const CallContext& caller, const std::string& image) const; // BootPlan.scanEntries
    // SetAppConfig: the UI's settings, read at each VM start.
    void set_app_config(const CallContext& caller, Json::Value config);
    Json::Value app_config() const;
    // BridgeDhcp.buildStatics over every known VM, for each VLAN of the network.
    std::map<int, network::DhcpStatics> statics(const Json::Value& network) const;
    std::string running_vm_using(const std::string& network) const; // empty when none
    size_t loaded() const { return loaded_; }
    const std::string& load_error() const { return load_error_; }
private:
    struct Entry { std::string id; std::shared_ptr<vm::VmRuntime> vm; };
    vm::RuntimeContext context_;
    mutable std::mutex mutex_;
    std::vector<Entry> entries_;
    std::shared_ptr<std::atomic<bool>> shutting_down_ = std::make_shared<std::atomic<bool>>(false);
    mutable std::mutex app_mutex_; // read from VMM launch threads
    Json::Value app_config_{Json::objectValue};
    std::mutex sweep_mutex_;
    std::thread sweep_;
    size_t loaded_ = 0;
    std::string load_error_;
    static std::optional<std::string> canonical(const std::string& id);
    const Entry* find(const std::string& id) const;
    void add(const std::string& id, Json::Value config);
    void auto_up();
};
}
