// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "context.h"
#include "vm_config.h"
#include "vm/runtime.h"
#include "network/helper_config.h"
#include <map>
#include <json/json.h>
#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <set>
#include <thread>
#include <vector>

namespace droidvm {
class HostPreferencesService;
class UsbAcmService;
using VmState = vm::State;
inline const char* vm_state_name(VmState state) { return vm::state_name(state); }
// Legacy mode reads vms.json once: the app owns it and re-sends a config
// before each start. A VmConfigService participant instead owns a revisioned
// persistent inventory and disables legacy writes. Production still uses
// legacy mode. Each entry owns its runtime (console streams, VMM).
class VmService {
    struct ManagedLifetime;
    struct ManagedClaim;
public:
    // Trusted internal ownership, never reconstructed from request JSON or an ID.
    // Dropping the handle marks its registered VM as orphaned without stopping
    // or removing it. Explicit removal or trusted recovery performs cleanup.
    class ManagedVm {
    public:
        ManagedVm(const ManagedVm&) = delete;
        ManagedVm& operator=(const ManagedVm&) = delete;
        ~ManagedVm() = default;
        const std::string& id() const { return target_->id(); }
        std::shared_ptr<vm::VmRuntime> runtime() const;
        // Idempotent after successful removal. Failure preserves inventory and
        // reservations; shutdown is followed by stopped admission and retirement.
        void remove(std::chrono::milliseconds timeout = std::chrono::seconds(30));
    private:
        friend class VmService;
        ManagedVm(std::shared_ptr<ManagedLifetime> lifetime, std::shared_ptr<ManagedClaim> claim,
            std::shared_ptr<vm::VmRuntime> target);
        std::shared_ptr<ManagedLifetime> lifetime_;
        std::shared_ptr<vm::VmRuntime> target_;
        std::shared_ptr<ManagedClaim> claim_;
    };
    // A file that fails to load as a whole starts empty, as DataStore.load.
    VmService(int files_directory, vm::RuntimeContext context, HostPreferencesService* preferences = nullptr, UsbAcmService* acm_preferences = nullptr,
        HostPreferencesService* disk_defaults = nullptr);
    explicit VmService(vm::RuntimeContext context = vm::RuntimeContext(), HostPreferencesService* preferences = nullptr, UsbAcmService* acm_preferences = nullptr,
        HostPreferencesService* disk_defaults = nullptr);
    ~VmService();
    Json::Value list(const CallContext& caller) const;
    Json::Value get(const CallContext& caller, const std::string& id) const;
    bool exists(const CallContext& caller, const std::string& id) const;
    VmState state(const CallContext& caller, const std::string& id) const;
    std::string create(const CallContext& caller, Json::Value config);
    // Internal rescue-profile admission only: isolation is set by this method,
    // not a JSON property. ConfigurationService must outlive accepted work.
    // Reservation release alone may follow coordinator teardown via shared
    // state; this does not extend the runtime's other dependency lifetimes.
    // Complete worker shutdown/managed cleanup before inventory destruction;
    // failure retains entries and reservations for a later cleanup retry.
    std::unique_ptr<ManagedVm> create_managed(Json::Value config,
        std::shared_ptr<const void> reservation = {});
    // Trusted recovery/status only; these return IDs, never private runtimes.
    std::vector<std::string> pending_orphaned_managed() const;
    // Attempts the current orphan snapshot; live owners and ordinary VMs are
    // untouched. timeout is per target, plus VmRuntime's final kill wait.
    // Failures retain their entries/reservations. Returns all remaining orphans,
    // including any whose owner disappeared after the initial snapshot.
    std::vector<std::string> recover_managed(
        std::chrono::milliseconds timeout = std::chrono::seconds(30));
    // Rejects a VM that is not stopped. A rejected rename keeps the old entry.
    std::string modify(const CallContext& caller, Json::Value config);
    bool remove(const CallContext& caller, const std::string& id); // false when unknown
    // Internal single-writer participant, called with normalized complete document.
    // Attach before loading/serving legacy inventory. Commit disables legacy writes.
    // Owner must outlive the returned transaction and its VmConfigService.
    std::unique_ptr<VmConfigService::Commit> prepare_config(const Json::Value& document,
        const std::set<std::string>& disk_affected = {});
    // The VM's runtime; not_found carries the legacy "VM not found: <id>".
    std::shared_ptr<vm::VmRuntime> runtime(const CallContext& caller, const std::string& id) const;
    // Internal managed start. expected is a definition from a fixed persistent
    // snapshot, never a runtime projection. No implicit rebase or file write.
    bool start_configured(const CallContext& caller, const std::string& id,
        const Json::Value& expected, const Json::Value& overrides = Json::Value(),
        std::optional<std::string> boot_entry = {}, std::optional<bool> clear_logs = {}, std::optional<vm::Observation> observed = {});
    void stop_all(); // stopAll: refuses further starts
    // VMInstanceStore.autoUpAsync: starts auto_up VMs in store order on a thread of its own.
    void auto_up_async();
    Json::Value boot_scan(const CallContext& caller, const std::string& image) const; // BootPlan.scanEntries
    // SetAppConfig: the UI's settings, read at each VM start.
    void set_app_config(const CallContext& caller, Json::Value config);
    Json::Value app_config() const;
    // Validate shared startup preferences before any log clearing, while an
    // explicit per-start boolean overrides only the clear-logs default.
    bool clear_logs_before_start(std::optional<bool> override = {}) const;
    // BridgeDhcp.buildStatics over every known VM, for each VLAN of the network.
    std::map<int, network::DhcpStatics> statics(const Json::Value& network) const;
    std::string running_vm_using(const std::string& network) const; // empty when none
    // DeleteHandler: names of VMs not stopped that use the network, in store order.
    std::vector<std::string> busy_vms_using(const std::string& network) const;
    // Legacy inventory-only operation: stopped leases protect an all-or-none
    // replacement of affected VMs and retire stale references. No file commit.
    void drop_network(const std::string& network);
    // VMInstanceStore.findVMByTap: a running VM with this TAP, as {vm_id, vm_name}.
    Json::Value vm_by_tap(const std::string& tap) const;
    size_t loaded() const { return loaded_; }
    const std::string& load_error() const { return load_error_; }
private:
    friend class ConfigurationService;
    // temporary: an Agent VM ("temporary": true) kept in memory only, outside
    // the persistent configuration; it survives configuration updates.
    struct Entry {
        std::string id;
        // Declared before vm so runtime destruction precedes reservation release.
        std::shared_ptr<const void> reservation;
        std::shared_ptr<vm::VmRuntime> vm;
        Json::Value definition;
        bool temporary = false;
        bool managed = false; // trusted membership, independent of all JSON fields
        std::weak_ptr<ManagedClaim> managed_claim{}; // only ManagedVm keeps it alive
    };
    class ConfigUpdate;
    vm::RuntimeContext context_;
    HostPreferencesService* preferences_;
    UsbAcmService* acm_preferences_;
    HostPreferencesService* disk_defaults_;
    std::shared_ptr<ManagedLifetime> managed_lifetime_;
    mutable std::mutex mutex_;
    std::vector<Entry> entries_;
    bool config_managed_ = false; // mutex_: persistent configuration owns inventory
    std::shared_ptr<std::atomic<bool>> shutting_down_ = std::make_shared<std::atomic<bool>>(false);
    mutable std::mutex app_mutex_; // read from VMM launch threads
    Json::Value app_config_{Json::objectValue};
    std::mutex sweep_mutex_;
    std::thread sweep_;
    size_t loaded_ = 0;
    std::string load_error_;
    static std::optional<std::string> canonical(const std::string& id);
    const Entry* find(const std::string& id) const;
    void add(const std::string& id, Json::Value config, bool managed = false,
        std::shared_ptr<const void> reservation = {}, std::weak_ptr<ManagedClaim> claim = {});
    void remove_managed(const std::shared_ptr<vm::VmRuntime>& target, std::chrono::milliseconds timeout);
    void require_legacy_writer() const; // mutex_ held
    void auto_up();
};
}
