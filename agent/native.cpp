// SPDX-License-Identifier: GPL-3.0-or-later
#include "agent/native.h"
#include "agent/rescue_sessions.h"
#include "common/identity.h"
#include "services/configuration.h"
#include "services/tasks.h"
#include "services/vm.h"
#include "store/disk_config.h"
#include "store/network_config.h"
#include "vm/console_busy.h"
#include <algorithm>
#include <map>
#include <thread>

namespace droidvm::agent {
namespace {
class Control final : public RunnerControl {
public:
    explicit Control(TaskControl& control) : control_(control) {}
    bool cancellation_requested() const override { return control_.cancellation_requested(); }
    bool enter_commit() override { return control_.enter_commit(); }
private:
    TaskControl& control_;
};

// Shared custody is acquired before automation starts. A failed registry
// publication leaves Host's reference intact for its mandatory cleanup path.
class MaintenanceTarget final : public RescueTarget {
public:
    MaintenanceTarget(std::unique_ptr<VmService::ManagedVm> owner, std::shared_ptr<const void> reservation)
        : reservation_(std::move(reservation)), owner_(std::move(owner)), runtime_(owner_->runtime()) {}
    std::shared_ptr<vm::VmRuntime> runtime() const { return runtime_; }
    void retain_disks() { disks_ = runtime_->private_disk_lease(); }
    void bind_rescue(const vm::Observation& expected) { rescue_expected_ = expected; }
    vm::Observation observation() override {
        const auto target = runtime_->console_target();
        if (rescue_expected_ && target.observed != *rescue_expected_)
            throw ServiceError(ErrorCode::conflict, "Rescue incarnation changed");
        if (std::find(target.streams.begin(), target.streams.end(), operation_stream) == target.streams.end())
            throw ServiceError(ErrorCode::conflict, "Rescue console unavailable");
        return target.observed;
    }
    vm::LogSlice read(const vm::Observation& expected, const std::optional<vm::LogCursor>& cursor, bool tail) override {
        return runtime_->console_read(std::string(operation_stream), expected, cursor, tail);
    }
    size_t write(const vm::Observation& expected, std::string_view bytes) override {
        return runtime_->console_write(std::string(operation_stream), expected, bytes);
    }
    CleanupReport close() override { return close_until(RunnerClock::now() + std::chrono::seconds(45)); }
    CleanupReport close_until(RunnerDeadline deadline) {
        if (closed_) return cleanup_;
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - RunnerClock::now());
        const auto soft = std::max(std::chrono::milliseconds::zero(), remaining - std::chrono::seconds(10));
        owner_->remove(soft);
        // Stop/retire first, while both the exact file lease and registry
        // reservation still belong to this custody object. No shell commands
        // are injected: a human terminal could have an arbitrary foreground job.
        bool synced = false;
        if (disks_ && RunnerClock::now() < deadline) {
            try { disks_->sync_writes(); synced = RunnerClock::now() <= deadline; }
            catch (...) { /* Never publish filesystem paths or exception text. */ }
        }
        cleanup_ = {true, true, synced};
        closed_ = true;
        disks_.reset();
        reservation_.reset();
        return cleanup_;
    }
private:
    // Release protected files before the registry reservation. A dropped owner
    // becomes a retained VmService orphan; destruction never silently removes it.
    std::shared_ptr<const void> reservation_;
    std::unique_ptr<VmService::ManagedVm> owner_;
    std::shared_ptr<vm::VmRuntime> runtime_;
    std::shared_ptr<config::DiskFileLeases::Lease> disks_;
    std::optional<vm::Observation> rescue_expected_;
    bool closed_ = false;
    CleanupReport cleanup_;
};

class Host final : public RunnerHost {
public:
    Host(std::shared_ptr<MaintenanceTarget> target, RescueSessions* sessions,
        const CallContext& caller, std::string disk_id, std::string& session_id)
        : target_(std::move(target)), runtime_(target_->runtime()), sessions_(sessions),
          caller_(caller), disk_id_(std::move(disk_id)), session_id_(session_id) {}
    bool start(RunnerDeadline deadline) override {
        if (now() >= deadline || !runtime_->start()) return false;
        // Capture the lease already granted to this run. A very early worker
        // exit may have released it; never reacquire a newer file as evidence.
        target_->retain_disks();
        return true;
    }
    RunState poll(RunnerDeadline deadline) override {
        if (now() >= deadline) return RunState::lost;
        const auto state = runtime_->state();
        if (state == vm::State::starting && !observed_) return RunState::starting;
        if (state == vm::State::stopped) return RunState::stopped;
        if (state != vm::State::running) return RunState::lost;
        try {
            const auto target = runtime_->console_target();
            if (std::find(target.streams.begin(), target.streams.end(), operation_stream) == target.streams.end())
                return RunState::lost;
            if (observed_ && *observed_ != target.observed) return RunState::lost;
            observed_ = target.observed;
            return RunState::running;
        } catch (const vm::ConsoleBusy&) {
            return observed_ ? RunState::running : RunState::starting;
        }
    }
    std::optional<vm::LogSlice> read(const std::optional<vm::LogCursor>& cursor, RunnerDeadline deadline) override {
        require_live(deadline);
        try { return runtime_->console_read(std::string(operation_stream), *observed_, cursor, false); }
        catch (const vm::ConsoleBusy&) { return std::nullopt; }
    }
    WriteResult write(std::string_view bytes, RunnerDeadline deadline) override {
        require_live(deadline);
        // Exceptions are intentionally not retried: the runner treats an
        // unreported actual write length as unknown and clears its secret.
        return {true, runtime_->console_write(std::string(operation_stream), *observed_, bytes)};
    }
    CleanupReport shutdown(RunnerDeadline deadline) override {
        return target_->close_until(deadline);
    }
    bool handoff(RunnerDeadline deadline) override {
        if (!sessions_ || !observed_ || now() >= deadline) return false;
        // Pin the automation's exact run before clearing history/publication.
        // A transition between these operations must reject the handoff rather
        // than silently accepting a newer running incarnation or revision.
        target_->bind_rescue(*observed_);
        runtime_->prepare_private_console_handoff(*observed_);
        if (now() >= deadline) return false;
        session_id_ = sessions_->publish(caller_, disk_id_, target_);
        // publish has a strong exception guarantee. Its success is the single
        // custody transfer point; no throwing work may follow that publication.
        return true;
    }
    RunnerDeadline now() const noexcept override { return RunnerClock::now(); }
    void wait_until(RunnerDeadline deadline) override { std::this_thread::sleep_until(deadline); }
private:
    std::shared_ptr<MaintenanceTarget> target_;
    std::shared_ptr<vm::VmRuntime> runtime_;
    RescueSessions* sessions_;
    const CallContext& caller_;
    std::string disk_id_;
    std::string& session_id_;
    std::optional<vm::Observation> observed_;
    void require_live(RunnerDeadline deadline) const {
        if (!observed_ || now() >= deadline)
            throw ServiceError(ErrorCode::unavailable, "Agent console is unavailable");
    }
};
}

NativeResult run_managed(ConfigurationService& configuration, const CallContext& caller,
        Request request, const Confirmation& confirmed, const std::string& data_dir, TaskControl& control,
        NativeRunOptions options) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || !caller.manage_tasks || caller.principal.empty())
        throw ServiceError(ErrorCode::permission_denied, "Administrator permission required");
    if (!configuration.disks() || !configuration.disk_files())
        throw ServiceError(ErrorCode::unavailable, "Agent requires coordinated disk ownership");
    if (confirmed.disk_revision.empty() || confirmed.vm_revision.empty())
        throw ServiceError(ErrorCode::invalid_argument, "Agent requires confirmed disk and VM revisions");
    if (data_dir.empty() || data_dir.front() != '/' || data_dir.find('\0') != std::string::npos)
        throw ServiceError(ErrorCode::invalid_argument, "Agent assets require an absolute data directory");

    const auto disks = configuration.disks()->snapshot(caller);
    const auto vms = configuration.vms().snapshot(caller);
    if (disks->revision != confirmed.disk_revision || vms->revision != confirmed.vm_revision)
        throw ServiceError(ErrorCode::conflict, "Agent confirmation is stale");
    std::map<std::string, std::string> path_ids;
    std::string path;
    for (const auto& row : disks->document["disks"]) {
        const auto id = config::uuid(row), disk_path = config::disk_path(row);
        path_ids.emplace(disk_path, id);
        if (id == request.disk_id()) path = disk_path;
    }
    if (path.empty()) throw ServiceError(ErrorCode::not_found, "Agent disk not found");
    const auto vm_id = random_id(true);
    auto definition = build_rescue_vm({vm_id, "agent-" + vm_id,
        data_dir + "/usr/share/droidvm/vmlinuz", data_dir + "/usr/share/droidvm/initramfs.img", path});
    // Reuse runtime admission: invalid ancestry, children and shared writable
    // targets are rejected. File identity/active VM conflicts are checked again
    // by runtime.start while acquiring its existing retained file leases.
    config::validate_disk_start(definition, vms->document, disks->document);
    std::set<std::string> ancestors;
    for (const auto& file : config::disk_start_files(definition, disks->document))
        if (file.path != path) ancestors.insert(path_ids.at(file.path));
    auto reservation = configuration.reserve_disks(confirmed.disk_revision, {request.disk_id()},
        ancestors, confirmed.vm_revision);

    std::vector<Action> actions{{request.action(), false, request.normal_users()}};
    Protocol protocol(rescue_script(actions, true), actions, std::string(request.password()), true,
        options.rescue_sessions != nullptr);
    request.clear_password();
    Control task(control);
    NativeResult result;
    result.managed_vm_id = vm_id;
    // Keep our own reservation until Host (and its retained file lease) has
    // finished syncing. On failed removal the inventory keeps its own copy.
    auto owner = configuration.inventory().create_managed(std::move(definition), reservation);
    auto target = std::make_shared<MaintenanceTarget>(std::move(owner), reservation);
    Host host(std::move(target), options.rescue_sessions, caller, request.disk_id(), result.rescue_session_id);
    result.execution = run(protocol, host, task);
    return result;
}
}
