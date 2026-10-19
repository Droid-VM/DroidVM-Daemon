// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "agent/plan.h"
#include "common/identity.h"
#include "services/configuration.h"
#include "services/vm.h"
#include <atomic>
#include <filesystem>
#include <fcntl.h>
#include <unistd.h>

using namespace droidvm;
using namespace droidvm::test;
namespace {
struct Fixture {
    std::filesystem::path directory = std::filesystem::temp_directory_path() / ("managed-vm-" + random_id(true));
    vm::RuntimeContext context;
    std::atomic<int> starts{0};
    Fixture() {
        std::filesystem::create_directory(directory);
        context.cache_dir = context.run_dir = directory.string();
        context.owner = getuid();
        // No test may launch a backend or prepare host devices.
        context.shutting_down = [&] { ++starts; return true; };
    }
    ~Fixture() { std::error_code error; std::filesystem::remove_all(directory, error); }
};
Json::Value rescue(const std::string& name = "agent-managed-contract") {
    return agent::build_rescue_vm({random_id(true), name, "/builtin/kernel", "/builtin/initrd", "/registered/disk"});
}
Json::Value document() {
    Json::Value value;
    value["vms"] = Json::Value(Json::arrayValue);
    return value;
}
void publish(VmService& service, const Json::Value& value) {
    auto update = service.prepare_config(value);
    update->commit();
}
void hidden_capability_and_json_independence() {
    Fixture fixture;
    VmService service(fixture.context);
    auto definition = rescue();
    auto owner = service.create_managed(definition);
    const auto id = owner->id();
    check(owner->runtime()->id() == id && service.list(admin).empty() && !service.exists(admin, id),
        "managed owner alone can resolve its runtime");
    error(ErrorCode::not_found, [&] { service.runtime(admin, id); });
    error(ErrorCode::not_found, [&] { service.get(admin, id); });
    error(ErrorCode::not_found, [&] { service.state(admin, id); });
    error(ErrorCode::not_found, [&] { service.modify(admin, definition); });
    error(ErrorCode::not_found, [&] { service.start_configured(admin, id, definition); });
    check(!service.remove(admin, id), "ordinary removal cannot stop or delete a managed VM");
    error(ErrorCode::conflict, [&] { service.create(admin, definition); });
    error(ErrorCode::conflict, [&] { service.create_managed(definition); });
    check(owner->runtime()->state() == VmState::stopped && fixture.starts == 0,
        "public operations never reach the private lifecycle");

    auto ordinary = rescue("ordinary-agent-flags");
    ordinary["managed"] = true;
    ordinary["private_console"] = true;
    const auto public_id = service.create(admin, ordinary);
    check(service.exists(admin, public_id) && service.list(admin).size() == 1 &&
        service.runtime(admin, public_id)->id() == public_id,
        "JSON fields cannot forge managed membership or hide an ordinary VM");
    check(service.remove(admin, public_id), "ordinary lifecycle remains available");
    owner->remove();
}
void updates_preserve_private_owner() {
    Fixture fixture;
    VmService service(fixture.context);
    publish(service, document());
    auto definition = rescue();
    auto owner = service.create_managed(definition);
    auto runtime = owner->runtime();
    auto next = document();
    Json::Value row;
    row["id"] = random_id(true);
    row["name"] = "saved-vm";
    next["vms"].append(row);
    publish(service, next);
    check(owner->runtime() == runtime && service.list(admin).size() == 1,
        "persistent updates keep managed runtime identity without exposing it");
    error(ErrorCode::not_found, [&] { service.start_configured(admin, owner->id(), definition); });
    auto collision = document();
    collision["vms"].append(definition);
    error(ErrorCode::conflict, [&] { publish(service, collision); });
    collision["vms"][0]["id"] = random_id(true);
    error(ErrorCode::conflict, [&] { publish(service, collision); });
    check(owner->runtime() == runtime && service.exists(admin, row["id"].asString()),
        "ID and name collisions cannot replace managed or persistent entries");
    publish(service, document());
    check(owner->runtime() == runtime && service.list(admin).empty(),
        "complete persistent replacement preserves private temporary entries");
    owner->remove();
}
void explicit_cleanup_retires_and_releases() {
    Fixture fixture;
    VmService service(fixture.context);
    auto reservation = std::make_shared<int>(7);
    std::weak_ptr<int> retained = reservation;
    auto owner = service.create_managed(rescue(), reservation);
    auto runtime = owner->runtime();
    reservation.reset();
    error(ErrorCode::invalid_argument, [&] { owner->remove(-1ms); });
    check(!retained.expired() && owner->runtime() == runtime, "rejected cleanup retains its reservation");
    owner->remove(0ms);
    check(retained.expired() && runtime->snapshot()["runtime_actions"].empty(),
        "successful cleanup retires the runtime and releases the reservation");
    check(!runtime->start() && fixture.starts == 0, "stale references cannot restart a removed managed VM");
    error(ErrorCode::not_found, [&] { owner->runtime(); });
    owner->remove(0ms);
}
void handle_drop_and_shutdown_ownership() {
    Fixture fixture;
    VmService service(fixture.context);
    auto definition = rescue();
    auto reservation = std::make_shared<int>(9);
    std::weak_ptr<int> retained = reservation;
    auto owner = service.create_managed(definition, reservation);
    auto runtime = owner->runtime();
    reservation.reset();
    owner.reset();
    check(!retained.expired() && !runtime->snapshot()["runtime_actions"].empty(),
        "dropping a handle does not remove or retire its inventory-owned VM");
    error(ErrorCode::conflict, [&] { service.create(admin, definition); });
    service.stop_all();
    check(retained.expired() && runtime->snapshot()["runtime_actions"].empty(),
        "stop_all includes hidden instances and retires before releasing reservations");
    error(ErrorCode::unavailable, [&] { service.create_managed(rescue()); });
}
void orphan_recovery_preserves_live_owners() {
    Fixture fixture;
    VmService service(fixture.context);
    const auto ordinary_id = service.create(admin, rescue("ordinary-recovery"));
    auto ordinary = service.runtime(admin, ordinary_id);
    const auto ordinary_observation = ordinary->observation();
    auto active = service.create_managed(rescue("agent-active"));
    auto active_runtime = active->runtime();
    auto reservation = std::make_shared<int>(13);
    std::weak_ptr<int> retained = reservation;
    const auto definition = rescue("agent-orphan");
    auto orphan = service.create_managed(definition, reservation);
    const auto id = orphan->id();
    auto orphan_runtime = orphan->runtime();
    reservation.reset();
    check(service.pending_orphaned_managed().empty(), "live managed capabilities are never recovery candidates");
    orphan.reset();
    check(service.pending_orphaned_managed() == std::vector<std::string>{id},
        "only a dropped managed capability becomes pending");
    error(ErrorCode::invalid_argument, [&] { service.recover_managed(-1ms); });
    check(!retained.expired(), "invalid recovery timeout cannot release a disk reservation");
    check(service.recover_managed(0ms).empty() && retained.expired() &&
        orphan_runtime->snapshot()["runtime_actions"].empty(),
        "recovery retires only the orphan and releases its reservation");
    check(active->runtime() == active_runtime && !active_runtime->snapshot()["runtime_actions"].empty() &&
        service.runtime(admin, ordinary_id) == ordinary && ordinary->observation() == ordinary_observation,
        "recovery preserves live managed and ordinary instances");
    check(!active_runtime->start() && fixture.starts == 1,
        "recovery does not set the global shutdown flag");
    // A new capability with the recovered ID cannot be mistaken for its prior orphan.
    auto replacement = service.create_managed(definition);
    check(service.recover_managed(0ms).empty() && replacement->runtime()->id() == id,
        "repeated recovery cannot affect a later live incarnation");
    replacement->remove(0ms);
    active->remove(0ms);
    check(service.remove(admin, ordinary_id), "ordinary operations remain usable after recovery");
}
void failed_stopped_admission_keeps_registration() {
    Fixture fixture;
    VmService service(fixture.context);
    auto definition = rescue();
    auto reservation = std::make_shared<int>(11);
    std::weak_ptr<int> retained = reservation;
    auto owner = service.create_managed(definition, reservation);
    auto runtime = owner->runtime();
    reservation.reset();
    {
        // Deterministically invalidate stopped admission without launching a VMM.
        // shutdown() still returns normally; a missing lease must not mean success.
        auto edit = runtime->try_edit();
        check(static_cast<bool>(edit), "stage stopped-admission refusal");
        edit.retire();
    }
    error(ErrorCode::unavailable, [&] { owner->remove(0ms); });
    check(!retained.expired() && owner->runtime() == runtime,
        "cleanup without a stopped lease keeps owner and disk reservation");
    error(ErrorCode::conflict, [&] { service.create(admin, definition); });
    error(ErrorCode::unavailable, [&] { service.stop_all(); });
    check(!retained.expired() && owner->runtime() == runtime,
        "shutdown failure preserves hidden registration for a later cleanup attempt");
    const auto id = owner->id();
    owner.reset();
    check(service.recover_managed(0ms) == std::vector<std::string>{id} && !retained.expired(),
        "failed orphan recovery returns the pending identity without releasing its reservation");
    // This fixture is already stopped/retired, so service teardown cannot orphan
    // a process. A real timed-out worker requires its service to remain alive.
}
void reservation_release_after_coordinator_teardown() {
    Fixture fixture;
    auto gate = std::make_shared<ConfigurationGate>();
    fixture.context.configuration_gate = gate;
    TaskService tasks({}, [] { return TaskService::Clock::now(); }, {}, gate);
    VmService inventory(fixture.context);
    Fd directory(open(fixture.directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    check(directory.get() >= 0, "open isolated reservation fixture");
    auto coordinator = std::make_unique<ConfigurationService>(directory.get(), getuid(), gate,
        inventory, tasks, config::ConfigTransaction::Observer{}, true);
    const auto disk_revision = coordinator->disks()->snapshot(admin)->revision;
    const auto vm_revision = coordinator->vms().snapshot(admin)->revision;
    auto reservation = coordinator->reserve_disks(disk_revision, {random_id(true)}, {}, vm_revision);
    std::weak_ptr<const void> retained = reservation;
    auto owner = inventory.create_managed(rescue("agent-late-reservation"), reservation);
    reservation.reset();
    owner.reset();
    coordinator.reset();
    check(!retained.expired(), "orphan retains real registry reservation beyond coordinator lifetime");
    check(inventory.recover_managed(0ms).empty() && retained.expired(),
        "late reservation release uses shared state without a dangling coordinator callback");
}
void handles_reject_destroyed_service() {
    Fixture fixture;
    auto service = std::make_unique<VmService>(fixture.context);
    auto owner = service->create_managed(rescue());
    auto runtime = owner->runtime();
    service.reset();
    error(ErrorCode::unavailable, [&] { owner->runtime(); });
    error(ErrorCode::unavailable, [&] { owner->remove(0ms); });
    check(runtime->snapshot()["runtime_actions"].empty() && !runtime->start() && fixture.starts == 0,
        "service destruction invalidates handles and retires fully stopped managed instances");
}
}
int main() {
    return run({{"managed_capability_visibility", hidden_capability_and_json_independence},
        {"managed_configuration_retention", updates_preserve_private_owner},
        {"managed_explicit_cleanup", explicit_cleanup_retires_and_releases},
        {"managed_stop_all_ownership", handle_drop_and_shutdown_ownership},
        {"managed_orphan_recovery", orphan_recovery_preserves_live_owners},
        {"managed_cleanup_failure_retention", failed_stopped_admission_keeps_registration},
        {"managed_reservation_outlives_coordinator", reservation_release_after_coordinator_teardown},
        {"managed_service_lifetime", handles_reject_destroyed_service}});
}
