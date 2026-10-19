// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "common/identity.h"
#include "services/legacy_events.h"
#include "vm/runtime.h"
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <unistd.h>

using namespace droidvm;
using namespace droidvm::test;
namespace {
struct Fixture {
    std::filesystem::path directory = std::filesystem::temp_directory_path() / ("private-vm-" + random_id(true));
    LegacyEvents events;
    vm::RuntimeContext context;
    std::atomic<int> callbacks{0};
    Fixture() {
        std::filesystem::create_directory(directory);
        context.private_console = true;
        context.owner = getuid();
        context.cache_dir = directory.string();
        context.run_dir = directory.string();
        context.events = &events;
        context.warn = context.info = [&](const std::string&) { ++callbacks; };
        context.state_changed = [&](const std::string&, const std::string&, vm::State) { ++callbacks; };
        context.input_status = [&](const std::string&, const std::string&, std::string) { ++callbacks; };
    }
    ~Fixture() { std::error_code error; std::filesystem::remove_all(directory, error); }
};
Json::Value definition() {
    Json::Value value;
    value["id"] = random_id(true);
    value["name"] = "private-contract";
    value["backend"] = "qemu";
    value["hypervisor"] = "soft";
    value["agent_mode"] = true;
    value["boot"]["protocol"] = "linux";
    value["boot"]["linux"]["source"] = "manual";
    return value;
}
void private_history_has_no_file() {
    Fixture fixture;
    auto value = definition();
    const auto id = value["id"].asString();
    const auto historical = vm::console_log_path(fixture.context.cache_dir, id, "uart");
    { std::ofstream old(historical); old << "historical-output"; }
    auto target = std::make_shared<vm::VmRuntime>(id, value, fixture.context);
    for (const auto& stream : target->streams()) {
        auto* log = target->log(stream);
        check(log && log->path().empty() && log->size() == 0, "private streams never load previous file history");
        log->set_persistent(true); // Cannot accidentally turn a private stream into a file.
        log->append("private-output");
        check(log->contents() == "private-output", "private owner can inspect bounded memory history");
    }
    const auto old_uart = target->log("uart")->read({}, false);
    error(ErrorCode::conflict, [&] { target->prepare_private_console_handoff(target->observation()); });
    check(target->log("uart")->contents() == "private-output", "stopped runtime cannot silently publish a rescue history");
    target->clear_logs();
    target->log("uart")->append("new-rescue-output");
    const auto fresh_uart = target->log("uart")->read(vm::LogCursor{old_uart.generation, 0}, false);
    check(fresh_uart.generation != old_uart.generation && fresh_uart.reset && fresh_uart.bytes == "new-rescue-output",
        "rotated memory history rejects pre-handoff cursors without returning old output");
    std::ifstream old(historical);
    std::string retained; std::getline(old, retained);
    check(retained == "historical-output", "private clearing cannot rewrite or unlink existing public files");
    check(std::distance(std::filesystem::directory_iterator(fixture.directory), std::filesystem::directory_iterator()) == 1,
        "no private output files created");
    check(!target->write_input("gpu-0", 0, "input"), "private runtime rejects public display input");
    check(fixture.callbacks == 0 && fixture.events.drain().empty(), "private history emits no public records");
}
void private_admission_and_worker() {
    Fixture fixture;
    auto value = definition();
    fixture.context.configuration_gate = std::make_shared<ConfigurationGate>();
    std::atomic<int> validations{0}, admissions{0};
    fixture.context.validate_start = std::make_shared<std::function<void(const Json::Value&)>>(
        [&](const Json::Value&) { ++validations; throw std::runtime_error("private-validation-detail"); });
    auto target = std::make_shared<vm::VmRuntime>(value["id"].asString(), value, fixture.context);
    {
        auto transaction = fixture.context.configuration_gate->transaction();
        check(!target->start() && validations == 0, "private runtime retains configuration gate admission");
    }
    check(!target->start() && validations == 1, "private runtime retains start validation");
    check(target->log("stdio")->contents().find("private-validation-detail") != std::string::npos,
        "failed admission diagnostics stay available only to private owner");
    check(fixture.callbacks == 0 && fixture.events.drain().empty(), "failed admission never leaks exception text");

    *fixture.context.validate_start = [&](const Json::Value&) { ++validations; };
    fixture.context.shutting_down = [&] { return ++admissions > 1; };
    // Context is copied at construction. The second runtime exercises the
    // normal STARTING/STOPPED/exited path without launching a real backend.
    auto worker = std::make_shared<vm::VmRuntime>(value["id"].asString(), value, fixture.context);
    worker->log("stdio")->append("private-exit-detail");
    check(worker->start(), "private lifecycle admits worker");
    worker->shutdown(2s);
    check(worker->state() == vm::State::stopped && worker->pid() == -1, "private lifecycle remains stoppable");
    check(fixture.callbacks == 0 && fixture.events.drain().empty(), "state, exit and diagnostic callbacks remain isolated");
}
void isolation_is_not_a_json_option() {
    Fixture fixture;
    fixture.context.private_console = false;
    auto value = definition();
    value["private_console"] = true;
    fixture.context.validate_start = std::make_shared<std::function<void(const Json::Value&)>>(
        [](const Json::Value&) { throw std::runtime_error("ordinary-validation"); });
    auto ordinary = std::make_shared<vm::VmRuntime>(value["id"].asString(), value, fixture.context);
    error(ErrorCode::permission_denied, [&] { ordinary->private_disk_lease(); });
    error(ErrorCode::permission_denied, [&] { ordinary->prepare_private_console_handoff(ordinary->observation()); });
    check(!ordinary->log("uart")->path().empty(), "agent_mode and spoofed JSON cannot enable private isolation");
    check(!ordinary->start() && fixture.callbacks > 0, "ordinary runtime retains public diagnostics");
}
void private_lease_outlives_worker() {
    Fixture fixture;
    const auto path = (fixture.directory / "disk").string();
    { std::ofstream output(path); output << "original"; }
    auto leases = std::make_shared<config::DiskFileLeases>();
    fixture.context.acquire_disks = std::make_shared<vm::RuntimeContext::AcquireDisks>(
        [leases, path](const Json::Value&) { return leases->acquire({{path, true}}); });
    std::shared_ptr<vm::VmRuntime> target;
    std::shared_ptr<config::DiskFileLeases::Lease> retained;
    bool same_lease = false;
    fixture.context.validate_disks = std::make_shared<vm::RuntimeContext::ValidateDisks>(
        [&](const Json::Value&, const config::DiskFileLeases::Lease& admitted,
                const std::function<bool()>&) -> vm::RuntimeContext::DiskImages {
            // Capture deterministically before the worker releases disks, then
            // stop at existing validation without preparing or launching a VMM.
            retained = target->private_disk_lease();
            same_lease = retained && retained.get() == &admitted;
            if (retained) {
                auto output = retained->open_file(path, true);
                check(pwrite(output.get(), "UPDATED!", 8, 0) == 8, "write through original runtime admission");
            }
            throw std::runtime_error("intentional private disk validation rejection");
        });
    const auto value = definition();
    target = std::make_shared<vm::VmRuntime>(value["id"].asString(), value, fixture.context);
    check(!target->private_disk_lease(), "private runtime has no disk lease before admission");
    check(target->start(), "private disk worker starts before controlled validation failure");
    target->shutdown(2s);
    check(same_lease && retained && !target->private_disk_lease(),
        "private owner retains the exact lease after runtime releases its reference");
    {
        auto stopped = target->try_edit();
        check(static_cast<bool>(stopped), "worker completion proved before disk synchronization");
        stopped.retire();
    }
    error(ErrorCode::conflict, [&] { leases->acquire({{path, true}}); });
    retained->sync_writes();
    check(!target->start(), "retired runtime cannot write again after synchronization");
    char bytes[8];
    check(pread(retained->read_fd(path), bytes, 8, 0) == 8 && std::string(bytes, 8) == "UPDATED!",
        "retained lease synchronizes the original worker inode after retirement");
    retained.reset();
    check(static_cast<bool>(leases->acquire({{path, true}})), "exclusive disk ownership releases after retained sync handle");
}
void unsafe_private_channels_refused() {
    Fixture fixture;
    auto expect_refused = [&](Json::Value value) {
        try { vm::VmRuntime target(value["id"].asString(), value, fixture.context); }
        catch (const std::invalid_argument& error) {
            check(std::string(error.what()) == "Invalid private VM configuration", "private rejection text is generic");
            return;
        }
        throw std::runtime_error("unsafe private channels accepted");
    };
    auto value = definition(); value["backend"] = "crosvm"; expect_refused(value);
    value = definition(); value["agent_mode"] = false; expect_refused(value);
    value = definition(); value["strace"] = true; expect_refused(value);
    for (const char* key : {"extra_options", "environment_variables", "networks", "peripherals", "shared_dirs", "serial_ports"}) {
        value = definition(); value[key].append("external-channel"); expect_refused(value);
    }
    check(fixture.callbacks == 0 && fixture.events.drain().empty(), "unsafe configurations emit no diagnostics");
}
}
int main() {
    return run({{"private_history_has_no_file", private_history_has_no_file},
        {"private_admission_and_worker", private_admission_and_worker},
        {"isolation_is_not_a_json_option", isolation_is_not_a_json_option},
        {"private_lease_outlives_worker", private_lease_outlives_worker},
        {"unsafe_private_channels_refused", unsafe_private_channels_refused}});
}
