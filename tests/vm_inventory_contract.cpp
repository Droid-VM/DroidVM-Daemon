// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "config_gate_contract.h"
#include "common/identity.h"
#include "services/vm.h"
#include "services/configuration.h"
#include "store/network_config.h"
#include "store/vm_ownership.h"
#include "transport/dispatcher.h"
#include "vm/qemu_command.h"
#include "vm/command_common.h"
#include <atomic>
#include <dirent.h>
#include <future>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace droidvm;
using namespace droidvm::test;
namespace {
void disk_option_path_encoding() {
    using namespace vm::command;
    const std::string path = "/isolated/a,readonly=off,ro=false,[x]'\"\\.img";
    const std::string qemu_path = "/isolated/a,,readonly=off,,ro=false,,[x]'\"\\.img";
    const std::string crosvm_path = "\"/isolated/a,readonly=off,ro=false,[x]'\\\"\\\\.img\"";
    check(qemu_option_value(path) == qemu_path, "QEMU commas stay in the filename");
    check(crosvm_option_value(path) == crosvm_path, "crosvm quotes and escapes the complete filename");
    for (auto encode : {qemu_option_value, crosvm_option_value}) {
        check(encode("/plain file.img") == "/plain file.img", "ordinary paths retain their existing arguments");
        bool refused = false;
        try { encode(std::string("/a\0b", 4)); } catch (const std::invalid_argument&) { refused = true; }
        check(refused, "NUL cannot truncate a backend path");
    }
    Json::Value config;
    config["name"] = "path-contract"; config["id"] = random_id(true);
    config["screens"]["gpu-0"]["enabled"] = false;
    config["screens"]["simplefb"]["enabled"] = false;
    vm::HostFacts host; host.optimize_sdcard = false;
    vm::QemuRun run;
    int size_queries = 0;
    run.file_length = [&](const std::string& actual) {
        ++size_queries;
        check(actual == path, "PMEM stat receives the unencoded filesystem path");
        return 64LL * 1024 * 1024;
    };
    for (const auto* bus : {"pflash", "pmem", "virtio", "scsi", "cdrom"}) {
        Json::Value disk;
        disk["path"] = path; disk["bus"] = bus; disk["readonly"] = true;
        config["disks"] = Json::Value(Json::arrayValue); config["disks"].append(disk);
        const auto qemu = vm::qemu_command(config, run, {}, host);
        size_t matches = 0;
        for (const auto& arg : qemu.argv) if (arg.find("/isolated/") != std::string::npos) {
            ++matches;
            check(arg.find(qemu_path + ",") != std::string::npos && arg.ends_with(",readonly=on"),
                "encoded QEMU path cannot inject additional disk options");
        }
        check(matches == 1, "one QEMU disk argument");
        if (std::string_view(bus) == "pflash") continue;
        const auto crosvm = vm::crosvm_command(config, {}, {}, host);
        matches = 0;
        for (const auto& arg : crosvm.argv) if (arg.find("/isolated/") != std::string::npos) {
            ++matches;
            check(arg.starts_with(crosvm_path + ",") && arg.find(",ro=true") != std::string::npos,
                "encoded crosvm path cannot inject additional disk options");
        }
        check(matches == 1, "one crosvm disk argument");
    }
    check(size_queries == 1, "only PMEM queries file size");
}
void qemu_disk_readonly_arguments() {
    Json::Value config;
    config["name"] = "readonly-contract";
    config["id"] = random_id(true);
    config["screens"]["gpu-0"]["enabled"] = false;
    config["screens"]["simplefb"]["enabled"] = false;
    vm::HostFacts host;
    host.optimize_sdcard = false;
    vm::QemuRun run;
    run.file_length = [](const std::string&) { return 64LL * 1024 * 1024; };
    for (const auto* bus : {"pflash", "pmem", "virtio", "scsi", "cdrom"}) {
        for (const bool readonly : {false, true}) {
            Json::Value disk;
            disk["path"] = "/isolated/readonly-contract.img";
            disk["bus"] = bus;
            disk["readonly"] = readonly;
            config["disks"] = Json::Value(Json::arrayValue);
            config["disks"].append(disk);
            const auto launch = vm::qemu_command(config, run, {}, host);
            size_t matches = 0;
            for (const auto& arg : launch.argv) {
                if (arg.find("/isolated/readonly-contract.img") == std::string::npos) continue;
                ++matches;
                check((arg.find(",readonly=on") != std::string::npos) ==
                    (readonly || std::string_view(bus) == "cdrom"),
                    "QEMU disk access agrees with read-only lease for every bus");
            }
            check(matches == 1, "disk is attached exactly once");
        }
    }
}
struct Fixture {
    std::string path = "/data/local/tmp/droidvm-vm-inventory-" + random_id(false);
    std::atomic<int> starts{0};
    vm::RuntimeContext context;
    Fixture() {
        check(mkdir(path.c_str(), 0700) == 0, "create isolated console directory");
        context.cache_dir = path;
        context.owner = getuid();
        // Reach admission but never prepare TAPs, hugepages, files or a VMM.
        context.shutting_down = [this] { ++starts; return true; };
    }
    ~Fixture() {
        if (auto* directory = opendir(path.c_str())) {
            while (auto* entry = readdir(directory)) if (std::string_view(entry->d_name) != "." && std::string_view(entry->d_name) != "..")
                unlink((path + "/" + entry->d_name).c_str());
            closedir(directory);
        }
        rmdir(path.c_str());
    }
};
Json::Value config(const std::string& name) {
    Json::Value value;
    value["id"] = random_id(true); value["name"] = name;
    return value;
}
void configuration_gate_domains_and_recovery() {
    Fixture fixture;
    auto gate = std::make_shared<ConfigurationGate>();
    fixture.context.configuration_gate = gate;
    Fd directory(open(fixture.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    TaskService tasks({}, [] { return TaskService::Clock::now(); }, {}, gate);
    VmService inventory(fixture.context);
    VmConfigService vms(directory.get(), getuid(), {},
        [&](const Json::Value& document) { return inventory.prepare_config(document); }, &tasks, gate);
    NetworkConfigService networks(directory.get(), getuid(), {}, &tasks, true, gate);
    auto network = config("network"); network["schema"] = 2; network["bridge_name"] = "brtest";
    const auto network_id = networks.create(admin, network);
    auto document = vms.snapshot(admin)->document;
    auto row = config("vm"); const auto id = row["id"].asString();
    document["vms"].append(row);
    const auto saved = vms.replace(admin, vms.snapshot(admin)->revision, document);
    auto runtime = inventory.runtime(admin, id);
    runtime->log("stdio")->append("must survive rejected start\n");
    auto old_view = tasks.vm_config_snapshot(admin);
    auto refused = [&] {
        error(ErrorCode::unavailable, [&] { vms.snapshot(admin); });
        error(ErrorCode::unavailable, [&] { vms.replace(admin, saved->revision, document); });
        error(ErrorCode::unavailable, [&] { vms.apply(admin, saved->revision, Json::Value(Json::arrayValue)); });
        error(ErrorCode::unavailable, [&] { networks.list(admin); });
        error(ErrorCode::unavailable, [&] { networks.get(admin, network_id); });
        error(ErrorCode::unavailable, [&] { networks.exists(admin, network_id); });
        error(ErrorCode::unavailable, [&] { networks.create(admin, network); });
        error(ErrorCode::unavailable, [&] { networks.update(admin, network); });
        error(ErrorCode::unavailable, [&] { networks.remove(admin, network_id); });
        error(ErrorCode::unavailable, [&] { networks.merge_if_matches(admin, Json::Value(Json::arrayValue)); });
        error(ErrorCode::unavailable, [&] { networks.prepare_runtime(admin, network_id); });
        error(ErrorCode::unavailable, [&] { tasks.vm_config_snapshot(admin); });
        error(ErrorCode::unavailable, [&] { tasks.network_config_snapshot(admin); });
        error(ErrorCode::unavailable, [&] { tasks.network_config_document(admin); });
        check(!runtime->start({}, {}, true) && fixture.starts == 0, "stale runtime cannot bypass configuration gate");
        check(!runtime->log("stdio")->contents().empty(), "rejected start does not clear logs");
        check(runtime->state() == VmState::stopped, "runtime inspection remains available for cleanup");
        check(tasks.snapshot_page(admin, old_view.id, 0).id == old_view.id, "previous fixed view remains readable");
    };
    {
        auto transaction = gate->transaction();
        refused();
        transaction.require_recovery();
    }
    refused(); // Releasing exclusivity cannot clear a persistent recovery fault.
    {
        auto recovery = gate->transaction();
        recovery.recovered();
        refused(); // Successful recovery still hides publication until exit.
    }
    check(vms.snapshot(admin)->revision == saved->revision && networks.get(admin, network_id) == network,
        "gate alone never changes configuration");
    check(!runtime->start() && fixture.starts == 1, "recovered runtime reaches normal admission");
    tasks.release_snapshot(admin, old_view.id);
}
struct Coordinated {
    Fd directory;
    std::shared_ptr<ConfigurationGate> gate = std::make_shared<ConfigurationGate>();
    TaskService tasks{{}, [] { return TaskService::Clock::now(); }, {}, gate};
    VmService inventory;
    ConfigurationService service;
    static vm::RuntimeContext context(Fixture& fixture, const std::shared_ptr<ConfigurationGate>& gate) {
        auto result = fixture.context; result.configuration_gate = gate; return result;
    }
    explicit Coordinated(Fixture& fixture, config::ConfigTransaction::Observer observer = {}, bool disks = false)
        : directory(open(fixture.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)), inventory(context(fixture, gate)),
          service(directory.get(), getuid(), gate, inventory, tasks, std::move(observer), disks) {}
};
Json::Value registered_disk() {
    auto row = config("image.qcow2"); row["folder"] = "/images/";
    return row;
}
void coordinated_disk_references() {
    Fixture fixture; Coordinated c(fixture, {}, true);
    auto& disks = *c.service.disks();
    auto disk = registered_disk(); auto initial = disks.snapshot(admin);
    auto document = initial->document; document["disks"].append(disk);
    auto saved = disks.replace(admin, initial->revision, document);
    auto row = config("disk VM"); Json::Value slot; slot["path"] = "/images/image.qcow2";
    row["disks"] = Json::Value(Json::arrayValue); row["disks"].append(slot);
    auto vm = c.service.vms().snapshot(admin); auto desired = vm->document; desired["vms"].append(row);
    vm = c.service.vms().replace(admin, vm->revision, desired);
    error(ErrorCode::conflict, [&] { disks.replace(admin, saved->revision, initial->document); });
    auto changed = document; changed["disks"][0]["folder"] = "/moved";
    error(ErrorCode::conflict, [&] { disks.replace(admin, saved->revision, changed); });
    changed = document; changed["disks"][0]["parent"] = random_id(true);
    error(ErrorCode::conflict, [&] { disks.replace(admin, saved->revision, changed); });
    check(disks.snapshot(admin)->revision == saved->revision, "rejected registry edits leave revision unchanged");
    desired = vm->document; desired["vms"][0]["disks"].clear();
    vm = c.service.vms().replace(admin, vm->revision, desired);
    disks.replace(admin, saved->revision, initial->document);
    desired["vms"][0]["disks"].append(slot);
    error(ErrorCode::conflict, [&] { c.service.vms().replace(admin, vm->revision, desired); });
    bool refused = false;
    try { config::require_legacy_disk_config(c.directory.get(), getuid()); } catch (...) { refused = true; }
    check(refused, "coordinator durably claims disk ownership");
}
void coordinated_historical_disk_references() {
    Fixture fixture;
    Fd directory(open(fixture.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    auto row = config("historical disk VM"); Json::Value slot; slot["path"] = "/unregistered"; slot["extension"] = 7;
    row["disks"] = Json::Value(Json::arrayValue); row["disks"].append(slot); row["disks"].append(slot);
    Json::Value document; document["vms"] = Json::Value(Json::arrayValue); document["vms"].append(row);
    config::JsonFile(directory.get(), "vms.json", getuid()).save(document);
    Coordinated c(fixture, {}, true); auto base = c.service.vms().snapshot(admin);
    auto edited = base->document; edited["vms"][0]["name"] = "renamed";
    base = c.service.vms().replace(admin, base->revision, edited);
    for (int mode = 0; mode < 3; ++mode) {
        edited = base->document;
        if (mode == 0) edited["vms"][0]["disks"].append(slot);
        if (mode == 1) edited["vms"][0]["disks"][0]["extension"] = 8;
        if (mode == 2) {
            auto copy = edited["vms"][0]; copy["id"] = random_id(true); copy["name"] = "copy";
            edited["vms"].append(copy);
        }
        error(ErrorCode::conflict, [&] { c.service.vms().replace(admin, base->revision, edited); });
    }
    edited = base->document; edited["vms"][0]["disks"].resize(1);
    base = c.service.vms().replace(admin, base->revision, edited);
    check(base->document["vms"][0]["disks"].size() == 1, "historical reference multiplicity may decrease");
    edited = base->document; edited["vms"][0]["disks"].clear();
    c.service.vms().replace(admin, base->revision, edited);
}
void coordinated_disk_start_guard() {
    Fixture fixture;
    fixture.context.shutting_down = [] { return false; };
    int attaches = 0;
    fixture.context.attach_nic = [&](const std::string&, const Json::Value&, const std::string&) {
        ++attaches; throw std::runtime_error("test stops before any network or VMM creation");
    };
    auto gate = std::make_shared<ConfigurationGate>(); fixture.context.configuration_gate = gate;
    Fd directory(open(fixture.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    auto row = config("historical invalid disk start");
    Json::Value slot; slot["path"] = "/not-registered";
    row["disks"] = Json::Value(Json::arrayValue); row["disks"].append(slot);
    Json::Value nic; nic["network_id"] = random_id(true);
    row["networks"] = Json::Value(Json::arrayValue); row["networks"].append(nic);
    Json::Value document; document["vms"] = Json::Value(Json::arrayValue); document["vms"].append(row);
    config::JsonFile(directory.get(), "vms.json", getuid()).save(document);
    TaskService tasks({}, [] { return TaskService::Clock::now(); }, {}, gate);
    VmService inventory(fixture.context);
    auto coordinator = std::make_unique<ConfigurationService>(directory.get(), getuid(), gate, inventory, tasks,
        config::ConfigTransaction::Observer{}, true);
    auto runtime = inventory.runtime(admin, row["id"].asString());
    check(!runtime->start() && attaches == 0 && runtime->state() == vm::State::stopped,
          "historical disk reference cannot reach TAP setup");
    auto snapshot = coordinator->vms().snapshot(admin);
    document = snapshot->document; document["vms"][0]["disks"].clear();
    coordinator->vms().replace(admin, snapshot->revision, document);
    check(!runtime->start() && attaches == 0, "old runtime remains retired after repair");
    runtime = inventory.runtime(admin, row["id"].asString());
    check(!runtime->start() && attaches == 1, "repaired diskless VM passes guard and reaches bounded test rejection");
    coordinator.reset();
    check(!runtime->start() && attaches == 1, "expired configuration owner rejects startup without dangling callback");
}
void runtime_disk_lease_admission() {
    Fixture fixture;
    const auto path = fixture.path + "/image";
    Fd file(open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
    check(file.get() >= 0, "create isolated leased disk");
    auto leases = std::make_shared<config::DiskFileLeases>();
    fixture.context.shutting_down = [] { return false; };
    fixture.context.acquire_disks = std::make_shared<vm::RuntimeContext::AcquireDisks>(
        [leases, path](const Json::Value&) { return leases->acquire({{path, true}}); });
    int attaches = 0;
    fixture.context.attach_nic = [&](const std::string&, const Json::Value&, const std::string&) {
        ++attaches;
        error(ErrorCode::conflict, [&] { leases->acquire({{path, true}}); });
        throw std::runtime_error("intentional TAP rejection before VMM creation");
    };
    auto row = config("lease admission"); Json::Value nic; nic["network_id"] = random_id(true);
    row["networks"] = Json::Value(Json::arrayValue); row["networks"].append(nic);
    auto runtime = std::make_shared<vm::VmRuntime>(row["id"].asString(), row, fixture.context);
    auto operation = leases->acquire({{path, true}});
    check(!runtime->start() && attaches == 0, "file operation blocks VM before TAP setup");
    operation.reset();
    for (int i = 0; i < 2; ++i) {
        check(!runtime->start() && attaches == i + 1, "VM holds file lease during network preparation");
        operation = leases->acquire({{path, true}});
        operation.reset();
    }
    check(runtime->state() == vm::State::stopped, "failed startup releases all disk leases");
}
void coordinated_disk_structure() {
    Fixture fixture; Coordinated c(fixture, {}, true); auto& disks = *c.service.disks();
    auto base = disks.snapshot(admin); auto document = base->document;
    auto root = registered_disk(), child = registered_disk();
    child["name"] = "child.qcow2"; child["parent"] = root["id"];
    document["disks"].append(root); document["disks"].append(child);
    auto invalid = document; invalid["disks"][0]["parent"] = child["id"];
    error(ErrorCode::conflict, [&] { disks.replace(admin, base->revision, invalid); });
    auto saved = disks.replace(admin, base->revision, document);
    auto vm = c.service.vms().snapshot(admin); auto wanted = vm->document; auto row = config("overlay VM");
    Json::Value slot; slot["path"] = "/images/child.qcow2";
    row["disks"] = Json::Value(Json::arrayValue); row["disks"].append(slot); wanted["vms"].append(row);
    c.service.vms().replace(admin, vm->revision, wanted);
    invalid = document; invalid["disks"][0]["name"] = "renamed-base.qcow2";
    error(ErrorCode::conflict, [&] { disks.replace(admin, saved->revision, invalid); });
    invalid = document; auto next = registered_disk(); next["parent"] = child["id"]; next["name"] = "next.qcow2";
    invalid["disks"].append(next);
    error(ErrorCode::conflict, [&] { disks.replace(admin, saved->revision, invalid); });
    check(disks.snapshot(admin)->revision == saved->revision, "ancestor and descendant edits of referenced disk rejected before IO");
}
struct VmDiskInput {
    ConfigurationService::VmDiskResult baseline;
    std::string vm_id, unrelated_id;
};
VmDiskInput seed_vm_disk(Coordinated& c) {
    auto vm = c.service.vms().snapshot(admin); auto disk = c.service.disks()->snapshot(admin);
    auto vms = vm->document, disks = disk->document;
    auto row = config("disk participant"), unrelated = config("unrelated participant");
    Json::Value slot; slot["path"] = "/images/image.qcow2"; slot["extension"] = Json::Int64(9007199254740993LL);
    row["disks"] = Json::Value(Json::arrayValue); row["disks"].append(slot);
    vms["vms"].append(row); vms["vms"].append(unrelated); vms["root_extension"] = "keep";
    disks["disks"].append(registered_disk()); disks["root_extension"] = Json::Int64(9007199254740993LL);
    return {c.service.replace_vm_disks(admin, vm->revision, disk->revision, vms, disks),
        row["id"].asString(), unrelated["id"].asString()};
}
void coordinated_vm_disk_commit() {
    Fixture fixture; Coordinated c(fixture, {}, true); auto input = seed_vm_disk(c);
    const auto old = c.inventory.runtime(admin, input.vm_id), unrelated = c.inventory.runtime(admin, input.unrelated_id);
    auto vms = input.baseline.vms->document, disks = input.baseline.disks->document;
    auto unchanged = c.service.replace_vm_disks(admin, input.baseline.vms->revision, input.baseline.disks->revision, vms, disks);
    check(unchanged.vms->revision == input.baseline.vms->revision && unchanged.disks->revision == input.baseline.disks->revision,
        "durable joint noop preserves revisions");
    vms["vms"][0]["disks"].clear(); disks["disks"].clear();
    auto saved = c.service.replace_vm_disks(admin, input.baseline.vms->revision, input.baseline.disks->revision, vms, disks);
    check(saved.vms->document["vms"][0]["disks"].empty() && saved.disks->document["disks"].empty(), "joint detach and registry removal");
    check(saved.vms->document["root_extension"] == "keep" && saved.disks->document["root_extension"].asInt64() == 9007199254740993LL,
        "joint commit retains extensions and int64");
    check(c.inventory.runtime(admin, input.unrelated_id) == unrelated && c.inventory.runtime(admin, input.vm_id) != old,
        "joint commit replaces only affected runtime");
    check(!old->start() && fixture.starts == 0, "old runtime retired after joint commit");
    check(config::JsonFile(c.directory.get(), "vms.json", getuid(), {}, VmConfigService::max_bytes).load()->value == saved.vms->document
        && config::JsonFile(c.directory.get(), "disks.json", getuid()).load()->value == saved.disks->document, "both committed files match views");
}
void coordinated_vm_disk_rejections() {
    Fixture fixture; Coordinated c(fixture, {}, true); auto input = seed_vm_disk(c);
    auto vms = input.baseline.vms->document, disks = input.baseline.disks->document;
    auto empty = disks; empty["disks"].clear();
    error(ErrorCode::conflict, [&] { c.service.replace_vm_disks(admin, input.baseline.vms->revision, input.baseline.disks->revision, vms, empty); });
    for (bool stale_vm : {false, true})
        error(ErrorCode::conflict, [&] { c.service.replace_vm_disks(admin, stale_vm ? "stale" : input.baseline.vms->revision,
            stale_vm ? input.baseline.disks->revision : "stale", vms, disks); });
    auto runtime = c.inventory.runtime(admin, input.vm_id);
    auto edited = disks; edited["disks"][0]["extension"] = "metadata edit";
    {
        auto busy = runtime->try_edit(); check(bool(busy), "hold stopped runtime lease");
        error(ErrorCode::conflict, [&] { c.service.replace_vm_disks(admin, input.baseline.vms->revision, input.baseline.disks->revision, vms, edited); });
    }
    check(c.service.vms().snapshot(admin)->revision == input.baseline.vms->revision
        && c.service.disks()->snapshot(admin)->revision == input.baseline.disks->revision, "joint rejection occurs before persistence");
    auto saved = c.service.replace_vm_disks(admin, input.baseline.vms->revision, input.baseline.disks->revision, vms, edited);
    check(saved.vms->document == vms && c.inventory.runtime(admin, input.vm_id) != runtime,
        "unchanged VM definition still receives fresh runtime when disk family changed");
}
void coordinated_vm_disk_failure_recovery() {
    for (const auto* boundary : {"before_decision", "participant_synced", "decision_removed"}) {
        Fixture fixture; bool fail = false;
        Coordinated c(fixture, [&](const char* stage, size_t) {
            if (fail && std::string_view(stage) == boundary) throw std::runtime_error("joint disk failure");
        }, true);
        auto input = seed_vm_disk(c); fail = true;
        auto vms = input.baseline.vms->document, disks = input.baseline.disks->document;
        vms["vms"][0]["disks"].clear(); disks["disks"].clear();
        const bool decided = std::string_view(boundary) != "before_decision";
        error(decided ? ErrorCode::commit_uncertain : ErrorCode::io_error,
            [&] { c.service.replace_vm_disks(admin, input.baseline.vms->revision, input.baseline.disks->revision, vms, disks); });
        if (decided) {
            error(ErrorCode::unavailable, [&] { c.service.vms().snapshot(admin); });
            error(ErrorCode::unavailable, [&] { c.service.disks()->snapshot(admin); });
            error(ErrorCode::unavailable, [&] { c.tasks.disk_config_snapshot(admin); });
            error(ErrorCode::unavailable, [&] { c.inventory.list(admin); });
        } else check(c.service.vms().snapshot(admin)->revision == input.baseline.vms->revision
            && c.service.disks()->snapshot(admin)->revision == input.baseline.disks->revision, "undecided failure preserves old generation");
        fail = false; c.service.recover(admin);
        const auto vm_after = c.service.vms().snapshot(admin); const auto disk_after = c.service.disks()->snapshot(admin);
        check(vm_after->document["vms"][0]["disks"].empty() == decided && disk_after->document["disks"].empty() == decided,
            "redo restores coherent VM/disk generation");
        check(!vm_after->durability_uncertain && !disk_after->durability_uncertain, "recovery clears both uncertainty flags");
        check(c.service.networks().list(admin).empty(), "disk recovery does not invent pending network state");
    }
}
void coordinated_vm_disk_restart() {
    Fixture fixture;
    {
        bool fail = false;
        Coordinated c(fixture, [&](const char* stage, size_t) {
            if (fail && std::string_view(stage) == "participant_synced") throw std::runtime_error("restart joint transaction");
        }, true);
        auto input = seed_vm_disk(c); auto vms = input.baseline.vms->document, disks = input.baseline.disks->document;
        vms["vms"][0]["disks"].clear(); disks["disks"].clear(); fail = true;
        error(ErrorCode::commit_uncertain, [&] { c.service.replace_vm_disks(admin, input.baseline.vms->revision, input.baseline.disks->revision, vms, disks); });
    }
    Coordinated reopened(fixture, {}, true);
    check(reopened.service.vms().snapshot(admin)->document["vms"][0]["disks"].empty()
        && reopened.service.disks()->snapshot(admin)->document["disks"].empty(), "restart replays actual joint API transaction");
}
void coordinated_vm_disk_readonly() {
    Fixture fixture; Coordinated c(fixture, {}, true); auto input = seed_vm_disk(c);
    auto vms = input.baseline.vms->document, disks = input.baseline.disks->document;
    auto child = registered_disk(); child["name"] = "overlay.qcow2"; child["parent"] = disks["disks"][0]["id"];
    disks["disks"].append(child);
    error(ErrorCode::conflict, [&] { c.service.replace_vm_disks(admin, input.baseline.vms->revision, input.baseline.disks->revision, vms, disks); });
    vms["vms"][0]["disks"][0]["readonly"] = true;
    auto saved = c.service.replace_vm_disks(admin, input.baseline.vms->revision, input.baseline.disks->revision, vms, disks);
    auto writer = vms; writer["vms"][0]["disks"][0]["path"] = "/images/overlay.qcow2";
    writer["vms"][0]["disks"][0]["readonly"] = false;
    saved = c.service.replace_vm_disks(admin, saved.vms->revision, saved.disks->revision, writer, disks);
    auto shared = saved.vms->document;
    shared["vms"][1]["disks"] = shared["vms"][0]["disks"];
    error(ErrorCode::conflict, [&] { c.service.vms().replace(admin, saved.vms->revision, shared); });
    shared["vms"][0]["disks"][0]["readonly"] = true; shared["vms"][1]["disks"][0]["readonly"] = true;
    c.service.vms().replace(admin, saved.vms->revision, shared);
}
void coordinated_vm_disk_uploads() {
    Fixture fixture; Coordinated c(fixture, {}, true); auto input = seed_vm_disk(c);
    auto now = ConfigUploads::Clock::now();
    ConfigUploads uploads(&c.service.vms(), &c.service.networks(), [&] { return now; }, {}, c.service.disks());
    uploads.bind_vm_disks([&](const CallContext& caller, const std::string& vm, const std::string& disk, Json::Value vms, Json::Value disks) {
        const auto saved = c.service.replace_vm_disks(caller, vm, disk, std::move(vms), std::move(disks));
        return ConfigUploads::VmDisks{saved.vms, saved.disks};
    });
    Json::Value payload; payload["vms"] = input.baseline.vms->document; payload["disks"] = input.baseline.disks->document;
    payload["vms"]["vms"][0]["disks"].clear(); payload["disks"]["disks"].clear();
    auto bytes = config::encode_json(payload, ConfigUploads::max_vm_disk_bytes);
    auto id = uploads.begin_vm_disks(admin, input.baseline.vms->revision, input.baseline.disks->revision, bytes.size());
    check(uploads.append_vm_disks(admin, id, 0, bytes) == bytes.size() && uploads.append_vm_disks(admin, id, 0, bytes) == bytes.size(),
        "joint upload duplicate chunk is idempotent");
    auto stranger = admin; stranger.principal = "another administrator";
    error(ErrorCode::permission_denied, [&] { uploads.commit_vm_disks(stranger, id); });
    error(ErrorCode::not_found, [&] { uploads.append_disk(admin, id, 0, bytes); });
    const auto saved = uploads.commit_vm_disks(admin, id);
    check(saved.vms->document["vms"][0]["disks"].empty() && saved.disks->document["disks"].empty(), "joint staging invokes coordinator");
    error(ErrorCode::not_found, [&] { uploads.commit_vm_disks(admin, id); });
    error(ErrorCode::conflict, [&] { uploads.begin_vm_disks(admin, input.baseline.vms->revision, saved.disks->revision, 1); });
    const std::string invalid = "{\"vms\":{},\"disks\":{},\"extra\":true}";
    id = uploads.begin_vm_disks(admin, saved.vms->revision, saved.disks->revision, invalid.size());
    uploads.append_vm_disks(admin, id, 0, invalid);
    error(ErrorCode::invalid_argument, [&] { uploads.commit_vm_disks(admin, id); });
    error(ErrorCode::not_found, [&] { uploads.commit_vm_disks(admin, id); });
    id = uploads.begin_vm_disks(admin, saved.vms->revision, saved.disks->revision, bytes.size());
    uploads.append_vm_disks(admin, id, 0, bytes);
    auto changed = saved.vms->document; changed["extension"] = "another writer";
    const auto current = c.service.vms().replace(admin, saved.vms->revision, changed);
    error(ErrorCode::conflict, [&] { uploads.commit_vm_disks(admin, id); });
    error(ErrorCode::not_found, [&] { uploads.commit_vm_disks(admin, id); });
    std::vector<std::string> held{
        uploads.begin(admin, current->revision, 1), uploads.begin_network(admin, 1),
        uploads.begin_disk(admin, saved.disks->revision, 1), uploads.begin_vm_disks(admin, current->revision, saved.disks->revision, 1)};
    error(ErrorCode::resource_exhausted, [&] { uploads.begin_vm_disks(admin, current->revision, saved.disks->revision, 1); });
    now += ConfigUploads::lifetime;
    error(ErrorCode::not_found, [&] { uploads.abort_vm_disks(admin, held.back()); });
    id = uploads.begin_vm_disks(admin, current->revision, saved.disks->revision, ConfigUploads::max_vm_disk_bytes);
    error(ErrorCode::resource_exhausted, [&] { uploads.begin_disk(admin, saved.disks->revision, DiskConfigService::max_bytes); });
    uploads.abort_vm_disks(admin, id);
    error(ErrorCode::invalid_argument, [&] { uploads.begin_vm_disks(admin, current->revision, saved.disks->revision, ConfigUploads::max_vm_disk_bytes + 1); });
}
void coordinated_disk_reference_races() {
    for (int attempt = 0; attempt < 16; ++attempt) {
        Fixture fixture; Coordinated c(fixture, {}, true); auto& disks = *c.service.disks();
        auto empty = disks.snapshot(admin); auto document = empty->document; document["disks"].append(registered_disk());
        auto baseline = disks.replace(admin, empty->revision, document);
        auto vm = c.service.vms().snapshot(admin); auto desired = vm->document;
        auto row = config("racing VM"); Json::Value slot; slot["path"] = "/images/image.qcow2";
        row["disks"] = Json::Value(Json::arrayValue); row["disks"].append(slot); desired["vms"].append(row);
        std::promise<void> ready; auto begin = ready.get_future().share();
        auto writer = std::async(std::launch::async, [&] {
            begin.wait();
            try { c.service.vms().replace(admin, vm->revision, desired); }
            catch (const ServiceError& error) { check(error.code() == ErrorCode::conflict || error.code() == ErrorCode::unavailable, "VM race rejects safely"); }
        });
        auto remover = std::async(std::launch::async, [&] {
            begin.wait();
            try { disks.replace(admin, baseline->revision, empty->document); }
            catch (const ServiceError& error) { check(error.code() == ErrorCode::conflict, "referenced removal rejects safely"); }
        });
        ready.set_value(); writer.get(); remover.get();
        check(c.service.vms().snapshot(admin)->document["vms"].empty() || !disks.snapshot(admin)->document["disks"].empty(),
            "concurrent disk removal and VM creation cannot publish dangling reference");
    }
}
void coordinated_disk_redo_before_load() {
    Fixture fixture; Fd directory(open(fixture.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    Json::Value disks; disks["disks"] = Json::Value(Json::arrayValue); disks["disks"].append(registered_disk());
    Json::Value vms; vms["vms"] = Json::Value(Json::arrayValue);
    auto row = config("replayed VM"); Json::Value slot; slot["path"] = "/images/image.qcow2";
    row["disks"] = Json::Value(Json::arrayValue); row["disks"].append(slot); vms["vms"].append(row);
    {
        config::ConfigTransaction journal(directory.get(), getuid(), [](const char* stage, size_t) {
            if (std::string_view(stage) == "participant_synced") throw std::runtime_error("interrupt redo");
        });
        bool interrupted = false;
        try { journal.commit({{"vms.json", vms}, {"disks.json", disks}}); }
        catch (const config::TransactionError& error) { interrupted = error.decided; }
        check(interrupted, "leave durable VM/disk redo for startup");
    }
    Coordinated c(fixture, {}, true);
    check(c.service.disks()->snapshot(admin)->document == disks && c.service.vms().snapshot(admin)->document["vms"].size() == 1,
        "coordinator replays disks and VMs before exposing inventory");
}
struct DeletionInput {
    Json::Value network;
    VmConfigService::Snapshot baseline;
    std::string vm_id, unrelated_id;
};
DeletionInput seed_deletion(Coordinated& c) {
    auto network = config("target"); network["schema"] = 2; network["bridge_name"] = "brtest";
    c.service.networks().create(admin, network);
    auto other = config("other network"); other["schema"] = 2; other["bridge_name"] = "brother";
    c.service.networks().create(admin, other);
    auto row = config("referencing VM"), unrelated = config("unrelated VM");
    Json::Value nic; nic["network_id"] = network["id"]; nic["opaque"] = "retain elsewhere";
    row["networks"] = Json::Value(Json::arrayValue); row["networks"].append(nic);
    nic["network_id"] = other["id"]; row["networks"].append(nic);
    row["opaque"] = "VM extension";
    auto document = c.service.vms().snapshot(admin)->document;
    document["root_extension"] = "preserve";
    document["vms"].append(row); document["vms"].append(unrelated);
    auto saved = c.service.vms().replace(admin, c.service.vms().snapshot(admin)->revision, document);
    return {network, saved, row["id"].asString(), unrelated["id"].asString()};
}
void coordinated_network_delete() {
    Fixture fixture;
    Coordinated c(fixture);
    auto input = seed_deletion(c);
    auto old = c.inventory.runtime(admin, input.vm_id);
    auto unchanged = c.inventory.runtime(admin, input.unrelated_id);
    auto view = c.tasks.vm_config_snapshot(admin);
    const auto result = c.service.remove_network(admin, input.baseline->revision, input.network);
    check(result->revision != input.baseline->revision && result->persisted && !result->durability_uncertain,
        "deletion returns a new durable VM revision");
    check(result->document["root_extension"] == "preserve" && result->document["vms"][0]["opaque"] == "VM extension"
        && result->document["vms"][0]["networks"].size() == 1
        && result->document["vms"][0]["networks"][0]["opaque"] == "retain elsewhere", "only target NICs removed");
    check(!c.service.networks().exists(admin, input.network["id"].asString()) && c.service.networks().list(admin).size() == 1,
        "network list changed in same transaction");
    check(c.inventory.runtime(admin, input.vm_id) != old && c.inventory.runtime(admin, input.unrelated_id) == unchanged,
        "affected runtime replaced and unrelated runtime retained");
    check(!old->start() && fixture.starts == 0, "pre-transaction runtime cannot start after deletion");
    check(c.tasks.snapshot_page(admin, view.id, 0).id == view.id, "old fixed view survives coherent replacement");
    c.tasks.release_snapshot(admin, view.id);
    check(config::JsonFile(c.directory.get(), "vms.json", getuid(), {}, VmConfigService::max_bytes).load()->value == result->document,
        "VM file matches published revision");
    check(config::JsonFile(c.directory.get(), "networks.json", getuid()).load()->value["networks"].size() == 1,
        "network file matches published removal");
    error(ErrorCode::conflict, [&] { c.service.remove_network(admin, input.baseline->revision, input.network); });
    error(ErrorCode::not_found, [&] { c.service.remove_network(admin, result->revision, input.network); });
}
void coordinated_vm_network_references() {
    Fixture fixture;
    Coordinated c(fixture);
    auto input = seed_deletion(c);
    const auto id = input.network["id"].asString();
    error(ErrorCode::conflict, [&] { c.service.networks().remove(admin, id); });
    auto before = c.service.vms().snapshot(admin);
    auto runtime = c.inventory.runtime(admin, input.vm_id);
    auto invalid = before->document;
    invalid["vms"][0]["networks"][0]["network_id"] = random_id(true);
    error(ErrorCode::conflict, [&] { c.service.vms().replace(admin, before->revision, invalid); });
    check(c.service.vms().snapshot(admin)->revision == before->revision
        && c.inventory.runtime(admin, input.vm_id) == runtime, "missing reference rejected before runtime publication");
    Json::Value op; op["op"] = "replace"; op["config"] = invalid["vms"][0];
    Json::Value operations(Json::arrayValue); operations.append(op);
    error(ErrorCode::conflict, [&] { c.service.vms().apply(admin, before->revision, operations); });
    ConfigUploads uploads(&c.service.vms(), &c.service.networks());
    auto encoded = config::encode_json(invalid);
    auto upload = uploads.begin(admin, before->revision, encoded.size());
    uploads.append(admin, upload, 0, encoded);
    error(ErrorCode::conflict, [&] { uploads.commit(admin, upload); });
    check(config::JsonFile(c.directory.get(), "vms.json", getuid(), {}, VmConfigService::max_bytes).load()->value == before->document,
        "all VM write adapters reject dangling refs without changing disk");
    auto canonical = before->document;
    auto upper = id;
    for (auto& ch : upper) if (ch >= 'a' && ch <= 'f') ch -= 'a' - 'A';
    canonical["vms"][0]["networks"][0]["network_id"] = upper;
    before = c.service.vms().replace(admin, before->revision, canonical);
    auto deleted = c.service.remove_network(admin, before->revision, input.network);
    error(ErrorCode::conflict, [&] { c.service.vms().replace(admin, deleted->revision, before->document); });
    check(!c.service.networks().exists(admin, id), "fresh revision cannot resurrect deleted network references");
}
void coordinated_historical_network_references() {
    Fixture fixture;
    Fd directory(open(fixture.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    auto row = config("historical");
    Json::Value nic; nic["network_id"] = random_id(true); nic["extension"] = "old";
    row["networks"] = Json::Value(Json::arrayValue); row["networks"].append(nic);
    auto future = config("future"); future["schema"] = 999;
    nic["network_id"] = future["id"]; row["networks"].append(nic);
    nic["network_id"] = "malformed"; row["networks"].append(nic);
    Json::Value vm_document; vm_document["vms"] = Json::Value(Json::arrayValue); vm_document["vms"].append(row);
    Json::Value network_document; network_document["networks"] = Json::Value(Json::arrayValue); network_document["networks"].append(future);
    config::JsonFile(directory.get(), "vms.json", getuid()).save(vm_document);
    config::JsonFile(directory.get(), "networks.json", getuid()).save(network_document);
    Coordinated c(fixture);
    auto base = c.service.vms().snapshot(admin);
    auto renamed = base->document; renamed["vms"][0]["name"] = "repairable";
    base = c.service.vms().replace(admin, base->revision, renamed);
    for (int mode = 0; mode < 3; ++mode) {
        auto invalid = base->document;
        if (mode == 0) invalid["vms"][0]["networks"].append(invalid["vms"][0]["networks"][0]);
        if (mode == 1) invalid["vms"][0]["networks"][0]["extension"] = "changed";
        if (mode == 2) {
            auto copy = invalid["vms"][0]; copy["id"] = random_id(true); copy["name"] = "copy";
            invalid["vms"].append(copy);
        }
        error(ErrorCode::conflict, [&] { c.service.vms().replace(admin, base->revision, invalid); });
    }
    auto repaired = base->document; repaired["vms"][0]["networks"] = Json::Value(Json::arrayValue);
    auto saved = c.service.vms().replace(admin, base->revision, repaired);
    check(saved->document["vms"][0]["networks"].empty(), "historical dangling refs load, survive unrelated edits and can be removed");
}
void coordinated_reference_delete_races() {
    for (int i = 0; i < 16; ++i) {
        Fixture fixture;
        Coordinated c(fixture);
        auto input = seed_deletion(c);
        auto edited = input.baseline->document; edited["vms"][0]["name"] = "concurrent edit";
        std::promise<void> ready; auto begin = ready.get_future().share();
        auto save = std::async(std::launch::async, [&] {
            begin.wait();
            try { c.service.vms().replace(admin, input.baseline->revision, edited); }
            catch (const ServiceError& error) {
                check(error.code() == ErrorCode::conflict || error.code() == ErrorCode::unavailable, "save race has bounded rejection");
            }
        });
        auto remove = std::async(std::launch::async, [&] {
            begin.wait();
            try { c.service.remove_network(admin, input.baseline->revision, input.network); }
            catch (const ServiceError& error) { check(error.code() == ErrorCode::conflict, "delete race rejects stale VM revision"); }
        });
        ready.set_value(); save.get(); remove.get();
        const bool exists = c.service.networks().exists(admin, input.network["id"].asString());
        const auto after = c.service.vms().snapshot(admin);
        check(after->document["vms"][0]["networks"].size() == (exists ? 2u : 1u), "VM edits and deletion never publish a new dangling reference");
        check(config::JsonFile(c.directory.get(), "vms.json", getuid(), {}, VmConfigService::max_bytes).load()->value == after->document,
            "racing edits preserve durable inventory view");
    }
}
void coordinated_delete_rejections() {
    Fixture fixture;
    Coordinated c(fixture);
    auto input = seed_deletion(c);
    error(ErrorCode::unauthenticated, [&] { c.service.remove_network({}, input.baseline->revision, input.network); });
    error(ErrorCode::permission_denied, [&] { c.service.remove_network(owner, input.baseline->revision, input.network); });
    auto stale = input.network; stale["name"] = "stale";
    error(ErrorCode::conflict, [&] { c.service.remove_network(admin, input.baseline->revision, stale); });
    {
        auto runtime = c.inventory.runtime(admin, input.vm_id);
        auto lease = runtime->try_edit(); check(bool(lease), "reserve affected VM");
        error(ErrorCode::conflict, [&] { c.service.remove_network(admin, input.baseline->revision, input.network); });
    }
    check(c.service.vms().snapshot(admin)->revision == input.baseline->revision
        && c.service.networks().get(admin, input.network["id"].asString()) == input.network, "rejections preserve both stores");
    {
        auto lease = c.service.networks().prepare_runtime(admin, input.network["id"].asString());
        auto current = c.service.networks().get(admin, input.network["id"].asString());
        error(ErrorCode::conflict, [&] { c.service.remove_network(admin, input.baseline->revision, current); });
    }
    check(c.service.vms().snapshot(admin)->revision == input.baseline->revision, "busy network does not remove VM references");
}
void coordinated_delete_failure_recovery() {
    for (const char* boundary : {"before_decision", "participant_synced", "decision_removed"}) {
        Fixture fixture;
        bool fail = true;
        Coordinated c(fixture, [&](const char* stage, size_t) {
            if (fail && std::string_view(stage) == boundary) throw std::runtime_error("injected coordinated commit failure");
        });
        auto input = seed_deletion(c);
        auto old = c.inventory.runtime(admin, input.vm_id);
        const bool decided = std::string_view(boundary) != "before_decision";
        error(decided ? ErrorCode::commit_uncertain : ErrorCode::io_error,
            [&] { c.service.remove_network(admin, input.baseline->revision, input.network); });
        if (decided) {
            error(ErrorCode::unavailable, [&] { c.service.vms().snapshot(admin); });
            error(ErrorCode::unavailable, [&] { c.service.networks().list(admin); });
            error(ErrorCode::unavailable, [&] { c.inventory.list(admin); });
            error(ErrorCode::unavailable, [&] { c.tasks.network_config_document(admin); });
            error(ErrorCode::unavailable, [&] { c.service.remove_network(admin, input.baseline->revision, input.network); });
            check(!old->start() && fixture.starts == 0, "uncertain deletion prevents old runtime admission");
            if (std::string_view(boundary) == "participant_synced")
                error(ErrorCode::unavailable, [&] { c.service.recover(admin); });
        } else check(c.service.vms().snapshot(admin)->revision == input.baseline->revision
            && c.service.networks().get(admin, input.network["id"].asString()) == input.network, "pre-decision IO failure preserves state");
        fail = false;
        c.service.recover(admin);
        auto current = c.service.vms().snapshot(admin);
        check(current->document["vms"][0]["networks"].size() == (decided ? 1u : 2u), "recovery publishes correct complete generation");
        check(c.service.networks().exists(admin, input.network["id"].asString()) != decided,
            "recovery keeps network and NIC outcomes consistent");
        if (decided) check(!current->durability_uncertain, "recovered transaction is durable");
    }
}
void coordinated_constructor_and_delete_race() {
    Fixture fixture;
    Fd directory(open(fixture.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    auto gate = std::make_shared<ConfigurationGate>();
    TaskService tasks({}, [] { return TaskService::Clock::now(); }, {}, gate);
    {
        VmService wrong(fixture.context);
        bool refused = false;
        try { ConfigurationService service(directory.get(), getuid(), gate, wrong, tasks); }
        catch (const std::invalid_argument&) { refused = true; }
        check(refused && faccessat(directory.get(), "vms.config-owner", F_OK, 0) != 0,
            "mismatched gate rejected before ownership or IO");
    }
    Coordinated c(fixture);
    auto input = seed_deletion(c);
    std::atomic<int> committed{0}, conflicts{0}, failures{0};
    std::vector<std::thread> writers;
    for (int i = 0; i < 12; ++i) writers.emplace_back([&] {
        try { c.service.remove_network(admin, input.baseline->revision, input.network); ++committed; }
        catch (const ServiceError& error) { if (error.code() == ErrorCode::conflict) ++conflicts; else ++failures; }
        catch (...) { ++failures; }
    });
    for (auto& writer : writers) writer.join();
    check(committed == 1 && conflicts == 11 && failures == 0, "one conditional delete wins, no rebasing competing callers");
    check(c.service.vms().snapshot(admin)->document["vms"][0]["networks"].size() == 1
        && !c.service.networks().exists(admin, input.network["id"].asString()), "concurrent deletion preserves cross-store result");
}
void coordinated_delete_restart() {
    Fixture fixture;
    std::string id, old_revision;
    {
        Coordinated c(fixture, [](const char* stage, size_t) {
            if (std::string_view(stage) == "participant_synced") throw std::runtime_error("interrupted between files");
        });
        auto input = seed_deletion(c); id = input.network["id"].asString(); old_revision = input.baseline->revision;
        error(ErrorCode::commit_uncertain, [&] { c.service.remove_network(admin, old_revision, input.network); });
    }
    Coordinated reopened(fixture);
    const auto current = reopened.service.vms().snapshot(admin);
    check(current->revision != old_revision && current->document["vms"][0]["networks"].size() == 1
        && !reopened.service.networks().exists(admin, id), "startup redo precedes both service loads");
    bool vm_refused = false, network_refused = false;
    try { config::require_legacy_vm_config(reopened.directory.get(), getuid()); } catch (...) { vm_refused = true; }
    try { config::require_legacy_network_config(reopened.directory.get(), getuid()); } catch (...) { network_refused = true; }
    check(vm_refused && network_refused, "both persistent ownership gates precede transaction recovery");
}
void replacement_and_failure() {
    Fixture fixture;
    VmService service(fixture.context);
    auto first = config("first"), second = config("second");
    auto id = service.create(admin, first);
    auto other = service.create(admin, second);
    auto original = service.runtime(admin, id);
    auto unchanged = service.runtime(admin, other);
    auto* log = original->log("stdio");
    log->append("console survives rejected edit\n");
    auto edited = first; edited["name"] = "second";
    error(ErrorCode::invalid_argument, [&] { service.modify(admin, edited); });
    check(service.runtime(admin, id) == original && original->log("stdio") == log && !log->contents().empty(), "rejected duplicate rename retains runtime and console");
    check(!original->start() && fixture.starts == 1, "failed edit does not retire original");
    edited["name"] = "changed";
    service.modify(admin, edited);
    auto replacement = service.runtime(admin, id);
    check(replacement != original && service.runtime(admin, other) == unchanged, "replace only modified runtime");
    check(replacement->log("stdio")->contents() == log->contents(), "legacy replacement reloads persistent console history");
    check(!original->start() && fixture.starts == 1, "stale reference cannot reach lifecycle side effects");
    check(!replacement->start() && fixture.starts == 2, "replacement retains start admission");
    check(!original->try_edit(), "retired instance cannot be edited again");
    check(service.remove(admin, id), "remove replacement");
    check(!service.exists(admin, id) && !replacement->start() && fixture.starts == 2, "removed reference cannot restart");
    check(!service.remove(admin, id), "unknown deletion retains legacy false result");
}
struct DeleteBackendState {
    bool running = false, fail_stop = false;
    int stops = 0, detaches = 0;
    std::function<void()> on_stop, on_manual;
};
class DeleteBackend final : public network::Backend {
public:
    explicit DeleteBackend(DeleteBackendState& state) : state_(state) {}
    void start(const Json::Value&) override { state_.running = true; }
    bool healthy() const override { return state_.running; }
    void recover(const Json::Value& value) override { start(value); }
    void stop() override {
        ++state_.stops;
        if (state_.on_stop) state_.on_stop();
        if (state_.fail_stop) throw std::runtime_error("cleanup incomplete");
        state_.running = false;
    }
    bool manual_address(const std::string&, bool) override { if (state_.on_manual) state_.on_manual(); return true; }
    void detach(const Json::Value&, const std::string&) override { ++state_.detaches; }
private:
    DeleteBackendState& state_;
};
void coordinated_delete_auto_stop() {
    for (int mode = 0; mode < 3; ++mode) {
        Fixture fixture;
        bool fail_commit = mode == 2;
        Coordinated c(fixture, [&](const char* stage, size_t) {
            if (fail_commit && std::string_view(stage) == "before_decision") throw std::runtime_error("staging failed");
        });
        auto input = seed_deletion(c);
        input.network["bridge_type"] = "gvisor";
        c.service.networks().update(admin, input.network);
        DeleteBackendState state; state.fail_stop = mode == 1;
        NetworkService runtime(c.service.networks(), [&](const Json::Value&) { return std::make_unique<DeleteBackend>(state); });
        const auto id = input.network["id"].asString();
        check(runtime.start(admin, id).state == NetworkState::running, "start isolated deletion backend");
        input.network = c.service.networks().get(admin, id);
        state.on_stop = [&] {
            error(ErrorCode::unavailable, [&] { runtime.start(admin, id); });
            error(ErrorCode::unavailable, [&] { c.service.networks().get(admin, id); });
        };
        error(ErrorCode::conflict, [&] { c.service.remove_network(admin, "stale", input.network, &runtime); });
        {
            auto lease = c.inventory.runtime(admin, input.vm_id)->try_edit();
            error(ErrorCode::conflict, [&] { c.service.remove_network(admin, input.baseline->revision, input.network, &runtime); });
        }
        check(state.stops == 0, "confirmation and VM lease rejection precede backend stop");
        if (mode) {
            error(ErrorCode::io_error, [&] { c.service.remove_network(admin, input.baseline->revision, input.network, &runtime); });
            check(c.service.vms().snapshot(admin)->revision == input.baseline->revision && c.service.networks().get(admin, id) == input.network,
                "stop/staging failure retains both configurations");
            if (mode == 1) {
                check(runtime.get(admin, id).state == NetworkState::failed, "failed cleanup remains observable");
                error(ErrorCode::conflict, [&] { c.service.networks().update(admin, input.network); });
            } else check(runtime.get(admin, id).state == NetworkState::stopped, "pre-decision failure may leave network safely stopped");
            state.fail_stop = false; fail_commit = false;
        }
        const auto saved = c.service.remove_network(admin, input.baseline->revision, input.network, &runtime);
        check(!state.running && saved->document["vms"][0]["networks"].size() == 1 && !c.service.networks().exists(admin, id),
            "automatic stop precedes atomic network and NIC removal");
        check(state.stops == (mode == 1 ? 2 : 1), "cleanup is not replayed after successful stop");
        state.on_stop = {}; // Shutdown does not use transaction callbacks.
    }
}
void coordinated_delete_drains_network_operation() {
    Fixture fixture;
    Coordinated c(fixture);
    auto input = seed_deletion(c); input.network["bridge_type"] = "gvisor";
    c.service.networks().update(admin, input.network);
    DeleteBackendState state;
    NetworkService runtime(c.service.networks(), [&](const Json::Value&) { return std::make_unique<DeleteBackend>(state); });
    const auto id = input.network["id"].asString(); runtime.start(admin, id);
    input.network = c.service.networks().get(admin, id);
    Gate entered, release;
    state.on_manual = [&] { entered.release(); release.wait(); };
    auto manual = std::async(std::launch::async, [&] { return runtime.manual(admin, id, true, "test", true); });
    entered.wait();
    std::atomic<bool> deleted{false};
    auto deletion = std::async(std::launch::async, [&] {
        c.service.remove_network(admin, input.baseline->revision, input.network, &runtime); deleted = true;
    });
    bool draining = false;
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (!draining && std::chrono::steady_clock::now() < deadline) {
        try { auto admitted = ConfigurationGate::enter(c.gate); }
        catch (const ServiceError& error) { draining = error.code() == ErrorCode::unavailable; }
        std::this_thread::yield();
    }
    const bool premature = deleted.load();
    release.release();
    check(manual.get(), "in-flight manual operation finishes");
    deletion.get();
    check(draining && !premature && deleted && state.stops == 1, "delete drains entire network operation before cleanup");
}
void network_cleanup_during_recovery() {
    Fixture fixture;
    Coordinated c(fixture);
    auto input = seed_deletion(c); input.network["bridge_type"] = "gvisor";
    c.service.networks().update(admin, input.network);
    DeleteBackendState state;
    NetworkService runtime(c.service.networks(), [&](const Json::Value&) { return std::make_unique<DeleteBackend>(state); });
    const auto id = input.network["id"].asString(); runtime.start(admin, id);
    { auto exclusive = c.gate->transaction(); exclusive.require_recovery(); }
    error(ErrorCode::unavailable, [&] { runtime.start(admin, id); });
    error(ErrorCode::permission_denied, [&] { runtime.stop(owner, id); });
    runtime.detach_nic(admin, id, {}, "test-tap");
    check(state.detaches == 1 && runtime.stop(admin, id).state == NetworkState::stopped && state.stops == 1,
        "pending configuration recovery does not prevent resource cleanup");
    c.service.recover(admin);
    check(c.service.networks().exists(admin, id), "cleanup never removes persistent configuration");
}
std::string encode_chunk(const std::string& bytes) {
    const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    for (size_t i = 0; i < bytes.size(); i += 3) {
        const auto a = static_cast<unsigned char>(bytes[i]);
        const auto b = i + 1 < bytes.size() ? static_cast<unsigned char>(bytes[i + 1]) : 0;
        const auto d = i + 2 < bytes.size() ? static_cast<unsigned char>(bytes[i + 2]) : 0;
        encoded += alphabet[a >> 2]; encoded += alphabet[((a & 3) << 4) | (b >> 4)];
        encoded += i + 1 < bytes.size() ? alphabet[((b & 15) << 2) | (d >> 6)] : '=';
        encoded += i + 2 < bytes.size() ? alphabet[d & 63] : '=';
    }
    return encoded;
}
void coordinated_vm_disk_adapter() {
    for (bool inject : {false, true}) {
        Fixture fixture; bool fail = false;
        Coordinated c(fixture, [&](const char* stage, size_t) {
            if (fail && std::string_view(stage) == "participant_synced") throw std::runtime_error("joint adapter uncertainty");
        }, true);
        auto input = seed_vm_disk(c);
        SystemService system([] { return true; }, [] { return "test"; }, "test", c.tasks.epoch());
        RequestDispatcher dispatcher(system, c.tasks, &c.service.networks(), nullptr, nullptr, nullptr, &c.inventory);
        dispatcher.set_configuration(&c.service);
        ClientSession session; session.caller.authorized = true;
        const auto caps = dispatcher.execute(session, "capabilities", {});
        check(caps["configuration_vm_disks"] == "revisioned-chunks-v1" && caps["service_api_minor"] == 24
            && dispatcher.background("configuration_vm_disks_commit"), "joint capability and worker dispatch");
        auto rejected = [](const Json::Value& response, const char* code) {
            check(response["success"] == false && response["error"]["code"] == code, "joint adapter structured rejection");
        };
        Json::Value payload; payload["vms"] = input.baseline.vms->document; payload["disks"] = input.baseline.disks->document;
        payload["vms"]["vms"][0]["disks"].clear(); payload["disks"]["disks"].clear();
        const auto bytes = config::encode_json(payload, ConfigUploads::max_vm_disk_bytes);
        Json::Value begin; begin["vm_revision"] = input.baseline.vms->revision; begin["disk_revision"] = input.baseline.disks->revision;
        begin["bytes"] = Json::UInt64(bytes.size());
        rejected(dispatcher.execute_background({}, "configuration_vm_disks_begin", begin), "UNAUTHENTICATED");
        auto bad = begin; bad["revision"] = "unexpected";
        rejected(dispatcher.execute_background(admin, "configuration_vm_disks_begin", bad), "INVALID_ARGUMENT");
        const auto started = dispatcher.execute_background(admin, "configuration_vm_disks_begin", begin);
        check(started["success"] == true, "joint adapter begin");
        // Idempotent participant binding must not discard the active joint upload.
        dispatcher.set_vm_config(&c.service.vms()); dispatcher.set_disk_config(c.service.disks());
        Json::Value chunk; chunk["upload_id"] = started["upload_id"]; chunk["offset"] = 0; chunk["data"] = "bad!";
        rejected(dispatcher.execute_background(admin, "configuration_vm_disks_append", chunk), "INVALID_ARGUMENT");
        chunk["data"] = encode_chunk(std::string(bytes.data(), bytes.size()));
        check(dispatcher.execute_background(admin, "configuration_vm_disks_append", chunk)["received"] == bytes.size(), "joint adapter chunk");
        Json::Value commit; commit["upload_id"] = started["upload_id"]; fail = inject;
        const auto result = dispatcher.execute_background(admin, "configuration_vm_disks_commit", commit);
        if (inject) {
            rejected(result, "COMMIT_UNCERTAIN"); fail = false;
            check(dispatcher.execute_background(admin, "configuration_recover", Json::Value(Json::objectValue))["success"] == true,
                "joint adapter explicit recovery");
        } else check(result["success"] == true && result["vms"]["persisted"] == true && result["disks"]["persisted"] == true
            && result["vms"]["revision"] != input.baseline.vms->revision && result["disks"]["revision"] != input.baseline.disks->revision,
            "joint acknowledgement includes both versions");
        rejected(dispatcher.execute_background(admin, "configuration_vm_disks_commit", commit), "NOT_FOUND");
        check(c.service.vms().snapshot(admin)->document["vms"][0]["disks"].empty()
            && c.service.disks()->snapshot(admin)->document["disks"].empty(), "joint adapter reaches coherent end state");
    }
}
void coordinated_delete_adapter() {
    for (bool inject : {false, true}) {
        Fixture fixture;
        bool fail = inject;
        Coordinated c(fixture, [&](const char* stage, size_t) {
            if (fail && std::string_view(stage) == "participant_synced") throw std::runtime_error("adapter commit failure");
        });
        auto input = seed_deletion(c);
        SystemService system([] { return true; }, [] { return "test"; }, "test", c.tasks.epoch());
        NetworkService runtime(c.service.networks(), [](const Json::Value&) -> std::unique_ptr<network::Backend> {
            throw std::runtime_error("test must not start a backend");
        });
        RequestDispatcher dispatcher(system, c.tasks, &c.service.networks(), nullptr, &runtime, nullptr, &c.inventory);
        dispatcher.set_configuration(&c.service);
        dispatcher.set_vm_config(&c.service.vms()); // Idempotent binding must retain deletion staging.
        ClientSession session; session.caller.authorized = true;
        auto caps = dispatcher.execute(session, "capabilities", {});
        check(caps["service_api_minor"] == 21 && caps["network_config_delete"] == "revisioned-stop-chunks-v1"
            && caps["configuration_recover"] == "redo-v1" && dispatcher.background("network_config_delete_commit")
            && dispatcher.background("configuration_recover"), "coordinated commands advertised and worker dispatched");
        auto assert_error = [](const Json::Value& result, const char* code) {
            check(result["success"] == false && result["error"]["code"] == code, "structured coordinated adapter error");
        };
        Json::Value old; old["network_id"] = input.network["id"];
        assert_error(dispatcher.execute_background(admin, "network_delete", old), "CONFLICT");
        assert_error(dispatcher.execute_background(owner, "configuration_recover", Json::Value(Json::objectValue)), "PERMISSION_DENIED");
        Json::Value payload; payload["expected"] = input.network;
        const auto bytes = config::encode_json(payload);
        Json::Value begin; begin["revision"] = input.baseline->revision; begin["bytes"] = Json::UInt64(bytes.size());
        auto bad = begin; bad["typo"] = true;
        assert_error(dispatcher.execute_background(admin, "network_config_delete_begin", bad), "INVALID_ARGUMENT");
        assert_error(dispatcher.execute_background({}, "network_config_delete_begin", begin), "UNAUTHENTICATED");
        auto started = dispatcher.execute_background(admin, "network_config_delete_begin", begin);
        check(started["success"] == true && started["chunk_bytes"] == 49152, "delete upload begun");
        // Encode a real request payload, keeping this fixture independent of the
        // production decoder. Full-size chunk handling is covered by upload tests.
        const auto encoded = encode_chunk(std::string(bytes.data(), bytes.size()));
        Json::Value chunk; chunk["upload_id"] = started["upload_id"]; chunk["offset"] = 0; chunk["data"] = encoded;
        check(dispatcher.execute_background(admin, "network_config_delete_append", chunk)["received"] == bytes.size(), "encoded delete confirmation accepted");
        Json::Value commit; commit["upload_id"] = started["upload_id"];
        const auto reply = dispatcher.execute_background(admin, "network_config_delete_commit", commit);
        if (inject) {
            assert_error(reply, "COMMIT_UNCERTAIN");
            fail = false;
            check(dispatcher.execute_background(admin, "configuration_recover", Json::Value(Json::objectValue))["success"] == true,
                "explicit recovery repairs the original decision");
        } else check(reply["success"] == true && reply["network_id"] == input.network["id"] && reply["persisted"] == true
            && reply["revision"] != input.baseline->revision, "delete acknowledgement includes network identity and VM version");
        assert_error(dispatcher.execute_background(admin, "network_config_delete_commit", commit), "NOT_FOUND");
        check(!c.service.networks().exists(admin, input.network["id"].asString()), "adapter deletion reaches both stores");
    }
}
void conditional_network_adapter() {
    Fixture fixture;
    Fd directory(open(fixture.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    TaskService tasks;
    NetworkConfigService networks(directory.get(), getuid(), {}, &tasks);
    SystemService system([] { return true; }, [] { return "test"; }, "test", tasks.epoch());
    RequestDispatcher dispatcher(system, tasks, &networks);
    ClientSession session; session.caller.authorized = true;
    const auto caps = dispatcher.execute(session, "capabilities", {});
    check(caps["network_config_update"] == "compare-config-v1" && caps["service_api_minor"] == 19
        && caps["network_config_document"] == "base64-json-chunks-v1",
        "conditional network edit capability is advertised");
    check(dispatcher.background("network_config_get") && dispatcher.background("network_config_update"),
        "configuration operations use bounded workers");
    auto value = config("network"); value["schema"] = 2; value["bridge_name"] = "brtest";
    const auto id = networks.create(admin, value);
    Json::Value read; read["network_id"] = id;
    auto response = dispatcher.execute_background(admin, "network_config_get", read);
    check(response["success"] == true && response["config"] == networks.get(admin, id)
        && !response["config"].isMember("state"), "read returns exact configuration without runtime projection");
    Json::Value update;
    update["type"] = "request"; update["command"] = "network_config_update"; update["request_id"] = "request";
    update["expected"] = response["config"]; update["config"] = response["config"];
    update["config"]["name"] = "updated";
    auto expect_error = [&](const CallContext& caller, const Json::Value& request, const char* code) {
        const auto result = dispatcher.execute_background(caller, "network_config_update", request);
        check(result["success"] == false && result["error"]["code"] == code, "structured conditional edit error");
    };
    expect_error({}, update, "UNAUTHENTICATED");
    expect_error(owner, update, "PERMISSION_DENIED");
    expect_error(admin, Json::Value(Json::arrayValue), "INVALID_ARGUMENT");
    expect_error(admin, Json::Value(Json::objectValue), "INVALID_ARGUMENT");
    response = dispatcher.execute_background(admin, "network_config_update", update);
    check(response["success"] == true && response["network_id"] == id, "conditional adapter accepts request envelope");
    expect_error(admin, update, "CONFLICT");
    check(networks.get(admin, id)["name"] == "updated", "stale request cannot overwrite target");
    check(caps["network_config_import"] == "conditional-chunks-v1"
        && dispatcher.background("network_config_import_commit"), "network import staging is advertised on workers");
    Json::Value begin; begin["type"] = "request"; begin["bytes"] = 17;
    auto started = dispatcher.execute_background(admin, "network_config_import_begin", begin);
    check(started["success"] == true && started["chunk_bytes"] == Json::UInt64(48u << 10), "network staging begins");
    Json::Value chunk; chunk["upload_id"] = started["upload_id"]; chunk["offset"] = 0;
    chunk["data"] = "eyJvcGVyYXRpb25zIjpbXX0=";
    check(dispatcher.execute_background(admin, "network_config_import_append", chunk)["received"] == 17, "network staging accepts strict base64");
    auto committed = dispatcher.execute_background(admin, "network_config_import_commit", chunk);
    check(committed["success"] == true && committed["network_ids"].isArray() && committed["network_ids"].empty(),
        "network staging consumes an empty atomic import");
    check(dispatcher.execute_background(admin, "network_config_import_commit", chunk)["error"]["code"] == "NOT_FOUND",
        "network import cannot commit twice");
}
void network_removal_is_atomic() {
    Fixture fixture;
    VmService service(fixture.context);
    auto first = config("first"), second = config("second"), untouched = config("untouched");
    Json::Value nic; nic["network_id"] = "removed"; nic["extension"] = "keep";
    first["networks"].append(nic); second["networks"].append(nic);
    nic["network_id"] = "retained"; first["networks"].append(nic);
    const auto a = service.create(admin, first), b = service.create(admin, second);
    const auto c = service.create(admin, untouched);
    auto before_a = service.runtime(admin, a), before_b = service.runtime(admin, b);
    auto before_c = service.runtime(admin, c);
    const auto config_a = before_a->config(), config_b = before_b->config();
    {
        auto busy = before_b->try_edit();
        check(bool(busy), "hold second VM lifecycle lease");
        error(ErrorCode::conflict, [&] { service.drop_network("removed"); });
        check(service.runtime(admin, a) == before_a && service.runtime(admin, b) == before_b,
            "later busy VM aborts all replacements");
        check(before_a->config() == config_a && before_b->config() == config_b,
            "failed network removal preserves every NIC");
        check(!before_a->start() && fixture.starts == 1, "aborted removal releases earlier lease without retiring");
    }
    service.drop_network("removed");
    check(service.runtime(admin, a) != before_a && service.runtime(admin, b) != before_b,
        "successful removal replaces every affected runtime");
    check(service.runtime(admin, c) == before_c, "unaffected runtime survives");
    check(!before_a->start() && !before_b->start() && fixture.starts == 1,
        "stale runtimes cannot start with removed network");
    check(service.get(admin, a)["networks"].size() == 1
        && service.get(admin, a)["networks"][0] == nic
        && service.get(admin, b)["networks"].empty(), "only target NICs removed and opaque fields preserved");
    const auto after = service.runtime(admin, a);
    service.drop_network("removed");
    check(service.runtime(admin, a) == after, "repeated removal preserves unchanged runtime");
}
void session_overrides_and_failed_admission() {
    Fixture fixture;
    auto value = config("session");
    value["protected_vm"] = "protected_protected";
    Json::Value disk;
    disk["path"] = "/never-opened.img"; disk["readonly"] = false;
    value["disks"] = Json::Value(Json::arrayValue); value["disks"].append(disk);
    std::shared_ptr<vm::VmRuntime> target;
    Json::Value observed;
    bool throw_on_admission = false;
    fixture.context.shutting_down = [&] {
        observed = target->config();
        if (throw_on_admission) throw std::runtime_error("injected admission failure");
        return true;
    };
    target = std::make_shared<vm::VmRuntime>(value["id"].asString(), value, fixture.context);
    const auto baseline = target->config();
    Json::Value overrides;
    overrides["readonly_disks"] = Json::Value(Json::arrayValue); overrides["readonly_disks"].append(0);
    overrides["pseudo_unprotected"] = true;
    check(!target->start({}, overrides), "shutdown refuses session start without side effects");
    check(observed["protected_vm"] == "pseudo_unprotected" && observed["disks"][0]["readonly"].asBool(), "start admission sees requested session settings");
    check(target->config() == baseline, "failed admission restores original configuration");
    check(!target->start() && observed == baseline, "later ordinary start does not inherit overrides");
    throw_on_admission = true;
    bool threw = false;
    try { target->start({}, overrides); } catch (const std::runtime_error&) { threw = true; }
    check(threw && target->config() == baseline, "admission exception restores original configuration");
    { auto edit = target->try_edit(); check(bool(edit), "failed session remains editable"); edit.retire(); }
    check(!target->start({}, overrides) && target->config() == baseline, "retired reference cannot install session overrides");
}
void invalid_session_overrides() {
    Fixture fixture;
    auto value = config("invalid-session");
    Json::Value disk; disk["path"] = "/never-opened.img"; disk["readonly"] = false;
    value["disks"] = Json::Value(Json::arrayValue); value["disks"].append(disk);
    auto target = std::make_shared<vm::VmRuntime>(value["id"].asString(), value, fixture.context);
    const auto baseline = target->config();
    const std::vector<std::string> invalid{
        R"([])", R"({"memory_mb":1024})", R"({"pseudo_unprotected":false})",
        R"({"readonly_disks":[-1]})", R"({"readonly_disks":[1]})", R"({"readonly_disks":[0,0]})",
        R"({"readonly_disks":[0.0]})", R"({"readonly_disks":["0"]})",
        R"({"readonly_disks":[0],"unknown":true})"};
    for (const auto& text : invalid) {
        bool rejected = false;
        try { target->start({}, wire::parse(text)); } catch (const std::invalid_argument&) { rejected = true; }
        check(rejected && target->config() == baseline && fixture.starts == 0, "invalid session is atomic and rejected before start admission");
    }
}
void session_overrides_worker_abort() {
    Fixture fixture;
    auto value = config("worker-abort");
    value["backend"] = "qemu"; value["hypervisor"] = "kvm";
    value["protected_vm"] = "protected_normal";
    std::atomic<int> admissions{0};
    // Admit lifecycle setup, then abort on the worker before launching a backend.
    fixture.context.shutting_down = [&] { return ++admissions > 1; };
    auto target = std::make_shared<vm::VmRuntime>(value["id"].asString(), value, fixture.context);
    const auto baseline = target->config();
    Json::Value overrides; overrides["pseudo_unprotected"] = true;
    target->log("stdio")->append("previous run\n");
    check(target->start({}, overrides, true), "session reaches asynchronous worker");
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (target->state() != vm::State::stopped && std::chrono::steady_clock::now() < deadline)
        std::this_thread::yield();
    check(target->state() == vm::State::stopped && target->pid() == -1 && admissions >= 2, "worker aborts before VMM launch");
    check(target->config() == baseline, "STOPPED publication restores complete baseline after worker abort");
    check(target->log("stdio")->contents().find("previous run") == std::string::npos, "admitted start clears previous run logs");
    check(bool(target->try_edit()), "completed session releases lifecycle admission");
}
void lease_abort_and_lifetime() {
    Fixture fixture;
    auto target = std::make_shared<vm::VmRuntime>(random_id(true), config("lease"), fixture.context);
    std::weak_ptr<vm::VmRuntime> weak = target;
    {
        auto edit = target->try_edit();
        check(bool(edit), "fully stopped runtime admits lease");
        // Do not try to recursively lock a non-recursive mutex on this thread.
        auto contender = std::async(std::launch::async, [&] { return bool(target->try_edit()); });
        check(!contender.get(), "second edit is rejected without waiting");
    }
    check(!target->start() && fixture.starts == 1, "aborting lease reopens start admission");
    {
        auto edit = target->try_edit();
        auto moved = std::move(edit);
        target.reset();
        check(!weak.expired() && bool(moved), "moved lease pins runtime until mutex unlock");
        moved.retire();
    }
    check(weak.expired(), "lease releases runtime after unlocking");
}
void lifecycle_races(int operation) {
    for (int i = 0; i < 16; ++i) {
        Fixture fixture;
        Gate started, proceed;
        VmService* inventory = nullptr;
        fixture.context.shutting_down = [&] {
            ++fixture.starts; started.release(); proceed.wait();
            // Simulate start/network hooks calling back into the inventory.
            // Editors must never wait for the lifecycle lock while holding it.
            check(inventory->list(admin).size() == 1, "callback can read inventory");
            return true;
        };
        VmService service(fixture.context); inventory = &service;
        auto value = config("before"), changed = value; changed["name"] = "after";
        if (operation == 2) {
            Json::Value nic; nic["network_id"] = "removed";
            value["networks"].append(nic);
        }
        const auto id = service.create(admin, value);
        auto original = service.runtime(admin, id);
        auto start = std::async(std::launch::async, [&] { return original->start(); });
        started.wait();
        auto mutation = std::async(std::launch::async, [&] {
            try {
                if (operation == 2) service.drop_network("removed");
                else if (operation == 1) service.remove(admin, id);
                else service.modify(admin, changed);
                return false;
            } catch (const ServiceError& error) { return error.code() == ErrorCode::conflict; }
        });
        const bool ready = mutation.wait_for(500ms) == std::future_status::ready;
        proceed.release();
        const bool admitted = start.get(), rejected = mutation.get();
        check(ready && rejected && !admitted, "lifecycle/edit race rejects promptly without lock inversion");
        check(service.runtime(admin, id) == original && service.get(admin, id)["name"] == "before", "racing edit leaves inventory unchanged");
        if (operation == 2) service.drop_network("removed");
        else if (operation == 1) service.remove(admin, id);
        else service.modify(admin, changed);
        check(!original->start() && fixture.starts == 1, "successful retry retires precisely the previous runtime");
    }
}
void modify_races() { lifecycle_races(0); }
void remove_races() { lifecycle_races(1); }
void network_removal_races() { lifecycle_races(2); }
void configured_start_binding() {
    Fixture fixture;
    Fd directory(open(fixture.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    VmService inventory(fixture.context);
    const auto initial = config("configured-start");
    const auto id = initial["id"].asString();
    error(ErrorCode::unauthenticated, [&] { inventory.start_configured({}, id, initial); });
    error(ErrorCode::permission_denied, [&] { inventory.start_configured({"reader", true, true, false}, id, initial); });
    error(ErrorCode::unavailable, [&] { inventory.start_configured(admin, id, initial); });
    VmConfigService store(directory.get(), getuid(), {}, [&](const Json::Value& doc) { return inventory.prepare_config(doc); });
    auto view = store.snapshot(admin);
    auto document = view->document;
    document["vms"].append(initial);
    view = store.replace(admin, view->revision, document);
    const auto definition = view->document["vms"][0];
    Json::Value overrides; overrides["pseudo_unprotected"] = true;
    check(!inventory.start_configured(admin, id, definition, overrides) && fixture.starts == 1, "matching definition reaches protected start admission");
    check(store.snapshot(admin) == view && inventory.runtime(admin, id)->config() == definition, "session start failure writes neither persistent view nor runtime baseline");
    Json::Value invalid; invalid["name"] = "overwrite";
    error(ErrorCode::invalid_argument, [&] { inventory.start_configured(admin, id, definition, invalid); });
    auto changed = view->document;
    changed["vms"][0]["name"] = "edited";
    view = store.replace(admin, view->revision, changed);
    error(ErrorCode::conflict, [&] { inventory.start_configured(admin, id, definition, overrides); });
    check(fixture.starts == 1, "stale definition rejected before runtime admission");
    const auto updated = view->document["vms"][0];
    changed = view->document; changed["extension"] = "unrelated";
    view = store.replace(admin, view->revision, changed);
    check(!inventory.start_configured(admin, id, updated) && fixture.starts == 2, "unrelated root edit does not change target definition");
    changed = view->document; changed["vms"].clear();
    store.replace(admin, view->revision, changed);
    error(ErrorCode::not_found, [&] { inventory.start_configured(admin, id, updated); });
}
void configured_start_adapter() {
    Fixture fixture;
    Fd directory(open(fixture.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    VmService inventory(fixture.context);
    TaskService tasks;
    VmConfigService store(directory.get(), getuid(), {}, [&](const Json::Value& doc) { return inventory.prepare_config(doc); }, &tasks);
    SystemService system([] { return true; }, [] { return "test"; }, "test", tasks.epoch());
    RequestDispatcher dispatcher(system, tasks, nullptr, nullptr, nullptr, nullptr, &inventory);
    ClientSession session; session.caller.authorized = true;
    check(!dispatcher.execute(session, "capabilities", {}).isMember("vm_config_start"), "legacy runtime does not advertise configured start");
    dispatcher.set_vm_config(&store);
    check(dispatcher.execute(session, "capabilities", {})["vm_config_start"] == "revisioned-session-v1" && dispatcher.background("vm_start_configured"), "configured start is an advertised worker operation");
    auto view = store.snapshot(admin);
    auto doc = view->document; auto vm = config("adapter-start"); vm["backend"] = "qemu";
    doc["vms"].append(vm); view = store.replace(admin, view->revision, doc);
    Json::Value request; request["revision"] = view->revision; request["vm_id"] = vm["id"];
    request["clear_logs_before_start"] = true;
    auto* log = inventory.runtime(admin, vm["id"].asString())->log("stdio");
    log->append("retain rejected start history\n");
    auto denied = [&](const CallContext& caller, const Json::Value& input, const char* code) {
        const auto result = dispatcher.execute_background(caller, "vm_start_configured", input);
        check(result["success"] == false && result["error"]["code"] == code, "configured start structured error");
    };
    denied({}, request, "UNAUTHENTICATED"); denied(owner, request, "PERMISSION_DENIED");
    auto bad = request; bad["revision"] = "stale"; denied(admin, bad, "CONFLICT");
    bad = request; bad["config"] = vm; denied(admin, bad, "INVALID_ARGUMENT");
    bad = request; bad["overrides"]["pseudo_unprotected"] = true; denied(admin, bad, "INVALID_ARGUMENT");
    bad = request; bad["vm_id"] = random_id(true); denied(admin, bad, "NOT_FOUND");
    bad = request; bad["clear_logs_before_start"] = "true"; denied(admin, bad, "INVALID_ARGUMENT");
    bad = request; bad["boot_entry"] = std::string((64u << 10) + 1, 'x'); denied(admin, bad, "INVALID_ARGUMENT");
    check(fixture.starts == 0, "invalid requests have no runtime side effects");
    denied(admin, request, "CONFLICT");
    check(fixture.starts == 1 && store.snapshot(admin) == view, "matching revision reaches admission without rewriting configuration");
    check(log->contents().find("retain rejected start history") != std::string::npos, "validation and shutdown refusal preserve logs even when clearing requested");
    bad = request; bad["boot_entry"] = std::string(64u << 10, 'x'); denied(admin, bad, "CONFLICT");
    check(fixture.starts == 2, "bounded long boot key reaches runtime admission");
    check(dispatcher.execute(session, "vm_start_configured", request)["error"]["code"] == "CONFLICT", "direct dispatch shares configured start implementation");
}
void persistent_inventory_commit() {
    Fixture fixture;
    Fd directory(open(fixture.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    VmService inventory(fixture.context);
    std::string failure;
    VmConfigService store(directory.get(), getuid(), [&](const char* stage) {
        if (failure == stage) throw std::runtime_error("injected IO failure");
    }, [&](const Json::Value& document) { return inventory.prepare_config(document); });
    auto initial = store.snapshot(admin);
    auto document = initial->document;
    document["vms"].append(config("first"));
    document["vms"].append(config("second"));
    auto saved = store.replace(admin, initial->revision, document);
    const auto id = saved->document["vms"][0]["id"].asString();
    const auto other = saved->document["vms"][1]["id"].asString();
    auto original = inventory.runtime(admin, id), unchanged = inventory.runtime(admin, other);
    error(ErrorCode::conflict, [&] { inventory.create(admin, config("bypass")); });
    error(ErrorCode::conflict, [&] { inventory.modify(admin, saved->document["vms"][0]); });
    error(ErrorCode::conflict, [&] { inventory.remove(admin, id); });
    error(ErrorCode::conflict, [&] { inventory.drop_network("network"); });
    original->log("stdio")->append("history before commit\n");
    auto changed = saved->document;
    changed["vms"][0]["name"] = "changed";
    failure = "before_install";
    error(ErrorCode::io_error, [&] { store.replace(admin, saved->revision, changed); });
    check(store.snapshot(admin) == saved && inventory.runtime(admin, id) == original, "pre-install failure retains snapshot and runtime");
    check(!original->start() && fixture.starts == 1, "aborted persistence releases lifecycle lease");
    failure = "installed";
    error(ErrorCode::commit_uncertain, [&] { store.replace(admin, saved->revision, changed); });
    auto uncertain = store.snapshot(admin);
    config::JsonFile disk(directory.get(), "vms.json", getuid());
    check(disk.load()->value == uncertain->document, "installed failure snapshot agrees with actual file");
    auto replacement = inventory.runtime(admin, id);
    check(uncertain->durability_uncertain && replacement != original && inventory.get(admin, id)["name"] == "changed", "installed failure publishes runtime and uncertain snapshot together");
    check(inventory.runtime(admin, other) == unchanged && replacement->log("stdio")->contents() == original->log("stdio")->contents(), "unchanged runtime and persistent console survive commit");
    check(!original->start() && fixture.starts == 1, "installed failure retires stale reference");
    failure.clear();
    auto confirmed = store.replace(admin, uncertain->revision, uncertain->document);
    check(!confirmed->durability_uncertain && inventory.runtime(admin, id) == replacement, "durability retry does not replace runtime");
    auto removed = confirmed->document;
    removed["vms"].removeIndex(0, nullptr);
    store.replace(admin, confirmed->revision, removed);
    check(!inventory.exists(admin, id) && !replacement->start() && fixture.starts == 1, "persistent deletion retires removed runtime");
    VmService reopened(fixture.context);
    VmConfigService restart(directory.get(), getuid(), {}, [&](const Json::Value& value) { return reopened.prepare_config(value); });
    check(reopened.list(admin).size() == 1 && reopened.exists(admin, other), "startup loads committed inventory through participant");
}
void persistent_busy_and_unchanged() {
    Fixture fixture;
    Fd directory(open(fixture.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    Gate entered, proceed;
    fixture.context.shutting_down = [&] { entered.release(); proceed.wait(); return true; };
    VmService inventory(fixture.context);
    unsigned writes = 0;
    VmConfigService store(directory.get(), getuid(), [&](const char* stage) {
        if (std::string_view(stage) == "before_write") ++writes;
    }, [&](const Json::Value& value) { return inventory.prepare_config(value); });
    auto empty = store.snapshot(admin);
    auto document = empty->document; document["vms"].append(config("busy"));
    auto saved = store.replace(admin, empty->revision, document);
    const auto id = saved->document["vms"][0]["id"].asString();
    auto runtime = inventory.runtime(admin, id);
    Json::Value live_nics(Json::arrayValue);
    Json::Value live_nic; live_nic["tap_name"] = "runtime-only"; live_nics.append(live_nic);
    runtime->set_networks(live_nics);
    auto starting = std::async(std::launch::async, [&] { return runtime->start(); });
    entered.wait();
    // Release the lifecycle gate even when an assertion throws.
    struct Release { Gate& gate; ~Release() { gate.release(); } } release{proceed};
    auto changed = saved->document; changed["vms"][0]["name"] = "edited";
    error(ErrorCode::conflict, [&] { store.replace(admin, saved->revision, changed); });
    auto removed = saved->document; removed["vms"].clear();
    error(ErrorCode::conflict, [&] { store.replace(admin, saved->revision, removed); });
    check(writes == 1 && store.snapshot(admin) == saved, "busy edits fail before disk write");
    auto added = saved->document; added["vms"].append(config("new"));
    auto current = store.replace(admin, saved->revision, added);
    check(inventory.runtime(admin, id) == runtime && current->document["vms"].size() == 2, "adding another VM preserves a busy unchanged runtime");
    check(runtime->config()["networks"] == live_nics, "live-only fields do not turn an unchanged VM into an edit");
    proceed.release();
    check(!starting.get(), "fixture never starts VMM");
}
void persistent_publication_and_writers() {
    Fixture fixture;
    Fd directory(open(fixture.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    VmService inventory(fixture.context);
    Gate saving, proceed;
    bool block = false;
    VmConfigService store(directory.get(), getuid(), [&](const char* stage) {
        if (block && std::string_view(stage) == "before_install") { saving.release(); proceed.wait(); }
    }, [&](const Json::Value& value) { return inventory.prepare_config(value); });
    auto empty = store.snapshot(admin);
    auto document = empty->document; document["vms"].append(config("original"));
    auto original = store.replace(admin, empty->revision, document);
    const auto id = original->document["vms"][0]["id"].asString();
    auto old = inventory.runtime(admin, id);
    auto changed = original->document; changed["vms"][0]["name"] = "committed";
    block = true;
    auto writer = std::async(std::launch::async, [&] { return store.replace(admin, original->revision, changed); });
    saving.wait();
    struct Release { Gate& gate; ~Release() { gate.release(); } } release{proceed};
    check(store.snapshot(admin) == original, "old immutable snapshot remains readable during persistence");
    // This request has already retained the old object, before publication.
    auto stale_start = std::async(std::launch::async, [&] { return old->start(); });
    proceed.release();
    auto committed = writer.get();
    check(!stale_start.get() && fixture.starts == 0, "waiting stale start is rejected after publication");
    check(inventory.get(admin, id)["name"] == "committed", "inventory follows published snapshot");
    block = false;
    std::atomic<int> success{0}, conflicts{0}, failures{0};
    std::vector<std::thread> writers;
    for (int i = 0; i < 12; ++i) writers.emplace_back([&, i] {
        auto candidate = committed->document;
        candidate["vms"][0]["name"] = "winner-" + std::to_string(i);
        try { store.replace(admin, committed->revision, candidate); ++success; }
        catch (const ServiceError& error) { if (error.code() == ErrorCode::conflict) ++conflicts; else ++failures; }
        catch (...) { ++failures; }
    });
    for (auto& thread : writers) thread.join();
    check(success == 1 && conflicts == 11 && failures == 0, "one persistent inventory writer wins revision race");
    check(inventory.get(admin, id) == store.snapshot(admin)->document["vms"][0], "winning runtime agrees with winning configuration");
}
void revisioned_batch_adapter() {
    Fixture fixture;
    Fd directory(open(fixture.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    VmService inventory(fixture.context);
    std::string fail;
    TaskService tasks;
    VmConfigService store(directory.get(), getuid(), [&](const char* stage) {
        if (fail == stage) throw std::runtime_error("injected failure");
    }, [&](const Json::Value& value) { return inventory.prepare_config(value); }, &tasks);
    SystemService system([] { return true; }, [] { return "test"; }, "test", tasks.epoch());
    RequestDispatcher dispatcher(system, tasks);
    ClientSession session; session.caller.authorized = true;
    check(!dispatcher.execute(session, "capabilities", {}).isMember("vm_config_updates"), "unattached dispatcher never advertises configuration ownership");
    dispatcher.set_vm_config(&store);
    auto caps = dispatcher.execute(session, "capabilities", {});
    check(caps["vm_config_updates"] == "revisioned-batch-v1" && caps["service_api_minor"] == 15 && caps["vm_config_snapshot"] == "base64-json-chunks-v1" && caps["vm_config_upload"] == "revisioned-chunks-v1", "attached dispatcher advertises batch, snapshot and upload APIs");
    check(dispatcher.background("vm_config_apply") && !dispatcher.background("vm_config_status"), "disk operations use bounded worker dispatch");
    auto status = dispatcher.execute(session, "vm_config_status", {});
    auto snapshot = dispatcher.execute(session, "vm_config_snapshot", {});
    check(snapshot["success"].asBool() && snapshot["items"][0]["revision"] == status["revision"], "snapshot adapter returns revisioned metadata");
    Json::Value cursor; cursor["epoch"] = snapshot["epoch"]; cursor["cursor"] = snapshot["cursor"];
    check(dispatcher.execute(session, "resource_subscribe", cursor)["success"].asBool(), "resource stream starts at snapshot cursor");
    ClientSession legacy; legacy.caller.authorized = true;
    check(dispatcher.execute(legacy, "task_subscribe", cursor)["success"].asBool(), "old task subscription starts at same cursor");
    Json::Value request, create;
    request["revision"] = status["revision"];
    create["op"] = "create"; create["config"] = config("adapter"); request["operations"].append(create);
    auto assert_error = [](const Json::Value& result, const char* code) {
        check(result["success"] == false && result["error"]["code"] == code, "structured configuration adapter error");
    };
    assert_error(dispatcher.execute_background({}, "vm_config_apply", {}), "UNAUTHENTICATED");
    assert_error(dispatcher.execute_background(owner, "vm_config_apply", {}), "PERMISSION_DENIED");
    auto created = dispatcher.execute_background(admin, "vm_config_apply", request);
    auto resource_event = dispatcher.events(session), old_event = dispatcher.events(legacy);
    check(resource_event && (*resource_event)["events"].size() == 1 && (*resource_event)["events"][0]["kind"] == "vm.config.invalidated", "resource stream carries VM invalidation");
    check(old_event && (*old_event)["events"].empty(), "old task stream filters VM configuration events");
    Json::Value release; release["snapshot_id"] = snapshot["snapshot_id"];
    check(dispatcher.execute(session, "resource_snapshot_release", release)["success"].asBool(), "generic resource release accepts VM document snapshot");
    check(created["success"] == true && created["count"].asUInt() == 1 && created["revision"] != status["revision"], "batch adapter commits and returns compact metadata");
    auto id = create["config"]["id"].asString();
    auto original = inventory.runtime(admin, id);
    assert_error(dispatcher.execute_background(admin, "vm_config_apply", request), "CONFLICT");
    request["revision"] = created["revision"];
    request["operations"][0]["op"] = "replace"; request["operations"][0]["config"]["name"] = "changed";
    fail = "before_install";
    assert_error(dispatcher.execute_background(admin, "vm_config_apply", request), "IO_ERROR");
    check(inventory.runtime(admin, id) == original && store.snapshot(admin)->revision == created["revision"].asString(), "adapter failure preserves runtime and revision");
    fail = "installed";
    assert_error(dispatcher.execute_background(admin, "vm_config_apply", request), "COMMIT_UNCERTAIN");
    auto uncertain = dispatcher.execute(session, "vm_config_status", {});
    check(uncertain["durability_uncertain"] == true && uncertain["revision"] != created["revision"] && inventory.get(admin, id)["name"] == "changed", "adapter exposes installed-but-uncertain revision for reread");
    fail.clear();
    Json::Value begin; begin["revision"] = uncertain["revision"]; begin["bytes"] = 10;
    auto started = dispatcher.execute_background(admin, "vm_config_upload_begin", begin);
    check(started["success"].asBool() && dispatcher.background("vm_config_upload_commit"), "upload is advertised and uses workers");
    Json::Value chunk; chunk["upload_id"] = started["upload_id"]; chunk["offset"] = 0;
    chunk["data"] = "eyJ2bXMiOltdfQ=="; // {"vms":[]}
    check(dispatcher.execute_background(admin, "vm_config_upload_append", chunk)["received"].asUInt64() == 10, "strict base64 upload adapter accepts JSON bytes");
    auto malformed = chunk; malformed["data"] = "Zh==";
    assert_error(dispatcher.execute_background(admin, "vm_config_upload_append", malformed), "INVALID_ARGUMENT");
    check(dispatcher.execute_background(admin, "vm_config_upload_commit", chunk)["success"].asBool() && !inventory.exists(admin, id), "uploaded complete document atomically deletes runtime inventory");
    assert_error(dispatcher.execute_background(admin, "vm_config_upload_commit", chunk), "NOT_FOUND");
    assert_error(dispatcher.execute_background({}, "vm_config_upload_begin", {}), "UNAUTHENTICATED");
    dispatcher.disconnected(session); dispatcher.disconnected(legacy);
    session.caller.authorized = false;
    assert_error(dispatcher.execute(session, "vm_config_status", {}), "UNAUTHENTICATED");
}
}
int main() {
    return run({{"disk_option_path_encoding", disk_option_path_encoding},
        {"qemu_disk_readonly_arguments", qemu_disk_readonly_arguments},
        {"replace_delete_stale_references", replacement_and_failure},
        {"configuration_gate_domains_recovery", configuration_gate_domains_and_recovery},
        {"configuration_gate_drains_nested", configuration_gate_drains_nested_admissions},
        {"coordinated_network_delete", coordinated_network_delete},
        {"coordinated_disk_references", coordinated_disk_references},
        {"coordinated_disk_structure", coordinated_disk_structure},
        {"coordinated_vm_disk_commit", coordinated_vm_disk_commit},
        {"coordinated_vm_disk_rejections", coordinated_vm_disk_rejections},
        {"coordinated_vm_disk_failure_recovery", coordinated_vm_disk_failure_recovery},
        {"coordinated_vm_disk_restart", coordinated_vm_disk_restart},
        {"coordinated_vm_disk_readonly", coordinated_vm_disk_readonly},
        {"coordinated_vm_disk_uploads", coordinated_vm_disk_uploads},
        {"coordinated_vm_disk_adapter", coordinated_vm_disk_adapter},
        {"coordinated_historical_disk_references", coordinated_historical_disk_references},
        {"coordinated_disk_start_guard", coordinated_disk_start_guard},
        {"runtime_disk_lease_admission", runtime_disk_lease_admission},
        {"sixteen_coordinated_disk_reference_races", coordinated_disk_reference_races},
        {"coordinated_disk_redo_before_load", coordinated_disk_redo_before_load},
        {"coordinated_vm_network_references", coordinated_vm_network_references},
        {"coordinated_historical_network_references", coordinated_historical_network_references},
        {"sixteen_coordinated_reference_delete_races", coordinated_reference_delete_races},
        {"coordinated_delete_rejections", coordinated_delete_rejections},
        {"coordinated_delete_failure_recovery", coordinated_delete_failure_recovery},
        {"coordinated_delete_restart", coordinated_delete_restart},
        {"coordinated_gate_validation_delete_race", coordinated_constructor_and_delete_race},
        {"network_removal_atomic_inventory", network_removal_is_atomic},
        {"conditional_network_config_adapter", conditional_network_adapter},
        {"coordinated_delete_upload_adapter", coordinated_delete_adapter},
        {"coordinated_delete_auto_stop", coordinated_delete_auto_stop},
        {"coordinated_delete_drains_network_operation", coordinated_delete_drains_network_operation},
        {"network_cleanup_during_recovery", network_cleanup_during_recovery},
        {"sixteen_network_removal_start_races", network_removal_races},
        {"session_overrides_failed_admission", session_overrides_and_failed_admission},
        {"invalid_session_overrides", invalid_session_overrides},
        {"session_overrides_worker_abort", session_overrides_worker_abort},
        {"lease_abort_move_lifetime", lease_abort_and_lifetime},
        {"sixteen_modify_start_races", modify_races}, {"sixteen_delete_start_races", remove_races},
        {"persistent_inventory_commit", persistent_inventory_commit},
        {"configured_start_binding", configured_start_binding},
        {"configured_start_adapter", configured_start_adapter},
        {"persistent_busy_and_unchanged", persistent_busy_and_unchanged},
        {"persistent_publication_and_writers", persistent_publication_and_writers},
        {"revisioned_batch_adapter", revisioned_batch_adapter}});
}
