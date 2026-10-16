// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "common/identity.h"
#include "services/vm.h"
#include "transport/dispatcher.h"
#include <atomic>
#include <dirent.h>
#include <future>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace droidvm;
using namespace droidvm::test;
namespace {
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
    return run({{"replace_delete_stale_references", replacement_and_failure},
        {"network_removal_atomic_inventory", network_removal_is_atomic},
        {"conditional_network_config_adapter", conditional_network_adapter},
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
