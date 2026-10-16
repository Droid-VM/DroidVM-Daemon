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
void lifecycle_races(bool removing) {
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
        const auto id = service.create(admin, value);
        auto original = service.runtime(admin, id);
        auto start = std::async(std::launch::async, [&] { return original->start(); });
        started.wait();
        auto mutation = std::async(std::launch::async, [&] {
            try {
                if (removing) service.remove(admin, id);
                else service.modify(admin, changed);
                return false;
            } catch (const ServiceError& error) { return error.code() == ErrorCode::conflict; }
        });
        const bool ready = mutation.wait_for(500ms) == std::future_status::ready;
        proceed.release();
        const bool admitted = start.get(), rejected = mutation.get();
        check(ready && rejected && !admitted, "lifecycle/edit race rejects promptly without lock inversion");
        check(service.runtime(admin, id) == original && service.get(admin, id)["name"] == "before", "racing edit leaves inventory unchanged");
        if (removing) service.remove(admin, id);
        else service.modify(admin, changed);
        check(!original->start() && fixture.starts == 1, "successful retry retires precisely the previous runtime");
    }
}
void modify_races() { lifecycle_races(false); }
void remove_races() { lifecycle_races(true); }
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
    check(caps["vm_config_updates"] == "revisioned-batch-v1" && caps["service_api_minor"] == 14 && caps["vm_config_snapshot"] == "base64-json-chunks-v1", "attached dispatcher advertises batch and snapshot APIs");
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
    dispatcher.disconnected(session); dispatcher.disconnected(legacy);
    session.caller.authorized = false;
    assert_error(dispatcher.execute(session, "vm_config_status", {}), "UNAUTHENTICATED");
}
}
int main() {
    return run({{"replace_delete_stale_references", replacement_and_failure},
        {"lease_abort_move_lifetime", lease_abort_and_lifetime},
        {"sixteen_modify_start_races", modify_races}, {"sixteen_delete_start_races", remove_races},
        {"persistent_inventory_commit", persistent_inventory_commit},
        {"persistent_busy_and_unchanged", persistent_busy_and_unchanged},
        {"persistent_publication_and_writers", persistent_publication_and_writers},
        {"revisioned_batch_adapter", revisioned_batch_adapter}});
}
