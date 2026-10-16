// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "common/identity.h"
#include "services/vm.h"
#include <atomic>
#include <dirent.h>
#include <future>
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
}
int main() {
    return run({{"replace_delete_stale_references", replacement_and_failure},
        {"lease_abort_move_lifetime", lease_abort_and_lifetime},
        {"sixteen_modify_start_races", modify_races}, {"sixteen_delete_start_races", remove_races}});
}
