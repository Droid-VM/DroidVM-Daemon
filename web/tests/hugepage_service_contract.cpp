// SPDX-License-Identifier: GPL-3.0-or-later
#include "services/hugepage.h"
#include <chrono>
#include <map>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <iostream>
#include <future>
#include <set>

namespace {
using namespace droidvm;
void check(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
CallContext admin() { return {"hugepage-contract", true, true, true}; }
TaskLimits limits() { TaskLimits value; value.background_workers = 1; value.max_result_bytes = 256u << 10; return value; }
struct Fixture {
    std::mutex mutex;
    std::map<std::string, std::string> files{
        {"/fixture/params", ""}, {"/fixture/module/module.prop", "id=hugepages"},
        {"/fixture/module/settings.prop", "pool_want=100\npool_target=100\npool_want_with_cma=300\nunknown_option=keep\n"},
        {"/fixture/params/pool_want", "100"}, {"/fixture/params/pool_want_with_cma", "300"},
        {"/fixture/params/refill_stat", "pool_total=100 pool_avail=100 served=0 acquire_active=0"},
        {"/fixture/params/acquire", "0"}, {"/fixture/params/manual_refill", "0"}};
    bool fail_publish = false, fail_acquire = false, unreadable_settings = false;
    std::set<std::string> read_only;
    std::string failed_knob;
    unsigned target_writes = 0, acquire_writes = 0, legacy_writes = 0;
    TaskService tasks{limits()};
    vm::PoolReservations pool{[this](int64_t value, int64_t) {
        std::lock_guard lock(mutex); files["/fixture/params/pool_want"] = std::to_string(value); ++target_writes; return true;
    }};
    std::unique_ptr<HugepageService> service;
    Fixture() {
        pool.initialize_manual(100);
        HugepageOptions io; io.parameters = "/fixture/params"; io.module_directory = "/fixture/module";
        io.exists = [this](const std::string& path) { std::lock_guard lock(mutex); return files.contains(path); };
        io.writable = [this](const std::string& path) { std::lock_guard lock(mutex); return files.contains(path) && !read_only.contains(path); };
        io.identity = [](const std::string&) { return "fixture-module-1"; };
        io.read = [this](const std::string& path, size_t) -> std::optional<std::string> {
            std::lock_guard lock(mutex);
            if (path == "/fixture/module/settings.prop" && unreadable_settings) return {};
            auto entry = files.find(path); if (entry == files.end()) return {}; return entry->second;
        };
        io.write = [this](const std::string& path, const std::string& value) {
            std::lock_guard lock(mutex);
            if (path == "/proc/sys/vm/drop_caches") return false;
            if (path == failed_knob) return false;
            if (path == "/fixture/params/pool_want") ++target_writes;
            if (path == "/fixture/params/acquire") { ++acquire_writes; if (fail_acquire) return false; }
            if (path == "/fixture/params/manual_refill") ++legacy_writes;
            files[path] = value; return true;
        };
        io.publish = [this](const std::string& path, const std::string& value) {
            std::lock_guard lock(mutex);
            if (fail_publish) throw ServiceError(ErrorCode::io_error, "Injected publication failure");
            files[path] = value;
        };
        io.marker = [this](const std::string& path, bool present) { std::lock_guard lock(mutex); if (present) files[path] = ""; else files.erase(path); };
        io.run = [](const std::vector<std::string>&) -> HugepageCommandResult { throw std::runtime_error("Unexpected module process"); };
        service = std::make_unique<HugepageService>(tasks, pool, std::move(io));
    }
    ~Fixture() { tasks.shutdown(); }
    Json::Value request(const std::string& id, const Json::Value& operation) {
        Json::Value value; value["requestId"] = id; value["expected"]["fingerprint"] = service->snapshot(admin())["fingerprint"]; value["operation"] = operation; return value;
    }
    TaskView finish(const TaskView& initial) {
        for (unsigned i = 0; i < 2000; ++i) {
            auto current = tasks.get(admin(), initial.ref);
            if (task_terminal(current.state)) return current;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        throw std::runtime_error("Hugepage task did not terminate");
    }
    TaskView run(const Json::Value& request) { return finish(service->start(admin(), request)); }
};
Json::Value target(int64_t pages, bool persist = true) {
    Json::Value value; value["kind"] = "targets"; value["poolPages"] = std::to_string(pages); value["cmaPages"] = Json::Value(); value["persist"] = persist; return value;
}
void consumer_floor_and_manual_baseline() {
    std::vector<int64_t> writes;
    vm::PoolReservations pool([&](int64_t target, int64_t baseline) { check(baseline == 100, "Manual baseline lost"); writes.push_back(target); return true; });
    pool.initialize_manual(100);
    check(pool.admit("manual-vm", 1, 150, false), "Manual consumer rejected");
    check(writes.empty(), "Manual consumer resized pool");
    check(pool.admit("auto-vm", 2, 70, true), "Automatic consumer rejected");
    check(writes.back() == 220, "Automatic target excluded manual consumer");
    pool.release("auto-vm", 1); check(pool.contains("auto-vm"), "Old generation released current VM");
    pool.release("auto-vm", 2); check(writes.back() == 150, "Release undercut active manual consumer");
    pool.release("manual-vm", 1); check(writes.back() == 100, "Last release discarded manual baseline");
    auto lease = pool.begin_control(); check(!pool.admit("racing-vm", 3, 1, false), "Admission bypassed control lease"); lease.reset();
    pool.initialize_manual(std::nullopt); check(!pool.admit("unknown-baseline", 4, 1, true), "Unknown baseline silently treated as zero");
}
void operations() {
    Fixture fixture;
    auto request = fixture.request("target-dedup", target(200));
    auto result = fixture.run(request);
    check(result.state == TaskState::succeeded, "Target operation failed");
    check(result.result["saved"].asBool() && result.result["applied"].asBool() && !result.result["uncertain"].asBool(), "Target receipt incorrect");
    check(fixture.files["/fixture/params/pool_want_with_cma"] == "300", "Null CMA mutated live target");
    check(fixture.files["/fixture/module/settings.prop"].find("unknown_option=keep") != std::string::npos, "Settings update discarded unknown key");
    request["operation"]["poolPages"] = 200;
    auto repeated = fixture.run(request);
    check(repeated.ref.id == result.ref.id && fixture.target_writes == 1, "Lost response was not deduplicated after numeric normalization");
    check(fixture.service->status(admin(), "target-dedup").ref.id == result.ref.id, "Status lost original operation identity");
    request["requestId"] = "stale-expectation";
    auto stale = fixture.run(request);
    check(stale.state == TaskState::failed && stale.error == ErrorCode::conflict && fixture.target_writes == 1, "Stale expectation performed writes");
    check(fixture.pool.admit("manual-vm", 1, 250, false), "Manual consumer registration failed");
    auto floor = fixture.run(fixture.request("floor", target(200)));
    check(floor.state == TaskState::failed && floor.error == ErrorCode::conflict && fixture.target_writes == 1, "Manual VM floor was ignored");
    fixture.pool.release("manual-vm", 1);
    fixture.fail_publish = true;
    auto partial = fixture.run(fixture.request("partial-persist", target(250)));
    check(partial.state == TaskState::failed && partial.result["applied"].asBool() && partial.result["uncertain"].asBool() && !partial.result["saved"].asBool(), "Partial persistence was falsely confirmed");
    check(fixture.target_writes == 2 && fixture.pool.snapshot().manual_pages == 250, "Partial operation replayed or lost applied baseline");
}
void no_unknown_fallback_or_settings_loss() {
    Fixture fixture;
    fixture.fail_acquire = true;
    Json::Value acquire; acquire["kind"] = "acquire"; acquire["mode"] = 3;
    auto result = fixture.run(fixture.request("acquire-failure", acquire));
    check(result.state == TaskState::failed && result.result["uncertain"].asBool(), "Acquire failure concealed uncertainty");
    check(fixture.acquire_writes == 1 && fixture.legacy_writes == 0, "Unknown acquire failure attempted fallback");
    fixture.unreadable_settings = true;
    bool rejected = false;
    try { fixture.service->snapshot(admin()); } catch (const ServiceError& error) { rejected = error.code() == ErrorCode::io_error; }
    check(rejected && fixture.target_writes == 0, "Unreadable existing settings treated as empty");
}
void cma_deficit_triggers_requested_acquire() {
    Fixture fixture;
    fixture.files["/fixture/params/refill_stat"] = "pool_total=100 pool_avail=100 served=0 pool_cma=50 acquire_active=0";
    auto operation = target(100);
    operation["cmaPages"] = "300";
    operation["acquireMode"] = 3;
    const auto result = fixture.run(fixture.request("cma-deficit", operation));
    check(result.state == TaskState::succeeded && fixture.acquire_writes == 1 && fixture.files["/fixture/params/acquire"] == "3",
        "Full ordinary pool concealed CMA deficit");
}
void queued_cancellation_has_a_definite_receipt() {
    Fixture fixture;
    std::promise<void> entered, unblock;
    auto entered_future = entered.get_future();
    auto gate = unblock.get_future().share();
    TaskSpec blocker; blocker.kind = "fixture-blocker"; blocker.background = true;
    fixture.tasks.submit(admin(), blocker, [&entered, gate](TaskControl&) {
        entered.set_value(); gate.wait(); return TaskCompletion::success();
    });
    if (entered_future.wait_for(std::chrono::seconds(2)) != std::future_status::ready) {
        unblock.set_value(); throw std::runtime_error("Fixture worker did not start");
    }
    TaskView cancelled;
    try {
        const auto task = fixture.service->start(admin(), fixture.request("cancel-queued", target(200)));
        fixture.tasks.cancel(admin(), task.ref);
        cancelled = fixture.service->status(admin(), "cancel-queued");
    } catch (...) { unblock.set_value(); throw; }
    unblock.set_value();
    check(cancelled.state == TaskState::cancelled && cancelled.result["uncertain"] == false &&
        cancelled.result["applied"] == false && fixture.target_writes == 0,
        "Queued cancellation was treated as a lost operation receipt");
}
void observed_capabilities_and_advanced_effects() {
    Fixture fixture;
    auto before = fixture.service->snapshot(admin());
    check(before["features"]["acquire"] == true && before["features"]["stopAcquire"] == true &&
        before["features"]["reconcile"] == false && before["hasLegacySettings"] == false, "Snapshot fabricated module capabilities");
    fixture.files["/fixture/params/reconcile"] = "0";
    auto after = fixture.service->snapshot(admin());
    check(after["features"]["reconcile"] == true && after["fingerprint"] != before["fingerprint"], "Capability changes did not invalidate controls");
    fixture.files["/fixture/params/refill_stat"] = "pool_total=100 pool_avail=75 served=25 acquire_active=0";
    check(fixture.service->snapshot(admin())["fingerprint"] == after["fingerprint"], "Usage counters invalidated control expectation");

    fixture.files["/fixture/params/boot_acquire"] = "0";
    fixture.files["/fixture/params/cma_reservoir_floor_mb"] = "16";
    fixture.read_only.insert("/fixture/params/cma_reservoir_floor_mb");
    check(fixture.pool.admit("active", 1, 50, false), "Consumer admission failed");
    Json::Value operation; operation["kind"] = "advanced"; operation["key"] = "boot_acquire"; operation["value"] = "2";
    auto boot = fixture.run(fixture.request("boot-next-load", operation));
    check(boot.state == TaskState::succeeded && boot.result["saved"] == true && boot.result["applied"] == false &&
        boot.result["implementation"] == "next-load" && fixture.files["/fixture/params/boot_acquire"] == "0",
        "Boot-only advanced setting falsely applied to running module");
    auto observed = fixture.service->snapshot(admin());
    check(observed["advancedLiveWritable"]["boot_acquire"] == false && observed["advancedLiveWritable"]["cma_reservoir_floor_mb"] == false,
        "Readonly or boot-only setting advertised as live");
    operation["key"] = "cma_reservoir_floor_mb"; operation["value"] = "32";
    auto readonly = fixture.run(fixture.request("readonly-floor", operation));
    check(readonly.state == TaskState::succeeded && readonly.result["saved"] == true && readonly.result["applied"] == false &&
        readonly.result["implementation"] == "next-load" && fixture.files["/fixture/params/cma_reservoir_floor_mb"] == "16",
        "Readonly floor failed instead of saving next-load configuration");
    fixture.read_only.clear();
    fixture.failed_knob = "/fixture/params/cma_reservoir_floor_mb";
    operation["value"] = "64";
    auto partial = fixture.run(fixture.request("advanced-partial", operation));
    check(partial.state == TaskState::failed && partial.result["saved"] == true && partial.result["uncertain"] == true &&
        fixture.files["/fixture/module/settings.prop"].find("cma_reservoir_floor_mb=64") != std::string::npos,
        "Advanced partial save/write failure lost its receipt");
    auto zero = fixture.run(fixture.request("zero-active", target(0)));
    check(zero.state == TaskState::failed && zero.error == ErrorCode::conflict && fixture.target_writes == 0,
        "Zero target bypassed active consumer floor");
    operation = Json::Value(Json::objectValue); operation["kind"] = "runtime"; operation["enabled"] = false;
    auto disabled = fixture.run(fixture.request("disable-active", operation));
    check(disabled.state == TaskState::failed && disabled.error == ErrorCode::conflict && fixture.acquire_writes == 0,
        "Runtime disable acted before checking active consumers");
}
void cma_persistence_preflight_and_legacy_migration() {
    Fixture fixture;
    fixture.files["/fixture/module/settings.prop"] += "pool_want=500\ncma_probe_result=0\ncma_movable_lever=hook\n";
    fixture.files["/fixture/module/crash"] = "";
    fixture.files["/fixture/params/moveable_to_cma_gfp_cma_hook"] = "1";
    auto observed = fixture.service->snapshot(admin());
    check(observed["hasLegacySettings"] == true && observed["hasCrash"] == true && observed["features"]["gfpHook"] == true,
        "Legacy settings or crash acknowledgement were hidden");
    Json::Value operation; operation["kind"] = "cma-target"; operation["pages"] = "300"; operation["persist"] = true;
    auto rejected = fixture.run(fixture.request("bad-saved-cma", operation));
    check(rejected.state == TaskState::failed && rejected.result["applied"] == false && rejected.result["saved"] == false &&
        fixture.acquire_writes == 0, "Incompatible saved CMA target performed partial live work");
    operation = Json::Value(Json::objectValue); operation["kind"] = "migrate-settings";
    auto migrated = fixture.run(fixture.request("migrate-legacy", operation));
    check(migrated.state == TaskState::succeeded && migrated.result["snapshot"]["hasLegacySettings"] == false &&
        migrated.result["snapshot"]["settings"]["unknown_option"] == "keep", "Legacy migration lost unrelated settings");
    operation["kind"] = "dismiss-crash";
    auto dismissed = fixture.run(fixture.request("dismiss-crash", operation));
    check(dismissed.state == TaskState::succeeded && dismissed.result["snapshot"]["hasCrash"] == false && dismissed.result["saved"] == true,
        "Crash acknowledgement did not update authoritative snapshot");
}
}
int main() {
    try { consumer_floor_and_manual_baseline(); operations(); no_unknown_fallback_or_settings_loss(); cma_deficit_triggers_requested_acquire(); queued_cancellation_has_a_definite_receipt(); observed_capabilities_and_advanced_effects(); cma_persistence_preflight_and_legacy_migration(); }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    return 0;
}
