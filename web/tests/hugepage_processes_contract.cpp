// SPDX-License-Identifier: GPL-3.0-or-later
#include "services/hugepage_processes.h"
#include <algorithm>
#include <chrono>
#include <future>
#include <iostream>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <thread>

namespace {
using namespace droidvm;
void check(bool good, const char* message) { if (!good) throw std::runtime_error(message); }
CallContext admin() { return {"hugepage-process-contract", true, true, true}; }
TaskLimits limits() { TaskLimits value; value.background_workers = 1; return value; }
struct Process {
    std::string birth = "100", state = "D", smaps = "AnonHugePages: 2048 kB\nShmemPmdMapped: 2048 kB\n", stack = "[<0>] blocked_function+0x1/0x2\n";
    bool alive = true, denied = false, smaps_denied = false;
};
struct Fixture {
    std::mutex mutex;
    std::map<int, std::shared_ptr<Process>> processes;
    std::map<std::string, std::string> module;
    std::map<int, std::string> owner_births;
    std::vector<HugepageVmProcess> vms;
    std::set<int> read_pids;
    bool provider_fails = false, pidfd_fails = false, replace_on_open = false;
    unsigned vm_signals = 0, direct_signals = 0, stack_reads = 0;
    int last_signal = 0;
    TaskService tasks{limits()};
    std::unique_ptr<HugepageProcessService> service;
    struct Handle : HugepageProcessHandle {
        Fixture& fixture; std::shared_ptr<Process> process;
        Handle(Fixture& fixture, std::shared_ptr<Process> process) : fixture(fixture), process(std::move(process)) {}
        bool alive() override { std::lock_guard lock(fixture.mutex); return process->alive; }
        bool signal(int number) override {
            std::lock_guard lock(fixture.mutex); if (!process->alive) return false;
            ++fixture.direct_signals; fixture.last_signal = number; return true;
        }
    };
    Fixture() {
        processes[42] = std::make_shared<Process>();
        processes[77] = std::make_shared<Process>(); processes[77]->birth = "90"; processes[77]->state = "S";
        vms.push_back({"vm-one", "VM one", 42, "100", "runtime-one", 7});
        HugepageProcessOptions options; options.parameters = "/fixture/params"; options.proc_directory = "/fixture/proc"; options.daemon_pid = 999;
        options.wall_ms = [] { return uint64_t{1234}; };
        options.running_vms = [this] { std::lock_guard lock(mutex); if (provider_fails) throw std::runtime_error("Provider failed"); return vms; };
        options.owner_start_ticks = [this](int pid) -> std::optional<std::string> {
            std::lock_guard lock(mutex); auto value = owner_births.find(pid); return value == owner_births.end() ? std::nullopt : std::optional<std::string>(value->second);
        };
        options.read = [this](const std::string& path, size_t) -> HugepageProcessRead {
            std::lock_guard lock(mutex);
            if (path.starts_with("/fixture/params/")) {
                auto found = module.find(path.substr(16));
                return found == module.end() ? HugepageProcessRead{} : HugepageProcessRead{HugepageProcessReadState::present, found->second, false};
            }
            check(path.starts_with("/fixture/proc/"), "Unexpected host file read");
            auto slash = path.find('/', 14); int pid = std::stoi(path.substr(14, slash - 14)); auto kind = path.substr(slash + 1);
            read_pids.insert(pid);
            auto found = processes.find(pid); if (found == processes.end() || !found->second->alive) return {};
            auto& process = *found->second;
            if (process.denied) return {HugepageProcessReadState::denied, {}, false};
            if (kind == "stat") {
                std::string value = std::to_string(pid) + " (worker ) with spaces) " + process.state;
                for (int field = 4; field < 22; ++field) value += " 0";
                value += " " + process.birth + " 0\n";
                return {HugepageProcessReadState::present, value, false};
            }
            if (kind == "smaps_rollup") return process.smaps_denied ? HugepageProcessRead{HugepageProcessReadState::denied, {}, false} : HugepageProcessRead{HugepageProcessReadState::present, process.smaps, false};
            if (kind == "stack") { ++stack_reads; return {HugepageProcessReadState::present, process.stack, false}; }
            throw std::runtime_error("Unexpected process file read");
        };
        options.open_process = [this](int pid) -> std::unique_ptr<HugepageProcessHandle> {
            std::lock_guard lock(mutex);
            if (pidfd_fails) throw ServiceError(ErrorCode::unavailable, "No pidfd");
            if (replace_on_open && pid == 42) {
                replace_on_open = false; processes[42]->alive = false;
                processes[42] = std::make_shared<Process>(); processes[42]->birth = "200";
            }
            auto found = processes.find(pid); if (found == processes.end() || !found->second->alive) return {};
            return std::make_unique<Handle>(*this, found->second);
        };
        options.signal_vm = [this](const HugepageVmProcess& observed, int number) {
            std::lock_guard lock(mutex);
            const auto found = std::find_if(vms.begin(), vms.end(), [&](const auto& vm) { return vm.id == observed.id; });
            if (found == vms.end() || found->runtime_revision != observed.runtime_revision || found->runtime_instance != observed.runtime_instance ||
                found->pid != observed.pid || found->start_ticks != observed.start_ticks)
                throw ServiceError(ErrorCode::conflict, "VM identity changed");
            ++vm_signals; last_signal = number; return true;
        };
        service = std::make_unique<HugepageProcessService>(tasks, std::move(options));
    }
    ~Fixture() { tasks.shutdown(); }
    Json::Value expected() { return service->snapshot(admin(), "scan")["entries"][0]["expected"]; }
    Json::Value request(const std::string& id, const Json::Value& expected, const char* signal = "term") {
        Json::Value value; value["requestId"] = id; value["expected"] = expected; value["signal"] = signal; return value;
    }
    TaskView finish(const TaskView& initial) {
        for (unsigned i = 0; i < 2000; ++i) {
            auto task = tasks.get(admin(), initial.ref);
            if (task_terminal(task.state)) return task;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        throw std::runtime_error("Process task did not finish");
    }
    TaskView run(const Json::Value& request) { return finish(service->start(admin(), request)); }
};
void exact_scan_scope_and_unknowns() {
    Fixture fixture;
    const auto snapshot = fixture.service->snapshot(admin(), "auto");
    check(snapshot["source"] == "scan" && snapshot["fallbackReason"] == "ko-unavailable" && snapshot["coverage"] == "running-vms", "Auto fallback lost its source");
    check(snapshot["entries"].size() == 1 && snapshot["entries"][0]["pages"] == "2" && snapshot["entries"][0]["bytes"] == "4194304", "THP bytes were rounded or miscounted");
    check(!fixture.read_pids.contains(77), "SCAN enumerated unrelated host processes");
    check(!fixture.service->snapshot(admin(), "ko")["available"].asBool(), "Explicit KO silently fell back");
    fixture.processes[42]->smaps_denied = true;
    auto unknown = fixture.service->snapshot(admin(), "scan");
    check(unknown["entries"][0]["bytes"].isNull() && unknown["totals"]["bytes"].isNull() && unknown["partial"] == true, "Unreadable THP data became zero");
    fixture.processes[42]->smaps_denied = false; fixture.processes[42]->smaps = "AnonHugePages: 1024 kB\nShmemPmdMapped: 0 kB\n";
    auto fraction = fixture.service->snapshot(admin(), "scan");
    check(fraction["entries"][0]["bytes"] == "1048576" && fraction["entries"][0]["pages"].isNull(), "Partial hugepage count was silently truncated");
    fixture.provider_fails = true;
    auto failed = fixture.service->snapshot(admin(), "scan");
    check(failed["available"] == false && failed["totals"]["bytes"].isNull(), "Failed VM inventory was presented as an empty successful scan");
}
void legacy_ko_is_not_a_birth_identity() {
    Fixture fixture;
    fixture.module["vm_owners"] = "pid=42 served=99 comm=old qemu\npid=77 served=20 comm=stale owner\n";
    fixture.module["served_summary"] = "owner pid=42 pages=4\nowner pid=77 pages=3\n";
    const auto snapshot = fixture.service->snapshot(admin(), "ko");
    check(snapshot["entries"].size() == 2 && snapshot["entries"][0]["pages"] == "4", "KO used cumulative served instead of current summary");
    const auto& vm = snapshot["entries"][0]; const auto& stale = snapshot["entries"][1];
    check(vm["identityStatus"] == "verified" && vm["attributionVerified"] == false && vm["expected"]["source"] == "scan" && vm["canSignal"] == true,
        "Current VM membership was confused with legacy KO attribution");
    check(stale["expected"].isNull() && stale["alive"].isNull() && stale["identityStatus"] == "unverified" && stale["canSignal"] == false,
        "Current proc birth was incorrectly assigned to an old KO PID");
    auto request = fixture.request("ko-current-vm", vm["expected"], "kill");
    auto signalled = fixture.run(request);
    check(signalled.state == TaskState::succeeded && fixture.vm_signals == 1 && fixture.direct_signals == 0 && fixture.last_signal == 9, "Owned VM bypassed its lifecycle signal callback");
    fixture.owner_births[77] = "90";
    const auto trusted = fixture.service->snapshot(admin(), "ko")["entries"][1];
    check(trusted["attributionVerified"] == true && trusted["expected"]["source"] == "ko", "Authoritative KO birth was ignored");
    auto direct = fixture.run(fixture.request("ko-authoritative", trusted["expected"]));
    check(direct.state == TaskState::succeeded && fixture.direct_signals == 1 && fixture.last_signal == 15, "Verified non-VM owner did not use its identity handle");
}
void signals_recheck_identity_membership_and_deduplicate() {
    Fixture fixture;
    auto original = fixture.expected();
    auto request = fixture.request("term-once", original);
    auto first = fixture.run(request), repeated = fixture.run(request);
    check(first.state == TaskState::succeeded && first.result["sent"] == true && repeated.ref.id == first.ref.id && fixture.vm_signals == 1 && fixture.last_signal == 15,
        "Lost signal response caused a repeat or changed TERM semantics");
    fixture.vms[0].runtime_revision = 8;
    auto stale = fixture.run(fixture.request("stale-generation", original));
    check(stale.state == TaskState::failed && stale.error == ErrorCode::conflict && stale.result["sent"] == false && stale.result["uncertain"] == false && stale.result["expected"] == original,
        "Stale VM generation signalled or lost definite no-effect receipt");
    auto current = fixture.expected(); fixture.replace_on_open = true;
    auto reused = fixture.run(fixture.request("pid-reused", current));
    check(reused.state == TaskState::failed && reused.result["sent"] == false && fixture.vm_signals == 1 && fixture.direct_signals == 0, "PID reuse after observation signalled another process");
    Fixture removed;
    auto member = removed.expected(); removed.vms.clear();
    auto rejected = removed.run(removed.request("removed-member", member));
    check(rejected.state == TaskState::failed && rejected.error == ErrorCode::conflict && removed.vm_signals == 0, "Caller-crafted identity bypassed current source membership");
    Fixture unsupported;
    auto identity = unsupported.expected(); unsupported.pidfd_fails = true;
    auto no_handle = unsupported.run(unsupported.request("no-pidfd", identity));
    check(no_handle.state == TaskState::failed && no_handle.error == ErrorCode::unavailable && unsupported.vm_signals == 0 && unsupported.direct_signals == 0,
        "Unavailable pidfd fell back to unsafe process signalling");
}
void bounded_stack_and_definite_queued_cancellation() {
    Fixture fixture;
    auto expected = fixture.expected(); fixture.processes[42]->stack = std::string(16383, 'x') + "\xe4\xb8\xad";
    auto stack = fixture.service->stack(admin(), expected);
    check(stack["available"] == true && stack["truncated"] == true && stack["text"].asString().size() <= 16384 && stack["text"].asString().back() == '?', "Stack output exceeded its bound or split UTF-8");
    fixture.processes[42]->state = "S";
    bool rejected = false;
    try { fixture.service->stack(admin(), expected); } catch (const ServiceError& error) { rejected = error.code() == ErrorCode::conflict; }
    check(rejected && fixture.stack_reads == 1, "Stack was read for a process no longer in D state");
    std::promise<void> entered, unblock; auto started = entered.get_future(); auto gate = unblock.get_future().share();
    TaskSpec blocker; blocker.kind = "process-fixture-blocker"; blocker.background = true;
    fixture.tasks.submit(admin(), blocker, [&entered, gate](TaskControl&) { entered.set_value(); gate.wait(); return TaskCompletion::success(); });
    if (started.wait_for(std::chrono::seconds(2)) != std::future_status::ready) { unblock.set_value(); throw std::runtime_error("Fixture queue did not start"); }
    TaskView cancelled;
    try {
        auto task = fixture.service->start(admin(), fixture.request("cancel-queued", expected));
        fixture.tasks.cancel(admin(), task.ref); cancelled = fixture.service->status(admin(), "cancel-queued");
    } catch (...) { unblock.set_value(); throw; }
    unblock.set_value();
    check(cancelled.state == TaskState::cancelled && cancelled.result["sent"] == false && cancelled.result["uncertain"] == false &&
        cancelled.result["expected"].isNull() && fixture.vm_signals == 0, "Queued cancellation became an unknown signal outcome");
}
}
int main() {
    try { exact_scan_scope_and_unknowns(); legacy_ko_is_not_a_birth_identity(); signals_recheck_identity_membership_and_deduplicate(); bounded_stack_and_definite_queued_cancellation(); }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    return 0;
}
