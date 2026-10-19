// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/disk_operations.h"
#include "common/wire.h"
#include <atomic>
#include <chrono>
#include <iostream>
#include <source_location>
#include <thread>
using namespace droidvm;
using namespace std::chrono_literals;
void require(bool value, const std::source_location& at = std::source_location::current()) {
    if (!value) throw std::runtime_error("Disk task contract failed at line " + std::to_string(at.line()));
}
template<class Work> void rejected(ErrorCode code, Work work) {
    try { work(); } catch (const ServiceError& error) { require(error.code() == code); return; }
    throw std::runtime_error("Expected operation rejection");
}
TaskView finished(TaskService& tasks, const CallContext& caller, const std::string& id) {
    const auto deadline = TaskService::Clock::now() + 5s;
    do {
        const auto task = tasks.get(caller, {tasks.epoch(), id});
        if (task_terminal(task.state)) return task;
        std::this_thread::sleep_for(1ms);
    } while (TaskService::Clock::now() < deadline);
    throw std::runtime_error("Task did not finish");
}
int main() {
    try {
        const CallContext caller{"browser", true, true, true};
        TaskLimits limits; limits.background_workers = 1;
        TaskService tasks(limits);
        std::atomic<int> calls = 0;
        const auto operations = web::disk_operations(tasks, [&](const CallContext&, const Json::Value& request, TaskControl& control) {
            ++calls;
            if (request["disk_revision"] == "stale") throw ServiceError(ErrorCode::conflict, "stale registry");
            if (!control.enter_commit()) return TaskCompletion::cancelled();
            return TaskCompletion::success(request);
        });
        auto input = wire::parse(R"({"requestId":"resize","revision":"disks","vmRevision":"vms","operation":{"action":"resize","diskId":"disk","size":"9223372036854775807","shrink":false,"cpus":[0,1023]}})");
        rejected(ErrorCode::unauthenticated, [&] { operations.submit({}, input); });
        rejected(ErrorCode::permission_denied, [&] { operations.submit({"viewer", true, true, false}, input); });
        const auto accepted = operations.submit(caller, input);
        const auto id = accepted["id"].asString();
        require(operations.submit(caller, input)["id"] == id);
        const auto outcome = finished(tasks, caller, id);
        require(outcome.state == TaskState::succeeded && calls == 1);
        require(outcome.result["size"].asInt64() == INT64_MAX && outcome.result["vm_revision"] == "vms");
        require(operations.find(caller, "resize")["id"] == id);
        require(operations.find({"other", true, true, true}, "resize").isNull());
        input["operation"]["size"] = "1";
        rejected(ErrorCode::conflict, [&] { operations.submit(caller, input); });
        input["requestId"] = "invalid";
        for (const auto* size : {"9223372036854775808", "01", "-1", "1.5"}) {
            input["operation"]["size"] = size;
            rejected(ErrorCode::invalid_argument, [&] { operations.submit(caller, input); });
        }
        input["operation"]["size"] = "1"; input["operation"]["path"] = "/unregistered";
        rejected(ErrorCode::invalid_argument, [&] { operations.submit(caller, input); });
        input["operation"].removeMember("path"); input["operation"]["cpus"].append(0);
        rejected(ErrorCode::invalid_argument, [&] { operations.submit(caller, input); });
        int index = 0;
        for (const auto* action : {"create", "clone", "convert", "flatten", "commit", "reset", "delete"}) {
            Json::Value operation; operation["action"] = action;
            if (std::string(action) != "create") operation["diskId"] = "disk";
            if (std::string(action) == "create" || std::string(action) == "clone") {
                operation["folder"] = "/" + std::string(2000, 'a'); operation["name"] = "new.qcow2";
            }
            if (std::string(action) == "create" || std::string(action) == "convert") operation["format"] = "qcow2";
            if (std::string(action) == "create") { operation["backingId"] = "disk"; operation["attach"] = "readonly"; }
            if (std::string(action) == "delete") operation["deleteFiles"] = true;
            input["operation"] = operation; input["requestId"] = "action-" + std::to_string(index++);
            input["operation"]["createFolder"] = std::string(action) == "clone";
            if (std::string(action) != "clone") {
                rejected(ErrorCode::invalid_argument, [&] { operations.submit(caller, input); });
                input["operation"].removeMember("createFolder");
            } else {
                input["operation"]["createFolder"] = "true";
                rejected(ErrorCode::invalid_argument, [&] { operations.submit(caller, input); });
                input["operation"]["createFolder"] = true;
            }
            const auto task = operations.submit(caller, input);
            const auto result = finished(tasks, caller, task["id"].asString());
            require(result.state == TaskState::succeeded && result.result["action"] == action);
            if (std::string(action) == "delete") require(result.result["delete_files"] == true);
            if (std::string(action) == "create") require(result.result["backing_id"] == "disk");
            if (std::string(action) == "clone") require(result.result["create_folder"] == true && !result.result.isMember("createFolder"));
        }
        input["revision"] = "stale"; input["requestId"] = "stale";
        const auto stale = operations.submit(caller, input);
        require(finished(tasks, caller, stale["id"].asString()).error == ErrorCode::conflict);
        require(operations.submit(caller, input)["id"] == stale["id"]);
        // Long signatures are retained under the same byte quota, not free metadata.
        TaskLimits small; small.retained_bytes = 4096 + 4 + 1024;
        TaskService bounded(small);
        TaskSpec spec{"disk", "disk:x", 4}; spec.request_id = "large"; spec.request_signature.assign(1025, 'x');
        rejected(ErrorCode::resource_exhausted, [&] { bounded.submit(caller, spec, [](TaskControl&) { return TaskCompletion::success(); }); });
        spec.request_signature.assign(TaskSpec::max_signature_bytes + 1, 'x');
        rejected(ErrorCode::invalid_argument, [&] { bounded.submit(caller, spec, [](TaskControl&) { return TaskCompletion::success(); }); });
        std::atomic<size_t> pending = 2;
        const auto recovery = web::disk_recovery(tasks, [&](const CallContext&) { return pending.load(); },
            [&](const CallContext&) { Json::Value result; result["pending"] = Json::UInt64(--pending); result["private"] = "omit"; return result; });
        require(recovery.status(caller)["pendingRecords"].asUInt64() == 2);
        const auto recover_input = wire::parse(R"({"requestId":"recover-1"})");
        const auto recovery_task = recovery.tasks.submit(caller, recover_input);
        require(finished(tasks, caller, recovery_task["id"].asString()).state == TaskState::succeeded);
        require(recovery.tasks.find(caller, "recover-1")["pendingRecords"].asUInt64() == 1);
        require(!recovery.tasks.find(caller, "recover-1").isMember("private"));
        require(recovery.tasks.submit(caller, recover_input)["id"] == recovery_task["id"] && pending == 1);
        require(recovery.tasks.find(CallContext{"another", true, true, true}, "recover-1").isNull());
        rejected(ErrorCode::permission_denied, [&] { recovery.status(CallContext{"browser", true, true, false}); });
        rejected(ErrorCode::permission_denied, [&] { recovery.tasks.submit(CallContext{"browser", true, false, true}, recover_input); });
        rejected(ErrorCode::conflict, [&] { operations.find(caller, "recover-1"); });
        rejected(ErrorCode::invalid_argument, [&] { recovery.tasks.submit(caller, wire::parse(R"({"requestId":"recover-2","extra":true})")); });
        std::cout << "Disk operations and recovery: scoped deduplication, result projection, permission and exact parameter checks passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
