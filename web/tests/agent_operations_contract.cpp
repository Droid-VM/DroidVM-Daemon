// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/agent_operations.h"
#include "web/task_adapter.h"
#include "common/wire.h"
#include <atomic>
#include <chrono>
#include <future>
#include <iostream>
#include <source_location>
#include <thread>

using namespace droidvm;
using namespace std::chrono_literals;
namespace {
constexpr const char* disk_id = "12345678-1234-4234-8234-123456789abc";
void require(bool value, const std::source_location& at = std::source_location::current()) {
    if (!value) throw std::runtime_error("Agent operations contract failed at line " + std::to_string(at.line()));
}
template<class Work> void rejected(ErrorCode code, Work work) {
    try { work(); } catch (const ServiceError& error) { require(error.code() == code); return; }
    throw std::runtime_error("Expected Agent request rejection");
}
TaskView finished(TaskService& tasks, const CallContext& caller, const std::string& id) {
    const auto deadline = TaskService::Clock::now() + 5s;
    do {
        const auto task = tasks.get(caller, {tasks.epoch(), id});
        if (task_terminal(task.state)) return task;
        std::this_thread::sleep_for(1ms);
    } while (TaskService::Clock::now() < deadline);
    throw std::runtime_error("Agent task did not finish");
}
agent::NativeResult native_result(agent::Outcome outcome = agent::Outcome::guest_succeeded) {
    using namespace agent;
    NativeResult result;
    result.managed_vm_id = "private-managed-vm-id";
    auto& run = result.execution;
    run.protocol.phase = Phase::finished;
    run.protocol.outcome = outcome;
    run.protocol.guest_result = outcome;
    run.protocol.guest_cleanup = GuestCleanup::succeeded;
    run.protocol.actions.push_back({ActionKind::password, false, outcome == Outcome::guest_skipped
        ? ActionState::skipped : outcome == Outcome::guest_succeeded ? ActionState::succeeded : ActionState::failed, {}});
    run.cleanup = {true, true, true};
    run.status = RunnerStatus::guest_reported;
    run.committed = true;
    run.durability_confirmed = true;
    return result;
}
Json::Value input(std::string request_id) {
    auto result = wire::parse(R"({"requestId":"request","revision":"disks","vmRevision":"vms","operation":{"action":"chpasswd","diskId":"disk","password":"Safe123!","normalUsers":true}})");
    result["requestId"] = std::move(request_id);
    result["operation"]["diskId"] = disk_id;
    return result;
}

void operations_and_projection() {
    const CallContext caller{"browser", true, true, true};
    TaskLimits limits; limits.background_workers = 1;
    TaskService tasks(limits);
    std::atomic<int> calls{0};
    auto operations = web::agent_operations(tasks, [&](const CallContext& actual, agent::Request request,
            const agent::Confirmation& confirmed, TaskControl& control, bool rescue) {
        ++calls;
        require(!rescue && actual.principal == caller.principal && request.password() == "Safe123!" && request.normal_users());
        require(confirmed.disk_revision == "disks" && confirmed.vm_revision == "vms");
        require(control.enter_commit());
        return native_result();
    });
    auto request = input("once");
    rejected(ErrorCode::unauthenticated, [&] { operations.submit({}, request); });
    rejected(ErrorCode::permission_denied, [&] { operations.submit({"viewer", true, true, false}, request); });
    const auto accepted = operations.submit(caller, request);
    const auto id = accepted["id"].asString();
    rejected(ErrorCode::conflict, [&] { operations.submit(caller, request); });
    request["operation"]["password"] = "Different!";
    rejected(ErrorCode::conflict, [&] { operations.submit(caller, request); });
    auto done = finished(tasks, caller, id);
    require(done.state == TaskState::succeeded && calls == 1 && done.resource == std::string("disk:") + disk_id);
    auto found = operations.find(caller, "once");
    require(found["agentResult"]["outcome"] == "succeeded" && found["agentResult"]["durabilityConfirmed"].asBool());
    const auto encoded = wire::stringify(found);
    require(encoded.find("Safe123") == std::string::npos && encoded.find("private-managed") == std::string::npos);
    require(operations.find({"other", true, true, true}, "once").isNull());
    request = input("extra"); request["unexpected"] = true;
    rejected(ErrorCode::invalid_argument, [&] { operations.submit(caller, request); });
    request = input("bad-action"); request["operation"]["script"] = "arbitrary shell";
    rejected(ErrorCode::invalid_argument, [&] { operations.submit(caller, request); });

    auto contaminated = done.result;
    contaminated["password"] = "private";
    contaminated["cleanup"]["path"] = "/private";
    contaminated["actions"][0]["output"] = "private";
    const auto projected = web::project_agent_result(contaminated);
    require(!projected.isNull() && wire::stringify(projected).find("private") == std::string::npos);
    contaminated["guestCode"] = "/private/host/path";
    require(web::project_agent_result(contaminated).isNull());
    contaminated = done.result; contaminated["cleanup"]["stopped"] = false;
    require(web::project_agent_result(contaminated).isNull());
    contaminated = done.result; contaminated["durabilityConfirmed"] = false;
    require(web::project_agent_result(contaminated).isNull());
}

void non_success_receipts_and_errors() {
    const CallContext caller{"browser", true, true, true};
    TaskLimits limits; limits.background_workers = 1;
    TaskService tasks(limits);
    for (auto outcome : {agent::Outcome::guest_skipped, agent::Outcome::guest_partial, agent::Outcome::guest_failed,
            agent::Outcome::uncertain}) {
        auto operations = web::agent_operations(tasks, [outcome](const CallContext&, agent::Request,
                const agent::Confirmation&, TaskControl& control, bool) {
            require(control.enter_commit());
            auto result = native_result(outcome);
            if (outcome == agent::Outcome::uncertain) {
                result.execution.status = agent::RunnerStatus::cleanup_failed;
                result.execution.cleanup = {false, false, false};
                result.execution.durability_confirmed = false;
                result.execution.protocol.guest_result = agent::Outcome::guest_succeeded;
            }
            return result;
        });
        const auto request_id = "outcome-" + std::to_string(static_cast<int>(outcome));
        const auto accepted = operations.submit(caller, input(request_id));
        const auto task = finished(tasks, caller, accepted["id"].asString());
        require(task.state == TaskState::failed && task.result_available && task.result.isObject());
        const auto view = operations.find(caller, request_id);
        require(view["resultAvailable"].asBool() && view["agentResult"].isObject());
        require(!task_summary(task).isMember("result"));
        if (outcome == agent::Outcome::uncertain)
            require(view["agentResult"]["recoveryRequired"].asBool() && view["agentResult"]["outcome"] == "uncertain");
    }
    auto throws = web::agent_operations(tasks, [](const CallContext&, agent::Request, const agent::Confirmation&, TaskControl&, bool)
            -> agent::NativeResult { throw ServiceError(ErrorCode::conflict, "/private/path password Safe123!"); });
    const auto accepted = throws.submit(caller, input("throws"));
    const auto task = finished(tasks, caller, accepted["id"].asString());
    require(task.error == ErrorCode::conflict && task.message == "Agent operation failed" && task.result.isNull());
}

void rescue_handoff_receipts() {
    const CallContext caller{"browser", true, true, true};
    TaskLimits limits; limits.background_workers = 1;
    TaskService tasks(limits);
    for (int scenario = 0; scenario != 4; ++scenario) {
        const auto operations = web::agent_operations(tasks,
            [scenario](const CallContext&, agent::Request, const agent::Confirmation&, TaskControl& control, bool rescue) {
                require(rescue == (scenario != 3) && control.enter_commit());
                auto result = native_result(agent::Outcome::guest_failed);
                result.execution.handed_off = true;
                result.execution.protocol.shell_ready = scenario != 2;
                result.execution.protocol.guest_code = "PASSWD_FAILED";
                result.execution.cleanup = {false, false, false};
                result.execution.durability_confirmed = false;
                result.rescue_session_id = scenario == 1 ? "/private/path" : std::string(64, 'a');
                return result;
            });
        auto request = input("rescue-" + std::to_string(scenario));
        request["rescue"] = scenario != 3;
        const auto accepted = operations.submit(caller, request);
        const auto task = finished(tasks, caller, accepted["id"].asString());
        if (scenario != 0) {
            require(task.state == TaskState::failed && task.error == ErrorCode::commit_uncertain && task.result.isNull());
            continue;
        }
        require(task.state == TaskState::succeeded);
        auto view = web::task_view(task)["agentResult"];
        require(view["outcome"] == "rescue_ready" && view["rescueSessionId"] == std::string(64, 'a')
            && view["guestOutcome"] == "failed" && view["guestCode"] == "PASSWD_FAILED"
            && view["guestCleanup"] == "succeeded" && view["actions"][0]["state"] == "failed"
            && !view["durabilityConfirmed"].asBool() && !view["recoveryRequired"].asBool());
        view["cleanup"]["stopped"] = true;
        require(web::project_agent_result(view).isNull());
        view = task.result; view["rescueSessionId"] = "invalid";
        require(web::project_agent_result(view).isNull());
        view = task.result; view["outcome"] = "failed";
        require(web::project_agent_result(view).isNull());
    }
}

void expired_and_cancelled_queue() {
    const CallContext caller{"browser", true, true, true};
    TaskLimits limits; limits.background_workers = 1;
    TaskService tasks(limits);
    std::promise<void> release, entered;
    auto released = release.get_future().share();
    auto entry = entered.get_future();
    auto block = tasks.submit(caller, {"block", "test", 1024, false, true}, [&](TaskControl&) {
        entered.set_value(); released.wait(); return TaskCompletion::success();
    });
    struct Release { std::promise<void>& value; ~Release() { try { value.set_value(); } catch (...) {} } } guard{release};
    require(entry.wait_for(5s) == std::future_status::ready);
    std::atomic<long long> milliseconds{0};
    std::atomic<int> calls{0};
    const auto operations = web::agent_operations(tasks,
        [&](const CallContext&, agent::Request, const agent::Confirmation&, TaskControl&, bool) { ++calls; return native_result(); },
        [&] { return TaskService::Clock::time_point(std::chrono::milliseconds(milliseconds.load())); });
    const auto expired = operations.submit(caller, input("expired"));
    const auto cancelled = operations.submit(caller, input("cancelled-queue"));
    tasks.cancel(caller, {tasks.epoch(), cancelled["id"].asString()});
    milliseconds = 60001;
    release.set_value();
    require(finished(tasks, caller, expired["id"].asString()).error == ErrorCode::unavailable);
    require(finished(tasks, caller, cancelled["id"].asString()).state == TaskState::cancelled && calls == 0);
    (void)finished(tasks, caller, block.id);
}

void cancelled_operation_receipt() {
    const CallContext caller{"browser", true, true, true};
    TaskLimits limits; limits.background_workers = 1;
    TaskService tasks(limits);
    std::promise<void> entered, release;
    auto entry = entered.get_future();
    auto released = release.get_future().share();
    struct Release { std::promise<void>& value; ~Release() { try { value.set_value(); } catch (...) {} } } guard{release};
    const auto operations = web::agent_operations(tasks, [&](const CallContext&, agent::Request,
            const agent::Confirmation&, TaskControl& control, bool) {
        entered.set_value(); released.wait();
        require(control.cancellation_requested());
        auto result = native_result();
        auto& run = result.execution;
        run.status = agent::RunnerStatus::cancelled;
        run.reason = agent::RunnerReason::cancelled;
        run.committed = run.durability_confirmed = false;
        run.cleanup = {true, true, false};
        run.protocol.outcome = agent::Outcome::aborted;
        run.protocol.guest_result = agent::Outcome::pending;
        run.protocol.guest_cleanup = agent::GuestCleanup::not_required;
        run.protocol.actions[0].state = agent::ActionState::pending;
        return result;
    });
    const auto accepted = operations.submit(caller, input("running-cancel"));
    require(entry.wait_for(5s) == std::future_status::ready);
    tasks.cancel(caller, {tasks.epoch(), accepted["id"].asString()});
    release.set_value();
    require(finished(tasks, caller, accepted["id"].asString()).state == TaskState::cancelled);
    const auto view = operations.find(caller, "running-cancel");
    require(view["resultAvailable"].asBool() && view["agentResult"]["outcome"] == "cancelled"
        && !view["agentResult"]["recoveryRequired"].asBool());
}

void bounded_failed_cancelled_results() {
    const CallContext caller{"browser", true, true, true};
    TaskService tasks;
    Json::Value receipt; receipt["safe"] = "receipt"; receipt["secret"] = "not-for-public-projection";
    const auto failed = tasks.submit(caller, {"unrelated", "test", 1024}, [receipt](TaskControl&) {
        return TaskCompletion::failure(ErrorCode::io_error, "Fixed failure", receipt);
    });
    const auto done = finished(tasks, caller, failed.id);
    require(done.state == TaskState::failed && done.result == receipt && done.result_available);
    require(!web::task_view(done).isMember("result") && !web::task_view(done).isMember("agentResult"));
    require(wire::stringify(task_summary(done)).find("not-for-public") == std::string::npos);
    const auto oversized = tasks.submit(caller, {"unrelated", "test", 4}, [receipt](TaskControl&) {
        return TaskCompletion::failure(ErrorCode::io_error, "Fixed failure", receipt);
    });
    const auto overflow = finished(tasks, caller, oversized.id);
    require(overflow.error == ErrorCode::resource_exhausted && overflow.result.isNull() && !overflow.result_available);

    std::promise<void> release, entered;
    auto released = release.get_future().share();
    auto entry = entered.get_future();
    const auto cancelled = tasks.submit(caller, {"unrelated", "test", 1024}, [&](TaskControl&) {
        entered.set_value(); released.wait(); return TaskCompletion::cancelled(receipt);
    });
    struct Release { std::promise<void>& value; ~Release() { try { value.set_value(); } catch (...) {} } } guard{release};
    require(entry.wait_for(5s) == std::future_status::ready);
    tasks.cancel(caller, cancelled);
    release.set_value();
    const auto cancelled_done = finished(tasks, caller, cancelled.id);
    require(cancelled_done.state == TaskState::cancelled && cancelled_done.result == receipt && cancelled_done.result_available);

    const auto invalid = tasks.submit(caller, {"unrelated", "test", 1024}, [receipt](TaskControl&) {
        return TaskCompletion::cancelled(receipt); // No cancellation was requested.
    });
    const auto invalid_done = finished(tasks, caller, invalid.id);
    require(invalid_done.state == TaskState::failed && invalid_done.result.isNull() && !invalid_done.result_available);
}

void recovery() {
    const CallContext caller{"browser", true, true, true};
    TaskLimits limits; limits.background_workers = 1;
    TaskService tasks(limits);
    std::atomic<int> calls{0};
    const auto recovery = web::agent_recovery(tasks, [](const CallContext&) { return size_t{2}; },
        [&](const CallContext&) { ++calls; Json::Value result; result["pending"] = Json::UInt64(1); result["path"] = "/private"; return result; });
    require(recovery.status(caller)["pendingRecords"].asUInt64() == 2);
    Json::Value request; request["requestId"] = "recover";
    const auto accepted = recovery.tasks.submit(caller, request);
    require(finished(tasks, caller, accepted["id"].asString()).state == TaskState::succeeded);
    require(recovery.tasks.submit(caller, request)["id"] == accepted["id"] && calls == 1);
    const auto view = recovery.tasks.find(caller, "recover");
    require(view["pendingRecords"].asUInt64() == 1 && view["resource"] == "agent" && !view.isMember("path"));
    require(recovery.tasks.find({"another", true, true, true}, "recover").isNull());
    rejected(ErrorCode::permission_denied, [&] { recovery.status({"viewer", true, true, false}); });
}
}

int main() {
    try {
        operations_and_projection();
        non_success_receipts_and_errors();
        rescue_handoff_receipts();
        expired_and_cancelled_queue();
        cancelled_operation_receipt();
        bounded_failed_cancelled_results();
        recovery();
        std::cout << "Agent operations contract passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
