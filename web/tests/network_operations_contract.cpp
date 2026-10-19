// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/network_operations.h"
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
void require(bool value, const std::source_location& at = std::source_location::current()) {
    if (!value) throw std::runtime_error("Network task contract failed at line " + std::to_string(at.line()));
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
}
int main() {
    try {
        const CallContext caller{"browser", true, true, true};
        TaskLimits limits; limits.background_workers = 1;
        TaskService tasks(limits);
        std::atomic<int> calls = 0;
        std::promise<void> entered, proceed;
        auto proceed_future = proceed.get_future().share();
        auto operations = web::network_operations(tasks, [&](const CallContext&, const web::NetworkOperation& operation) {
            ++calls;
            if (operation.configuration_revision == "stale") throw ServiceError(ErrorCode::conflict, "stale configuration");
            if (operation.configuration_revision == "blocking") { entered.set_value(); proceed_future.wait(); }
            require(operation.network_id == "network" && operation.generation == UINT64_MAX && operation.state == NetworkState::stopped);
        });
        auto input = wire::parse(R"({"requestId":"start","networkId":"network","action":"start","expected":{"generation":"18446744073709551615","state":"STOPPED","configurationRevision":"current"}})");
        rejected(ErrorCode::unauthenticated, [&] { operations.submit({}, input); });
        rejected(ErrorCode::permission_denied, [&] { operations.submit({"viewer", true, true, false}, input); });
        rejected(ErrorCode::permission_denied, [&] { operations.submit({"viewer", true, false, true}, input); });
        const auto task = operations.submit(caller, input);
        const auto outcome = finished(tasks, caller, task["id"].asString());
        require(outcome.state == TaskState::succeeded && outcome.kind == "network_lifecycle" && outcome.resource == "networks");
        require(operations.submit(caller, input)["id"] == task["id"] && calls == 1);
        require(operations.find(caller, "start")["id"] == task["id"]);
        require(operations.find({"other", true, true, true}, "start").isNull());
        input["action"] = "stop";
        rejected(ErrorCode::conflict, [&] { operations.submit(caller, input); });
        input["requestId"] = "stale"; input["expected"]["configurationRevision"] = "stale";
        const auto stale = operations.submit(caller, input);
        require(finished(tasks, caller, stale["id"].asString()).error == ErrorCode::conflict);
        require(operations.submit(caller, input)["id"] == stale["id"] && calls == 2);
        for (const auto* invalid : {"18446744073709551616", "01", "-1", "1.5", ""}) {
            input["expected"]["generation"] = invalid;
            rejected(ErrorCode::invalid_argument, [&] { operations.submit(caller, input); });
        }
        input["expected"]["generation"] = "18446744073709551615";
        input["expected"]["unknown"] = true;
        rejected(ErrorCode::invalid_argument, [&] { operations.submit(caller, input); });
        input["expected"].removeMember("unknown"); input["action"] = "delete";
        rejected(ErrorCode::invalid_argument, [&] { operations.submit(caller, input); });
        input["action"] = "stop"; input["expected"]["state"] = "UNKNOWN";
        rejected(ErrorCode::invalid_argument, [&] { operations.submit(caller, input); });
        input["expected"]["state"] = "STOPPED";
        TaskSpec other{"other", "networks", 4}; other.request_id = "other"; other.request_signature = "other";
        tasks.submit(caller, other, [](TaskControl&) { return TaskCompletion::success(); });
        rejected(ErrorCode::conflict, [&] { operations.find(caller, "other"); });
        input["requestId"] = "blocking"; input["expected"]["configurationRevision"] = "blocking";
        const auto blocking = operations.submit(caller, input);
        try {
            require(entered.get_future().wait_for(5s) == std::future_status::ready);
            const auto running = tasks.get(caller, {tasks.epoch(), blocking["id"].asString()});
            require(!running.cancellable);
            input["requestId"] = "queued";
            const auto queued = operations.submit(caller, input);
            tasks.cancel(caller, {tasks.epoch(), queued["id"].asString()});
            proceed.set_value();
            require(finished(tasks, caller, blocking["id"].asString()).state == TaskState::succeeded);
            require(finished(tasks, caller, queued["id"].asString()).state == TaskState::cancelled && calls == 3);
        } catch (...) { try { proceed.set_value(); } catch (...) {} throw; }
        std::cout << "network operation contracts passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
