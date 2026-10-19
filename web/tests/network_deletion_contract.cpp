// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/network_deletion.h"
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
    if (!value) throw std::runtime_error("Network deletion contract failed at line " + std::to_string(at.line()));
}
template<class Work> void rejected(ErrorCode code, Work work) {
    try { work(); } catch (const ServiceError& error) { require(error.code() == code); return; }
    throw std::runtime_error("Expected deletion rejection");
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
        std::atomic<int> commits = 0, aborts = 0, recoveries = 0;
        std::string received;
        const auto deletion = web::network_deletion(tasks, {
            [&](const CallContext&, const std::string& revision, size_t bytes) {
                require(revision == "vms-observed" && bytes == 3); return "upload";
            },
            [&](const CallContext&, const std::string& upload, size_t offset, std::string_view bytes) {
                require(upload == "upload" && offset == received.size()); received.append(bytes); return received.size();
            },
            [&](const CallContext&, const std::string& upload) {
                ++commits;
                if (upload == "stale") throw ServiceError(ErrorCode::conflict, "changed network or VM configuration");
                auto result = wire::parse(R"({"networkId":"network","vmRevision":"vms-after","persistence":"persisted","private":"must not escape"})");
                if (upload == "uncertain") result["persistence"] = "uncertain";
                if (upload == "invalid") result["vmRevision"] = "/private/path";
                return result;
            },
            [&](const CallContext&, const std::string&) { ++aborts; }
        });
        const auto begin = wire::parse(R"({"revision":"vms-observed","bytes":3})");
        rejected(ErrorCode::unauthenticated, [&] { deletion.invoke({}, "begin", begin); });
        rejected(ErrorCode::permission_denied, [&] { deletion.invoke({"viewer", true, true, false}, "begin", begin); });
        auto too_large = begin; too_large["bytes"] = (9u << 20) + 1;
        rejected(ErrorCode::invalid_argument, [&] { deletion.invoke(caller, "begin", too_large); });
        require(deletion.invoke(caller, "begin", begin)["uploadId"] == "upload");
        require(deletion.invoke(caller, "append", wire::parse(R"({"uploadId":"upload","offset":0,"data":"YWJj"})"))["received"].asUInt64() == 3);
        require(received == "abc");
        auto input = wire::parse(R"({"uploadId":"upload","requestId":"delete"})");
        const auto accepted = deletion.invoke(caller, "commit", input)["task"];
        const auto outcome = finished(tasks, caller, accepted["id"].asString());
        require(outcome.state == TaskState::succeeded && outcome.kind == "network_deletion" && outcome.resource == "networks");
        require(deletion.invoke(caller, "commit", input)["task"]["id"] == accepted["id"] && commits == 1);
        const auto status_input = wire::parse(R"({"requestId":"delete"})");
        const auto status = deletion.invoke(caller, "status", status_input);
        require(status["version"].size() == 3 && status["version"]["networkId"] == "network" &&
            status["version"]["vmRevision"] == "vms-after" && status["version"]["persistence"] == "persisted");
        require(deletion.invoke({"another", true, true, true}, "status", status_input)["task"].isNull());
        input["uploadId"] = "different";
        rejected(ErrorCode::conflict, [&] { deletion.invoke(caller, "commit", input); });
        for (const char* failure : {"stale", "uncertain", "invalid"}) {
            input["uploadId"] = failure; input["requestId"] = failure;
            const auto task = deletion.invoke(caller, "commit", input)["task"];
            const auto result = finished(tasks, caller, task["id"].asString());
            require(result.error == (std::string(failure) == "stale" ? ErrorCode::conflict : ErrorCode::commit_uncertain));
            Json::Value query; query["requestId"] = failure;
            require(deletion.invoke(caller, "status", query)["version"].isNull());
        }
        const auto recovery = web::configuration_recovery(tasks, [&](const CallContext&) { ++recoveries; });
        const auto recovery_input = wire::parse(R"({"requestId":"recover"})");
        rejected(ErrorCode::permission_denied, [&] { recovery.submit({"viewer", true, false, true}, recovery_input); });
        auto invalid = recovery_input; invalid["networkId"] = "network";
        rejected(ErrorCode::invalid_argument, [&] { recovery.submit(caller, invalid); });
        rejected(ErrorCode::conflict, [&] { recovery.find(caller, "delete"); });
        const auto recovering = recovery.submit(caller, recovery_input);
        const auto recovered = finished(tasks, caller, recovering["id"].asString());
        require(recovered.state == TaskState::succeeded && recovered.kind == "configuration_recovery" && recovered.resource == "networks");
        require(recovery.submit(caller, recovery_input)["id"] == recovering["id"] && recoveries == 1 && commits == 4);
        require(recovery.find({"another", true, true, true}, "recover").isNull());
        rejected(ErrorCode::not_found, [&] { deletion.invoke(caller, "status", recovery_input); });
        // Shared staging must abort an upload if its queued commit is cancelled.
        std::promise<void> entered, proceed;
        auto wait = proceed.get_future().share();
        const auto blocking_recovery = web::configuration_recovery(tasks, [&](const CallContext&) { entered.set_value(); wait.wait(); });
        Json::Value blocking_input; blocking_input["requestId"] = "blocking";
        const auto blocking = blocking_recovery.submit(caller, blocking_input);
        try {
            require(entered.get_future().wait_for(5s) == std::future_status::ready);
            require(!tasks.get(caller, {tasks.epoch(), blocking["id"].asString()}).cancellable);
            input["requestId"] = "cancelled"; input["uploadId"] = "queued";
            const auto queued = deletion.invoke(caller, "commit", input)["task"];
            tasks.cancel(caller, {tasks.epoch(), queued["id"].asString()});
            proceed.set_value();
            require(finished(tasks, caller, queued["id"].asString()).state == TaskState::cancelled);
            require(finished(tasks, caller, blocking["id"].asString()).state == TaskState::succeeded);
            require(aborts == 1 && commits == 4);
        } catch (...) { try { proceed.set_value(); } catch (...) {} throw; }
        std::cout << "network deletion contracts passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
