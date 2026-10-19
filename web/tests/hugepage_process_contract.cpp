// SPDX-License-Identifier: GPL-3.0-or-later
#include "hugepage_process_fixture.h"
#include <chrono>
#include <iostream>
#include <thread>
using namespace droidvm;
using namespace droidvm::web;
namespace {
void require(bool value) { if (!value) throw std::runtime_error("Hugepage process browser contract failed"); }
template<class Work> void rejected(ErrorCode code, Work work) {
    try { work(); } catch (const ServiceError& error) { require(error.code() == code); return; }
    throw std::runtime_error("Expected hugepage process rejection");
}
}
int main() {
    try {
        const CallContext caller{"browser", true, true, true};
        TaskLimits limits; limits.background_workers = 1; TaskService tasks(limits);
        FixtureHugepageProcesses fixture; auto operations = hugepage_process_operations(fixture.bindings(tasks));
        auto catalog = operations.list(caller, "auto");
        require(catalog["source"] == "ko" && catalog["entries"].size() == 2 && fixture.effects == 0);
        require(!catalog["entries"][0].isMember("private") && catalog["entries"][1]["expected"].isNull());
        require(catalog["entries"][1]["canSignal"] == false && catalog["totals"]["pages"] == "640");
        rejected(ErrorCode::unauthenticated, [&] { operations.list({}, "auto"); });
        rejected(ErrorCode::invalid_argument, [&] { operations.list(caller, "all"); });
        const auto identity = catalog["entries"][0]["expected"];
        Json::Value input; input["expected"] = identity; input["signal"] = "term"; input["requestId"] = "first";
        auto bad = input; bad["signal"] = "9";
        rejected(ErrorCode::invalid_argument, [&] { operations.tasks.submit(caller, bad); });
        bad = input; bad["expected"]["pid"] = 1;
        rejected(ErrorCode::invalid_argument, [&] { operations.tasks.submit(caller, bad); });
        bad = input; bad["expected"]["path"] = "/proc/1";
        rejected(ErrorCode::invalid_argument, [&] { operations.tasks.submit(caller, bad); });
        auto finish = [&](const Json::Value& request) {
            const auto first = operations.tasks.submit(caller, request);
            const auto deadline = TaskService::Clock::now() + std::chrono::seconds(5);
            while (!task_terminal(tasks.get(caller, {tasks.epoch(), first["id"].asString()}).state)) {
                require(TaskService::Clock::now() < deadline); std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            return operations.tasks.find(caller, request["requestId"].asString());
        };
        auto done = finish(input);
        require(done["state"] == "succeeded" && done["hugepageProcessResult"]["sent"] == true && done["hugepageProcessResult"]["exited"] == false);
        require(!done["hugepageProcessResult"].isMember("private") && fixture.effects == 1);
        require(operations.tasks.submit(caller, input)["id"] == done["id"] && fixture.effects == 1);
        require(operations.tasks.find({"other", true, true, true}, "first").isNull());
        { std::lock_guard lock(fixture.mutex); ++fixture.revision; fixture.mode = "d-state"; }
        input["requestId"] = "stale"; done = finish(input);
        require(done["errorCode"] == "CONFLICT" && done["hugepageProcessResult"]["sent"] == false && fixture.effects == 1);
        rejected(ErrorCode::conflict, [&] { operations.stack(caller, identity); });
        catalog = operations.list(caller, "scan");
        const auto current = catalog["entries"][0]["expected"];
        const auto stack = operations.stack(caller, current);
        require(stack["expected"] == current && stack["available"] == true && stack["text"].asString().find("fixture_wait") != std::string::npos);
        require(fixture.effects == 1 && catalog["entries"][0]["canStack"] == true);
        { std::lock_guard lock(fixture.mutex); fixture.mode = "legacy"; }
        catalog = operations.list(caller, "ko");
        require(catalog["entries"][0]["source"] == "ko" && catalog["entries"][0]["expected"]["source"] == "scan");
        require(catalog["entries"][0]["attributionVerified"] == false && catalog["entries"][0]["canSignal"] == true);
        { std::lock_guard lock(fixture.mutex); fixture.mode = "partial"; }
        catalog = operations.list(caller, "ko");
        require(catalog["totals"]["pages"].isNull() && catalog["totals"]["knownPages"] == "128");
        { std::lock_guard lock(fixture.mutex); fixture.mode = "fallback"; }
        require(operations.list(caller, "auto")["source"] == "scan" && operations.list(caller, "ko")["available"] == false);
        { std::lock_guard lock(fixture.mutex); fixture.mode = "empty"; }
        catalog = operations.list(caller, "auto");
        require(catalog["source"] == "ko" && catalog["entries"].empty() && catalog["totals"]["pages"] == "0");
        { std::lock_guard lock(fixture.mutex); fixture.mode = "uncertain"; }
        input["requestId"] = "uncertain"; input["expected"] = current; done = finish(input);
        require(done["state"] == "failed" && done["hugepageProcessResult"]["sent"] == true && done["hugepageProcessResult"]["uncertain"] == true);
        require(operations.tasks.find(caller, "uncertain")["id"] == done["id"] && fixture.effects == 2);
        const auto cancelled = wire::parse(R"({"signal":null,"expected":null,"sent":false,"uncertain":false,"exited":false})");
        require(project_hugepage_process_result(cancelled).isNull());
        require(!project_hugepage_process_result(cancelled, true).isNull());
        std::cout << "hugepage process browser contracts passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
