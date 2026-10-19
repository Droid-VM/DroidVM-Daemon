// SPDX-License-Identifier: GPL-3.0-or-later
#include "hugepage_fixture.h"
#include <chrono>
#include <iostream>
#include <thread>
using namespace droidvm;
using namespace droidvm::web;
namespace {
void require(bool value) { if (!value) throw std::runtime_error("Hugepage browser contract failed"); }
template<class Work> void rejected(ErrorCode code, Work work) {
    try { work(); } catch (const ServiceError& error) { require(error.code() == code); return; }
    throw std::runtime_error("Expected hugepage rejection");
}
}
int main() {
    try {
        const CallContext caller{"browser", true, true, true};
        TaskLimits limits; limits.background_workers = 1; TaskService tasks(limits);
        FixtureHugepages fixture; auto operations = hugepage_operations(fixture.bindings(tasks));
        const auto initial = operations.read(caller);
        require(initial["consumerPages"] == "512" && initial["actualPoolPages"] == "1024");
        require(initial["manualPoolPages"] == "768" && initial["savedPoolPages"] == "1024");
        require(initial["features"]["gfpHook"] == true && initial["advanced"].size() == 5);
        require(initial["advanced"][0]["key"] == "system_reserve_mb" && initial["advanced"][0]["application"] == "next-load");
        require(initial["advanced"][0]["saved"] == "768" && initial["advanced"][0]["live"] == "512");
        require(initial["cma"]["savedLastPages"] == "2048" && initial["systemReserveDefaultMb"] == "256");
        require(!initial.isMember("settings") && fixture.effects == 0);
        auto input = wire::parse(R"({"requestId":"hugepage-request","expected":{"fingerprint":"hugepage-fixture:1"},"operation":{"kind":"targets","poolPages":"1536","cmaPages":null,"persist":true}})");
        rejected(ErrorCode::unauthenticated, [&] { operations.tasks.submit({}, input); });
        for (const auto* kind : {"runtime", "unload", "advanced", "write", "boot"}) {
            auto bad = input; bad["operation"]["kind"] = kind;
            rejected(ErrorCode::invalid_argument, [&] { operations.tasks.submit(caller, bad); });
        }
        for (const auto* count : {"-1", "01", "1073741825", "18446744073709551616"}) {
            auto bad = input; bad["operation"]["poolPages"] = count;
            rejected(ErrorCode::invalid_argument, [&] { operations.tasks.submit(caller, bad); });
        }
        auto bad = input; bad["operation"]["acquireMode"] = 1;
        rejected(ErrorCode::invalid_argument, [&] { operations.tasks.submit(caller, bad); });
        for (const auto* unsupported : {R"({"kind":"write","path":"/proc/sys/vm/drop_caches","value":"3"})",
            R"({"kind":"advanced","key":"arbitrary_knob","value":"1"})",
            R"({"kind":"advanced","key":"system_reserve_mb","value":"63"})",
            R"({"kind":"advanced","key":"boot_acquire_runs","value":"100"})",
            R"({"kind":"cma","enabled":true,"pages":"0","persist":false,"lever":null})",
            R"({"kind":"cma-save","pages":"2048","lever":"shell"})",
            R"({"kind":"runtime","enabled":true,"path":"/private/module"})"}) {
            bad = input; bad["operation"] = wire::parse(unsupported);
            rejected(ErrorCode::invalid_argument, [&] { operations.tasks.submit(caller, bad); });
        }
        auto first = operations.tasks.submit(caller, input);
        auto finish = [&](const Json::Value& task) {
            auto deadline = TaskService::Clock::now() + std::chrono::seconds(5);
            while (!task_terminal(tasks.get(caller, {tasks.epoch(), task["id"].asString()}).state)) {
                require(TaskService::Clock::now() < deadline); std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            return operations.tasks.find(caller, input["requestId"].asString());
        };
        auto done = finish(first);
        require(done["state"] == "succeeded" && done["hugepageResult"]["saved"] == true);
        require(done["hugepageResult"]["snapshot"]["actualCmaPages"] == "2048");
        require(operations.tasks.submit(caller, input)["id"] == first["id"] && fixture.effects == 1);
        require(operations.tasks.find({"other", true, true, true}, "hugepage-request").isNull());
        { std::lock_guard lock(fixture.mutex); fixture.mode = "uncertain"; }
        input["requestId"] = "partial"; input["expected"]["fingerprint"] = "hugepage-fixture:2";
        done = finish(operations.tasks.submit(caller, input));
        require(done["state"] == "failed" && done["hugepageResult"]["uncertain"] == true && done["hugepageResult"]["applied"] == true);
        { std::lock_guard lock(fixture.mutex); fixture.mode = "unknown"; }
        auto unknown = operations.read(caller);
        require(unknown["actualPoolPages"].isNull() && unknown["acquireActive"].isNull() && unknown["consumerPages"].isNull());
        require(unknown["manualPoolPages"].isNull());
        { std::lock_guard lock(fixture.mutex); fixture.set_mode("idle"); }
        unsigned sequence = 0;
        auto run = [&](const char* operation) {
            input["requestId"] = "manage-" + std::to_string(++sequence);
            input["expected"]["fingerprint"] = operations.read(caller)["fingerprint"];
            input["operation"] = wire::parse(operation);
            return finish(operations.tasks.submit(caller, input));
        };
        done = run(R"({"kind":"boot","enabled":false})");
        require(done["state"] == "succeeded" && done["hugepageResult"]["saved"] == true && operations.read(caller)["bootEnabled"] == false);
        done = run(R"({"kind":"cma","enabled":true,"pages":"4096","persist":false,"lever":"hook"})");
        require(done["hugepageResult"]["saved"] == false && done["hugepageResult"]["applied"] == true);
        auto trial = operations.read(caller);
        require(trial["actualCmaPages"] == "4096" && trial["savedCmaPages"] == "2048" && trial["acquireActive"] == true);
        done = run(R"({"kind":"cma-save","pages":"4096","lever":"hook"})");
        require(done["hugepageResult"]["saved"] == true && operations.read(caller)["savedCmaPages"] == "4096");
        done = run(R"({"kind":"advanced","key":"system_reserve_mb","value":"1024"})");
        require(done["hugepageResult"]["implementation"] == "next-load" && done["hugepageResult"]["applied"] == false);
        require(operations.read(caller)["advanced"][0]["live"] == "512");
        done = run(R"({"kind":"unload"})"); require(done["state"] == "succeeded" && operations.read(caller)["loaded"] == false);
        done = run(R"({"kind":"runtime","enabled":true})"); require(done["state"] == "succeeded" && operations.read(caller)["loaded"] == true);
        { std::lock_guard lock(fixture.mutex); fixture.set_mode("legacy"); }
        const auto before_read = fixture.effects;
        auto legacy = operations.read(caller);
        require(legacy["features"]["stopAcquire"] == false && legacy["hasCma"] == false && legacy["acquireActive"].isNull());
        require(legacy["actualPoolPages"].isString() && fixture.effects == before_read);
        require(legacy["hasCrash"] == true && legacy["hasLegacySettings"] == true);
        done = run(R"({"kind":"migrate-settings"})"); require(done["state"] == "succeeded");
        done = run(R"({"kind":"dismiss-crash"})"); require(done["state"] == "succeeded");
        require(operations.read(caller)["hasCrash"] == false && operations.read(caller)["hasLegacySettings"] == false);
        { std::lock_guard lock(fixture.mutex); fixture.set_mode("ready"); }
        const auto before_conflict = fixture.effects;
        done = run(R"({"kind":"unload"})");
        require(done["state"] == "failed" && done["errorCode"] == "CONFLICT" && fixture.effects == before_conflict);
        std::cout << "hugepage browser contracts passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
