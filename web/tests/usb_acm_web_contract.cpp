// SPDX-License-Identifier: GPL-3.0-or-later
#include "usb_acm_fixture.h"
#include <iostream>
using namespace droidvm;
using namespace droidvm::web;
namespace {
void check(bool value) { if (!value) throw std::runtime_error("USB ACM browser contract failed"); }
template<class Work> void rejects(ErrorCode code, Work work) {
    try { work(); } catch (const ServiceError& error) { check(error.code() == code); return; }
    throw std::runtime_error("USB ACM request was not rejected");
}
}
int main() {
    try {
        const CallContext caller{"browser", true, true, true};
        TaskLimits limits; limits.background_workers = 1; TaskService tasks(limits);
        FixtureUsbAcm fixture(tasks); auto api = usb_acm_operations(fixture.bindings());
        const auto initial = api.read(caller);
        check(initial["initialized"] == false && !initial.isMember("private") && fixture.saves == 0 && fixture.pool.applies == 0);
        rejects(ErrorCode::unauthenticated, [&] { api.read({}); });
        Json::Value request; request["requestId"] = "configure"; request["expected"] = initial["expected"];
        request["operation"]["kind"] = "configure"; request["operation"]["enabled"] = true; request["operation"]["ports"] = 2;
        auto bad = request; bad["operation"]["ports"] = 7;
        rejects(ErrorCode::invalid_argument, [&] { api.tasks.submit(caller, bad); });
        bad = request; bad["operation"]["enabled"] = "true";
        rejects(ErrorCode::invalid_argument, [&] { api.tasks.submit(caller, bad); });
        bad = request; bad["operation"]["path"] = "/config/arbitrary";
        rejects(ErrorCode::invalid_argument, [&] { api.tasks.submit(caller, bad); });
        const auto finish = [&](const Json::Value& input) {
            auto task = api.tasks.submit(caller, input);
            const auto until = TaskService::Clock::now() + std::chrono::seconds(5);
            while (task["state"] == "queued" || task["state"] == "running") {
                check(TaskService::Clock::now() < until);
                std::this_thread::sleep_for(std::chrono::milliseconds(1)); task = api.tasks.find(caller, input["requestId"].asString());
            }
            return task;
        };
        auto task = finish(request);
        check(task["state"] == "succeeded" && task["usbAcmResult"]["saved"] == true && task["usbAcmResult"]["applied"] == true);
        check(api.tasks.submit(caller, request)["id"] == task["id"] && fixture.saves == 1 && fixture.pool.applies == 1);
        check(api.tasks.find({"other", true, true, true}, "configure").isNull());
        auto current = api.read(caller);
        fixture.set_mode("busy"); current = api.read(caller);
        check(current["live"]["owners"].size() == 1 && !current["live"]["owners"][0].isMember("private"));
        request["requestId"] = "busy"; request["expected"] = current["expected"]; request["operation"]["ports"] = 3;
        task = finish(request);
        check(task["errorCode"] == "CONFLICT" && fixture.saves == 1 && fixture.pool.applies == 1);
        fixture.set_mode("apply-failed"); request["requestId"] = "apply-failed";
        task = finish(request);
        check(task["state"] == "failed" && task["usbAcmResult"]["saved"] == true && task["usbAcmResult"]["applied"] == false && task["usbAcmResult"]["uncertain"] == false);
        check(fixture.saves == 2 && api.read(caller)["desired"]["ports"] == 3 && api.read(caller)["live"]["ports"] == 2);
        fixture.set_mode("ready");
        request["requestId"] = "apply-saved"; request["expected"] = api.read(caller)["expected"];
        request["operation"] = Json::Value(Json::objectValue); request["operation"]["kind"] = "apply";
        task = finish(request);
        check(task["state"] == "succeeded" && task["usbAcmResult"]["saved"] == true && task["usbAcmResult"]["applied"] == true && fixture.saves == 2);
        fixture.set_mode("apply-unknown"); request["requestId"] = "unknown";
        task = finish(request);
        check(task["state"] == "failed" && task["usbAcmResult"]["uncertain"] == true);
        Json::Value cancelled;
        for (const auto* key : {"expected", "desired", "revision", "live"}) cancelled[key] = Json::Value();
        for (const auto* key : {"saved", "applied", "uncertain"}) cancelled[key] = false;
        check(project_usb_acm_result(cancelled).isNull() && !project_usb_acm_result(cancelled, true).isNull());
        tasks.shutdown();
        std::cout << "USB ACM browser contracts passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
