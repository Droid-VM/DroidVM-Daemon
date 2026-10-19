// SPDX-License-Identifier: GPL-3.0-or-later
#include "host_preference_fixture.h"
#include <iostream>
using namespace droidvm;
using namespace droidvm::web;
namespace {
void require(bool value) { if (!value) throw std::runtime_error("Host preference HTTP contract failed"); }
template<class Work> void rejected(ErrorCode code, Work work) {
    try { work(); } catch (const ServiceError& error) { require(error.code() == code); return; }
    throw std::runtime_error("Host preference request was not rejected");
}
}
int main() {
    try {
        const CallContext caller{"browser", true, true, true};
        TaskLimits limits; limits.background_workers = 1; TaskService tasks(limits);
        FixtureHostPreferences fixture(tasks); auto api = host_preference_operations(fixture.bindings());
        const auto initial = api.read(caller);
        require(!initial.isMember("private") && initial["initialized"] == false && fixture.effects == 0);
        require(initial["values"]["optimize_sdcard"] == true);
        rejected(ErrorCode::unauthenticated, [&] { api.read({}); });
        rejected(ErrorCode::permission_denied, [&] { api.read({"viewer", true, false, false}); });
        Json::Value request; request["requestId"] = "save"; request["expected"] = initial["expected"];
        request["changes"]["vm_hugepage_auto_reserve"] = false;
        auto bad = request; bad["changes"]["path"] = "arbitrary";
        rejected(ErrorCode::invalid_argument, [&] { api.tasks.submit(caller, bad); });
        bad = request; bad["changes"]["vm_hugepage_auto_reserve"] = "false";
        rejected(ErrorCode::invalid_argument, [&] { api.tasks.submit(caller, bad); });
        bad = request; bad["changes"] = Json::Value(Json::objectValue);
        rejected(ErrorCode::invalid_argument, [&] { api.tasks.submit(caller, bad); });
        const auto finish = [&](const Json::Value& input) {
            auto task = api.tasks.submit(caller, input);
            const auto until = TaskService::Clock::now() + std::chrono::seconds(5);
            while (task["state"] == "queued" || task["state"] == "running") {
                require(TaskService::Clock::now() < until);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                task = api.tasks.find(caller, input["requestId"].asString());
            }
            return task;
        };
        auto task = finish(request);
        require(task["state"] == "succeeded" && task["hostPreferenceResult"]["saved"] == true);
        require(task["hostPreferenceResult"]["expected"] == request["expected"] && fixture.effects == 1);
        require(api.tasks.submit(caller, request)["id"] == task["id"] && fixture.effects == 1);
        require(api.tasks.find({"other", true, true, true}, "save").isNull());
        auto legacy = initial["values"]; fixture.service.sync_legacy(caller, legacy);
        require(api.read(caller)["values"]["vm_hugepage_auto_reserve"] == false && fixture.effects == 1);
        request["requestId"] = "stale"; task = finish(request);
        require(task["errorCode"] == "CONFLICT" && task["hostPreferenceResult"]["saved"] == false && fixture.effects == 1);
        request["requestId"] = "uncertain"; request["expected"] = api.read(caller)["expected"];
        request["changes"]["vm_hugepage_auto_reserve"] = true;
        { std::lock_guard lock(fixture.mutex); fixture.mode = "installed-uncertain"; }
        task = finish(request);
        require(task["state"] == "failed" && task["hostPreferenceResult"]["uncertain"] == true);
        require(api.read(caller)["uncertain"] == true && fixture.effects == 2);
        Json::Value cancelled;
        for (const auto* name : {"expected", "values", "revision"}) cancelled[name] = Json::Value();
        cancelled["saved"] = false; cancelled["uncertain"] = false;
        require(project_host_preference_result(cancelled).isNull());
        require(!project_host_preference_result(cancelled, true).isNull());
        FixtureHostPreferences disks(tasks, HostPreferenceDomain::disk_operations);
        const auto disk_api = host_preference_operations(disks.bindings(), HostPreferenceDomain::disk_operations);
        const auto disk_initial = disk_api.read(caller);
        require(disk_initial["capability"] == "disk-defaults-v1" && !disk_initial.isMember("private") &&
            disk_initial["values"]["optimizeCompression"] == "ask" && disk_initial["values"]["qemuImgCpus"].empty());
        Json::Value disk_request; disk_request["requestId"] = "disk-default-save";
        disk_request["expected"] = disk_initial["expected"];
        disk_request["changes"]["optimizeCompression"] = "none";
        disk_request["changes"]["qemuImgCpus"] = Json::Value(Json::arrayValue);
        disk_request["changes"]["qemuImgCpus"].append(3); disk_request["changes"]["qemuImgCpus"].append(1);
        bad = disk_request; bad["changes"]["optimizeCompression"] = "zstd";
        rejected(ErrorCode::invalid_argument, [&] { disk_api.tasks.submit(caller, bad); });
        bad = disk_request; bad["changes"]["qemuImgCpus"].append(3);
        rejected(ErrorCode::invalid_argument, [&] { disk_api.tasks.submit(caller, bad); });
        bad = disk_request; bad["changes"]["qemuImgCpus"][0] = 1024;
        rejected(ErrorCode::invalid_argument, [&] { disk_api.tasks.submit(caller, bad); });
        bad = disk_request; bad["changes"]["qemuImgCpus"] = "1-3";
        rejected(ErrorCode::invalid_argument, [&] { disk_api.tasks.submit(caller, bad); });
        bad = disk_request; bad["changes"]["vm_clear_logs_before_start"] = true;
        rejected(ErrorCode::invalid_argument, [&] { disk_api.tasks.submit(caller, bad); });
        auto disk_task = disk_api.tasks.submit(caller, disk_request);
        const auto disk_until = TaskService::Clock::now() + std::chrono::seconds(5);
        while (disk_task["state"] == "queued" || disk_task["state"] == "running") {
            require(TaskService::Clock::now() < disk_until);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            disk_task = disk_api.tasks.find(caller, "disk-default-save");
        }
        require(disk_task["state"] == "succeeded" && disk_task["diskDefaultResult"]["saved"] == true &&
            disk_task["diskDefaultResult"]["values"]["qemuImgCpus"][0] == 1 && !disk_task.isMember("hostPreferenceResult"));
        require(disk_api.tasks.submit(caller, disk_request)["id"] == disk_task["id"] && disks.effects == 1);
        require(api.tasks.find(caller, "disk-default-save").isNull());
        require(disk_api.tasks.find(caller, "save").isNull());
        tasks.shutdown();
        std::cout << "host preference browser contracts passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
