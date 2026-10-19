// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/package_exports.h"
#include "web/task_adapter.h"
#include "common/wire.h"
#include <chrono>
#include <iostream>
#include <source_location>
#include <thread>

using namespace droidvm;
using namespace droidvm::web;
using namespace std::chrono_literals;
namespace {
constexpr const char* vm_id = "12345678-1234-4234-8234-123456789abc";
void require(bool value, const std::source_location& at = std::source_location::current()) {
    if (!value) throw std::runtime_error("Package export contract failed at line " + std::to_string(at.line()));
}
template<class Work> void rejected(ErrorCode code, Work work) {
    try { work(); } catch (const ServiceError& error) { require(error.code() == code); return; }
    throw std::runtime_error("Expected export rejection");
}
TaskView finished(TaskService& tasks, const CallContext& caller, const std::string& id) {
    const auto end = TaskService::Clock::now() + 5s;
    while (TaskService::Clock::now() < end) {
        const auto task = tasks.get(caller, {tasks.epoch(), id});
        if (task_terminal(task.state)) return task;
        std::this_thread::sleep_for(1ms);
    }
    throw std::runtime_error("Export task did not finish");
}
Json::Value request(std::string request_id) {
    auto value = wire::parse(R"({"requestId":"export","vmId":"vm","vmRevision":"vms","diskRevision":"disks","networkRevision":"networks","operation":{"destination":"/exports/test.dvm","compression":"ZSTD","volumeBytes":"0","disks":[1],"overwriteConfirmed":true}})");
    value["vmId"] = vm_id; value["requestId"] = std::move(request_id); return value;
}
std::string cookie(const HttpResponse& response) {
    for (const auto& [name, value] : response.headers)
        if (name == "Set-Cookie") return value.substr(0, value.find(';'));
    throw std::runtime_error("Missing login cookie");
}
void contract() {
    TaskLimits limits; limits.background_workers = 1;
    TaskService tasks(limits);
    int submissions = 0;
    Json::Value captured;
    auto exports = package_exports(tasks,
        [](const CallContext&, const std::string& id) {
            Json::Value value; value["vm_id"] = id; value["vm_name"] = "Export VM";
            value["vm_revision"] = "vms"; value["disk_revision"] = "disks"; value["network_revision"] = "networks";
            value["disks"] = Json::Value(Json::arrayValue);
            Json::Value disk; disk["index"] = 1; disk["path"] = "/disks/data.qcow2"; disk["readonly"] = false;
            disk["private"] = "not-projected"; value["disks"].append(disk); value["private"] = "not-projected";
            return value;
        },
        [&](const CallContext& caller, const Json::Value& value, const pkg::ExportConfirmation& confirmed,
                const std::string& request_id) {
            ++submissions; captured = value;
            require(confirmed.vm_revision == "vms" && confirmed.disk_revision == "disks" && confirmed.network_revision == "networks");
            TaskSpec spec{"vm_export", "package", 1024, true, true};
            spec.request_id = request_id; spec.request_signature = wire::stringify(value);
            return tasks.submit(caller, std::move(spec), [value](TaskControl&) {
                Json::Value result; result["dest_path"] = "/private/export/path";
                if (value["volume_size"].asInt64() > 0) result["volume_total"] = 3;
                if (value["dest_path"] == "/exports/fail") return TaskCompletion::failure(ErrorCode::io_error, "/private/exception", result);
                return TaskCompletion::success(result);
            });
        });
    const CallContext owner{"browser", true, true, true};
    const auto plan = exports.plan(owner, vm_id);
    require(plan["vmId"] == vm_id && plan["compressions"].size() == 4 && plan["minVolumeBytes"] == "16777216"
        && plan["disks"][0]["index"].asUInt() == 1 && wire::stringify(plan).find("not-projected") == std::string::npos);
    rejected(ErrorCode::unauthenticated, [&] { exports.plan({}, vm_id); });
    rejected(ErrorCode::permission_denied, [&] { exports.tasks.submit({"viewer", true, true, false}, request("denied")); });
    auto input = request("single");
    const auto accepted = exports.tasks.submit(owner, input);
    require(captured.size() == 5 && captured["vm_id"] == vm_id && captured["dest_path"] == "/exports/test.dvm"
        && captured["volume_size"].asInt64() == 0 && captured["disks"][0] == 1);
    require(finished(tasks, owner, accepted["id"].asString()).state == TaskState::succeeded);
    const auto single = exports.tasks.find(owner, "single");
    require(single["packageExport"]["volumeCount"] == 0 && wire::stringify(single).find("/private") == std::string::npos);
    require(exports.tasks.find({"other", true, true, true}, "single").isNull());
    input = request("split"); input["operation"]["volumeBytes"] = "16777216";
    const auto split = exports.tasks.submit(owner, input);
    require(task_view(finished(tasks, owner, split["id"].asString()))["packageExport"]["volumeCount"] == 3);
    input = request("configuration-only"); input["operation"]["disks"] = Json::Value(Json::arrayValue);
    const auto configuration = exports.tasks.submit(owner, input);
    require(captured["disks"].isArray() && captured["disks"].empty());
    require(finished(tasks, owner, configuration["id"].asString()).state == TaskState::succeeded);
    input = request("failed"); input["operation"]["destination"] = "/exports/fail";
    const auto failed = exports.tasks.submit(owner, input);
    const auto failed_view = task_view(finished(tasks, owner, failed["id"].asString()));
    require(failed_view["state"] == "failed" && !failed_view.isMember("packageExport") && wire::stringify(failed_view).find("/private") == std::string::npos);
    const auto before = submissions;
    for (const char* volume : {"-1", "00", "16777215", "9223372036854775808"}) {
        input = request("invalid"); input["operation"]["volumeBytes"] = volume;
        rejected(ErrorCode::invalid_argument, [&] { exports.tasks.submit(owner, input); });
    }
    input = request("invalid"); input["operation"]["disks"].append(1);
    rejected(ErrorCode::invalid_argument, [&] { exports.tasks.submit(owner, input); });
    input = request("invalid"); input["operation"]["disks"][0] = 1.0;
    rejected(ErrorCode::invalid_argument, [&] { exports.tasks.submit(owner, input); });
    input = request("invalid"); input["operation"]["overwriteConfirmed"] = false;
    rejected(ErrorCode::invalid_argument, [&] { exports.tasks.submit(owner, input); });
    for (const auto& path : {std::string("relative.dvm"), std::string("/bad\0path", 9)}) {
        input = request("invalid"); input["operation"]["destination"] = path;
        rejected(ErrorCode::invalid_argument, [&] { exports.tasks.submit(owner, input); });
    }
    require(submissions == before);
    Json::Value bad; bad["volume_total"] = 1000; require(project_package_export(bad).isNull());
    bad["volume_total"] = -1; require(project_package_export(bad).isNull());
    TaskSpec unrelated{"other", "package", 1024}; unrelated.request_id = "unrelated"; unrelated.request_signature = "other";
    tasks.submit(owner, unrelated, [](TaskControl&) { return TaskCompletion::success(); });
    rejected(ErrorCode::conflict, [&] { exports.tasks.find(owner, "unrelated"); });

    SessionStore sessions;
    ResourceCatalogs resources; resources.package_exports = exports;
    HttpApi api(sessions, {{"127.0.0.1:8080", "http://127.0.0.1:8080"}},
        [](const CallContext&) { return Json::Value(); }, {"epoch", {"test", "1"}}, {}, {}, {}, {}, false, {}, resources);
    auto http = [](std::string method, std::string path) {
        return HttpRequest{std::move(method), std::move(path), {{"Host", "127.0.0.1:8080"}, {"Origin", "http://127.0.0.1:8080"}}, {}};
    };
    auto login = http("POST", "/api/v1/session"); login.headers.emplace_back("Content-Type", "application/json");
    Json::Value credentials; credentials["pairingToken"] = sessions.issue_pairing({"local-admin", true, true, true}).token;
    login.body = wire::stringify(credentials); const auto logged = api.handle(login); require(logged.status == 201);
    const auto identity = wire::parse(logged.body);
    auto read = http("GET", std::string("/api/v1/package-export-plans/") + vm_id);
    require(api.handle(read).status == 401);
    read.headers.emplace_back("Cookie", cookie(logged));
    const auto response = api.handle(read); require(response.status == 200);
    auto body = request("http"); body["context"] = wire::parse(response.body)["context"];
    auto post = http("POST", "/api/v1/package-exports"); post.headers.emplace_back("Cookie", cookie(logged));
    post.headers.emplace_back("Content-Type", "application/json"); post.body = wire::stringify(body);
    require(api.handle(post).status == 403);
    post.headers.emplace_back("X-DroidVM-CSRF", identity["csrfToken"].asString());
    auto stale = body; stale["context"]["daemonEpoch"] = "stale"; post.body = wire::stringify(stale);
    require(api.handle(post).status == 409);
    post.body = wire::stringify(body); require(api.handle(post).status == 202);
    post.body.resize((32u << 10) + 1, ' '); require(api.handle(post).status == 413);
    read.path = "/api/v1/package-exports/http"; require(api.handle(read).status == 200);
    read.path = "/api/v1/capabilities";
    const auto capabilities = wire::parse(api.handle(read).body)["server"]["capabilities"];
    bool enabled = false; for (const auto& capability : capabilities) enabled |= capability == "packages.export.v1";
    require(enabled);
}
}
int main() {
    try { contract(); std::cout << "Package export API contract passed\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
