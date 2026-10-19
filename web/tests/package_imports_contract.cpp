// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/package_imports.h"
#include "web/task_adapter.h"
#include "common/identity.h"
#include "common/wire.h"
#include <chrono>
#include <iostream>
#include <source_location>
#include <thread>

using namespace droidvm;
using namespace droidvm::web;
using namespace std::chrono_literals;
namespace {
void require(bool value, const std::source_location& at = std::source_location::current()) {
    if (!value) throw std::runtime_error("Package import contract failed at line " + std::to_string(at.line()));
}
template<class Work> void rejected(ErrorCode code, Work work) {
    try { work(); } catch (const ServiceError& error) { require(error.code() == code); return; }
    throw std::runtime_error("Expected import rejection");
}
TaskView finished(TaskService& tasks, const CallContext& caller, const std::string& id) {
    const auto end = TaskService::Clock::now() + 5s;
    while (TaskService::Clock::now() < end) {
        const auto task = tasks.get(caller, {tasks.epoch(), id});
        if (task_terminal(task.state)) return task;
        std::this_thread::sleep_for(1ms);
    }
    throw std::runtime_error("Import task did not finish");
}
Json::Value plan_result() {
    return wire::parse(R"({"source_path":"/packages/guest.dvm","vm_name":"Guest","app_version":"1","backend":"QEMU","cpu_count":4,"memory_mib":2048,"notes":"<untrusted>notes</untrusted>","manifest_version":2,"compression":"ZSTD","volume_count":0,"vm_revision":"vms","disk_revision":"disks","network_revision":"networks","disks":[{"name":"root","size_bytes":"1234","attached":true,"readonly":false}],"boots":[{"name":"boot","kind":"kernel","size_bytes":"12"}],"networks":[{"ref":"net0","name":"Imported network","bridge_type":"BRIDGE","uplink_mode":"NONE","create_allowed":false,"conflict_kind":"ipv4","candidates":[{"id":"existing","name":"Existing"}]}],"_confirmation":{"manifest":"SECRET_MANIFEST","source_identity":"SECRET_INODE"}})");
}
Json::Value receipt() {
    return wire::parse(R"({"registered":true,"registration_uncertain":false,"recovery_required":false,"cleanup_complete":true,"vm_id":"new-vm","total":2,"done":2,"private":"SECRET_RECEIPT"})");
}
Json::Value preview(std::string id) {
    Json::Value value; value["requestId"] = std::move(id); value["source"] = "/packages/guest.dvm.001"; return value;
}
Json::Value import_request(std::string id, std::string plan) {
    auto value = wire::parse(R"({"requestId":"import","planRequestId":"plan","operation":{"targetDirectory":"/imports","networks":[{"ref":"net0","action":"join","networkId":"existing"}],"confirmed":true}})");
    value["requestId"] = std::move(id); value["planRequestId"] = std::move(plan); return value;
}
std::string cookie(const HttpResponse& response) {
    for (const auto& [name, value] : response.headers) if (name == "Set-Cookie") return value.substr(0, value.find(';'));
    throw std::runtime_error("Missing cookie");
}
void contract() {
    TaskLimits limits; limits.background_workers = 1; limits.max_result_bytes = 256u << 10;
    TaskService tasks(limits);
    int submissions = 0;
    Json::Value captured;
    const auto operations = package_imports(tasks,
        [&](const CallContext& caller, const std::string& source, const std::string& request_id) {
            require(source == "/packages/guest.dvm.001");
            TaskSpec spec{"package_import_plan", "package", 256u << 10, true, true};
            spec.request_id = request_id; spec.request_signature = random_id(true);
            return tasks.submit(caller, spec, [](TaskControl&) { return TaskCompletion::success(plan_result()); });
        },
        [&](const CallContext& caller, const Json::Value& request, const std::string& plan_request_id, const std::string& request_id) {
            ++submissions;
            const auto plan = tasks.find_request(caller, plan_request_id);
            if (!plan || plan->kind != "package_import_plan" || plan->state != TaskState::succeeded)
                throw ServiceError(ErrorCode::not_found, "Import plan unavailable");
            captured = request;
            TaskSpec spec{"vm_import", "package", 1024, true, true};
            spec.request_id = request_id; spec.request_signature = random_id(true);
            return tasks.submit(caller, spec, [](TaskControl&) { return TaskCompletion::success(receipt()); });
        });
    const CallContext owner{"browser", true, true, true}, other{"other", true, true, true};
    rejected(ErrorCode::unauthenticated, [&] { operations.plans.submit({}, preview("plan")); });
    const auto started = operations.plans.submit(owner, preview("plan"));
    const auto done = finished(tasks, owner, started["id"].asString());
    const auto plan = operations.plans.find(owner, "plan");
    const auto& view = plan["packageImportPlan"];
    require(view["source"] == "/packages/guest.dvm" && view["vmRevision"] == "vms" && view["disks"][0]["sizeBytes"] == "1234"
        && view["networks"][0]["candidates"][0]["id"] == "existing" && view["memoryMiB"].asUInt() == 2048
        && view["notes"] == "<untrusted>notes</untrusted>" && wire::stringify(plan).find("SECRET_") == std::string::npos);
    rejected(ErrorCode::conflict, [&] { operations.plans.submit(owner, preview("plan")); });
    require(operations.plans.find(other, "plan").isNull());
    rejected(ErrorCode::not_found, [&] { operations.tasks.submit(other, import_request("other-import", "plan")); });
    const auto accepted = operations.tasks.submit(owner, import_request("import", "plan"));
    require(captured.size() == 2 && captured["target_dir"] == "/imports" && captured["network_plan"][0]["network_id"] == "existing"
        && !captured.isMember("src_path") && !captured.isMember("manifest"));
    auto imported = finished(tasks, owner, accepted["id"].asString());
    require(task_view(imported)["packageImport"]["registered"].asBool() && wire::stringify(task_view(imported)).find("SECRET_") == std::string::npos);
    rejected(ErrorCode::conflict, [&] { operations.tasks.find(owner, "plan"); });
    rejected(ErrorCode::conflict, [&] { operations.tasks.submit(owner, import_request("import", "plan")); });
    const auto before = submissions;
    auto input = import_request("bad", "plan"); input["operation"]["networks"].append(input["operation"]["networks"][0]);
    rejected(ErrorCode::invalid_argument, [&] { operations.tasks.submit(owner, input); });
    input = import_request("bad", "plan"); input["operation"]["networks"][0]["action"] = "skip";
    rejected(ErrorCode::invalid_argument, [&] { operations.tasks.submit(owner, input); }); // Join-only target must not survive action change.
    input = import_request("bad", "plan"); input["operation"]["confirmed"] = false;
    rejected(ErrorCode::invalid_argument, [&] { operations.tasks.submit(owner, input); });
    input = import_request("bad", "plan"); input["manifest"] = Json::Value(Json::objectValue);
    rejected(ErrorCode::invalid_argument, [&] { operations.tasks.submit(owner, input); });
    input = import_request("bad", "plan"); input["operation"]["targetDirectory"] = "relative";
    rejected(ErrorCode::invalid_argument, [&] { operations.tasks.submit(owner, input); });
    require(submissions == before);
    auto contaminated = done.result; contaminated["disks"][0]["size_bytes"] = "-1";
    require(project_package_import_plan(contaminated).isNull());
    for (const auto state : {TaskState::failed, TaskState::cancelled}) {
        imported.state = state;
        imported.result = receipt(); imported.result["registered"] = false;
        imported.result["registration_uncertain"] = state == TaskState::failed;
        imported.result["recovery_required"] = true; imported.result["cleanup_complete"] = false;
        imported.result["retained_directory"] = "/imports/retained"; imported.result["done"] = 0;
        const auto result = task_view(imported)["packageImport"];
        require(result["recoveryRequired"].asBool() && !result["cleanupComplete"].asBool() && result["retainedDirectory"] == "/imports/retained"
            && result["vmId"] == "new-vm" && !result["registered"].asBool());
    }

    SessionStore sessions; ResourceCatalogs resources; resources.package_imports = operations;
    HttpApi api(sessions, {{"127.0.0.1:8080", "http://127.0.0.1:8080"}}, [](const CallContext&) { return Json::Value(); },
        {"epoch", {"test", "1"}}, {}, {}, {}, {}, false, {}, resources);
    auto http = [](std::string method, std::string path) {
        return HttpRequest{std::move(method), std::move(path), {{"Host", "127.0.0.1:8080"}, {"Origin", "http://127.0.0.1:8080"}}, {}};
    };
    auto login = http("POST", "/api/v1/session"); login.headers.emplace_back("Content-Type", "application/json");
    Json::Value token; token["pairingToken"] = sessions.issue_pairing({"local-admin", true, true, true}).token;
    login.body = wire::stringify(token); const auto logged = api.handle(login); require(logged.status == 201);
    const auto session = wire::parse(logged.body);
    auto read = http("GET", "/api/v1/capabilities"); read.headers.emplace_back("Cookie", cookie(logged));
    const auto capabilities = wire::parse(api.handle(read).body);
    bool enabled = false; for (const auto& capability : capabilities["server"]["capabilities"]) enabled |= capability == "packages.import.v1";
    require(enabled);
    auto body = preview("http-plan"); body["context"] = capabilities["context"];
    auto post = http("POST", "/api/v1/package-import-plans"); post.headers.emplace_back("Cookie", cookie(logged));
    post.headers.emplace_back("Content-Type", "application/json"); post.body = wire::stringify(body);
    require(api.handle(post).status == 403);
    post.headers.emplace_back("X-DroidVM-CSRF", session["csrfToken"].asString());
    const auto submitted = api.handle(post); require(submitted.status == 202);
    const auto caller = sessions.authenticate(cookie(logged).substr(cookie(logged).find('=') + 1)).caller;
    (void)finished(tasks, caller, wire::parse(submitted.body)["task"]["id"].asString());
    read.path = "/api/v1/package-import-plans/http-plan"; require(api.handle(read).status == 200);
    body = import_request("http-import", "http-plan"); body["context"] = capabilities["context"];
    post.path = "/api/v1/package-imports"; post.body = wire::stringify(body); require(api.handle(post).status == 202);
    read.path = "/api/v1/package-imports/http-import"; require(api.handle(read).status == 200);
    body["context"]["daemonEpoch"] = "old"; post.body = wire::stringify(body); require(api.handle(post).status == 409);
    post.body.resize((32u << 10) + 1, ' '); require(api.handle(post).status == 413);
}
}
int main() {
    try { contract(); std::cout << "Package import API contract passed\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
