// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/image_imports.h"
#include "common/wire.h"
#include <atomic>
#include <chrono>
#include <iostream>
#include <source_location>
#include <thread>

using namespace droidvm;
using namespace droidvm::web;
using namespace std::chrono_literals;
namespace {
void require(bool value, const std::source_location& at = std::source_location::current()) {
    if (!value) throw std::runtime_error("Image import contract failed at line " + std::to_string(at.line()));
}
Json::Value plan() {
    return wire::parse(R"({"source":"/alias/image.qcow2","vmRevision":"vm-rev","diskRevision":"disk-rev","diskId":"child","members":[{"id":"child","path":"/images/image.qcow2","name":"image.qcow2","parentId":"base","existing":false,"format":"qcow2","virtualSizeBytes":"9007199254740993"},{"id":"base","path":"/images/base.raw","name":"base.raw","parentId":null,"existing":true,"format":"raw","virtualSizeBytes":"9007199254740993"}],"attachments":[{"vmId":"vm","slot":0,"beforePath":"/images/base.raw","afterPath":"/images/image.qcow2","beforeReadOnly":false,"afterReadOnly":false}],"_files":{"private":"PRIVATE_PROOF"}})");
}
void contract() {
    TaskLimits limits; limits.background_workers = 1; limits.max_result_bytes = 256u << 10; TaskService tasks(limits);
    SessionStore sessions; const CallContext local{"local-admin", true, true, true};
    const auto grant = sessions.exchange(sessions.issue_pairing(local).token);
    std::atomic<size_t> previews = 0, commits = 0;
    ImageImportBindings bindings;
    bindings.preview = [&](const CallContext& caller, const std::string& source, const std::function<bool()>& cancelled) {
        require(caller.principal == grant.session.caller.principal && source == "/alias/image.qcow2" && !cancelled());
        ++previews; return plan();
    };
    bindings.commit = [&](const CallContext& caller, const Json::Value& retained, TaskControl& control) {
        require(caller.principal == grant.session.caller.principal && retained["_files"]["private"] == "PRIVATE_PROOF");
        ++commits; require(control.enter_commit());
        auto result = wire::parse(R"({"diskId":"child","registered":false,"registrationUncertain":true,"recoveryRequired":true,"added":1,"private":"PRIVATE_RECEIPT"})");
        return TaskCompletion::failure(ErrorCode::commit_uncertain, "PRIVATE_MESSAGE", std::move(result));
    };
    ResourceCatalogs resources; resources.image_imports = image_imports(tasks, bindings);
    HttpApi api(sessions, {{"127.0.0.1:8080", "http://127.0.0.1:8080"}}, [](const CallContext&) { return Json::Value(); },
        {"epoch", {"test", "1"}}, {}, {}, {}, {}, false, {}, resources);
    auto request = [&](std::string method, std::string path, Json::Value body = {}) {
        HttpRequest req{method, std::move(path), {{"Host", "127.0.0.1:8080"}, {"Cookie", "droidvm-session=" + grant.token}}, {}};
        if (method == "POST") { req.headers.emplace_back("Origin", "http://127.0.0.1:8080"); req.headers.emplace_back("X-DroidVM-CSRF", grant.session.csrf); }
        if (!body.isNull()) { req.headers.emplace_back("Content-Type", "application/json"); req.body = wire::stringify(body); }
        return req;
    };
    const auto caps = wire::parse(api.handle(request("GET", "/api/v1/capabilities")).body);
    bool enabled = false; for (const auto& cap : caps["server"]["capabilities"]) enabled |= cap == "images.import.v1";
    require(enabled);
    auto post = [&](const std::string& path, Json::Value body) { body["context"] = caps["context"]; return request("POST", path, body); };
    const std::string plans = "/api/v1/image-import-plans", imports = "/api/v1/image-imports";
    const auto preview = post(plans, wire::parse(R"({"requestId":"plan","source":"/alias/image.qcow2"})"));
    auto no_csrf = preview; no_csrf.headers.erase(no_csrf.headers.begin() + 3);
    require(api.handle(no_csrf).status == 403 && previews == 0);
    require(api.handle(post(plans, wire::parse(R"({"requestId":"url","source":"https://example/image"})"))).status == 400);
    auto finish = [&](const std::string& base, const std::string& id) {
        const auto deadline = std::chrono::steady_clock::now() + 5s;
        do {
            auto task = wire::parse(api.handle(request("GET", base + "/" + id)).body)["task"];
            if (task["state"] == "failed" || task["state"] == "succeeded") return task;
            std::this_thread::sleep_for(1ms);
        } while (std::chrono::steady_clock::now() < deadline);
        throw std::runtime_error("Image import task deadline exceeded");
    };
    require(api.handle(preview).status == 202);
    const auto planned = finish(plans, "plan");
    require(planned["state"] == "succeeded" && planned["imageImportPlan"]["members"][0]["virtualSizeBytes"] == "9007199254740993"
        && planned["imageImportPlan"]["source"] == "/alias/image.qcow2" && wire::stringify(planned).find("PRIVATE") == std::string::npos);
    const auto retained = tasks.find_request(grant.session.caller, "plan"); require(retained && retained->result["_files"]["private"] == "PRIVATE_PROOF");
    require(api.handle(preview).status == 202 && previews == 1);
    require(api.handle(post(plans, wire::parse(R"({"requestId":"plan","source":"/other"})"))).status == 409);
    require(api.handle(post(imports, wire::parse(R"({"requestId":"bad","planRequestId":"plan","source":"/replacement"})"))).status == 400);
    const auto commit = post(imports, wire::parse(R"({"requestId":"commit","planRequestId":"plan"})"));
    require(api.handle(commit).status == 202);
    const auto imported = finish(imports, "commit");
    require(imported["state"] == "failed" && imported["errorCode"] == "COMMIT_UNCERTAIN"
        && imported["imageImport"]["registrationUncertain"] == true && imported["imageImport"]["added"] == 1
        && wire::stringify(imported).find("PRIVATE") == std::string::npos);
    require(api.handle(commit).status == 202 && commits == 1);
    require(api.handle(post(imports, wire::parse(R"({"requestId":"missing","planRequestId":"absent"})"))).status == 202);
    require(finish(imports, "missing")["errorCode"] == "NOT_FOUND" && commits == 1);
    require(api.handle(request("GET", imports + "/plan")).status == 409);
    const auto other = sessions.exchange(sessions.issue_pairing(local).token);
    auto foreign = request("GET", plans + "/plan"); foreign.headers[1].second = "droidvm-session=" + other.token;
    require(wire::parse(api.handle(foreign).body)["task"].isNull());
    auto foreign_commit = post(imports, wire::parse(R"({"requestId":"foreign","planRequestId":"plan"})"));
    foreign_commit.headers[1].second = "droidvm-session=" + other.token; foreign_commit.headers[3].second = other.session.csrf;
    auto foreign_body = wire::parse(foreign_commit.body); foreign_body["context"]["sessionId"] = other.session.id; foreign_commit.body = wire::stringify(foreign_body);
    require(api.handle(foreign_commit).status == 202);
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    for (;;) {
        const auto task = tasks.find_request(other.session.caller, "foreign");
        if (task && task_terminal(task->state)) { require(task->error == ErrorCode::not_found && commits == 1); break; }
        require(std::chrono::steady_clock::now() < deadline); std::this_thread::sleep_for(1ms);
    }
    auto invalid = plan(); invalid["members"][0]["virtualSizeBytes"] = "01";
    require(project_image_import_plan(invalid).isNull());
    tasks.shutdown();
}
}
int main() {
    try { contract(); std::cout << "Image import contract passed\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
