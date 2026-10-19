// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/service_control.h"
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
    if (!value) throw std::runtime_error("Web service control contract failed at line " + std::to_string(at.line()));
}
void contract() {
    TaskLimits limits; limits.background_workers = 1; TaskService tasks(limits);
    SessionStore sessions; const CallContext local{"local-admin", true, true, true};
    const auto grant = sessions.exchange(sessions.issue_pairing(local).token);
    const auto baseline = wire::parse(R"({"enabled":true,"port":8080,"scope":"lan","publicOrigins":[],"lanAutoLogin":false})");
    std::atomic<size_t> changes = 0;
    WebServiceBindings bindings;
    bindings.read = [&](const CallContext& caller) {
        require(caller.principal == grant.session.caller.principal && caller.principal != "local-admin");
        auto result = wire::parse(R"({"running":true,"state":"running","error":null,"addresses":["http://127.0.0.1:8080"],"applyPending":true,"pairingToken":"PRIVATE","sessions":["PRIVATE"]})");
        result["settings"] = baseline; return result;
    };
    bindings.change = [&](const CallContext& caller, const Json::Value& input) {
        require(caller.principal == grant.session.caller.principal && input.size() == 3 && !input.isMember("requestId"));
        ++changes;
        if (input["expected"] != baseline) throw ServiceError(ErrorCode::conflict, "PRIVATE");
        if (input["settings"]["port"] == 8082) throw ServiceError(ErrorCode::commit_uncertain, "PRIVATE");
        Json::Value result; result["action"] = input["action"]; result["settings"] = input["settings"]; result["applyPending"] = true;
        result["pairingToken"] = "PRIVATE"; return result;
    };
    ResourceCatalogs resources; resources.web_service = web_service_operations(tasks, bindings);
    HttpApi api(sessions, {{"127.0.0.1:8080", "http://127.0.0.1:8080"}}, [](const CallContext&) { return Json::Value(); },
        {"epoch", {"test", "1"}}, {}, {}, {}, {}, false, {}, resources);
    auto request = [&](std::string method, std::string path, Json::Value body = {}) {
        HttpRequest req{method, std::move(path), {{"Host", "127.0.0.1:8080"}, {"Cookie", "droidvm-session=" + grant.token}}, {}};
        if (method == "POST") { req.headers.emplace_back("Origin", "http://127.0.0.1:8080"); req.headers.emplace_back("X-DroidVM-CSRF", grant.session.csrf); }
        if (!body.isNull()) { req.headers.emplace_back("Content-Type", "application/json"); req.body = wire::stringify(body); }
        return req;
    };
    const auto caps = wire::parse(api.handle(request("GET", "/api/v1/capabilities")).body);
    bool enabled = false; for (const auto& cap : caps["server"]["capabilities"]) enabled |= cap == "web.service.v1";
    require(enabled);
    const auto read = api.handle(request("GET", "/api/v1/web-service"));
    require(read.status == 200 && read.body.find("PRIVATE") == std::string::npos && wire::parse(read.body)["applyPending"] == true);
    Json::Value input; input["context"] = caps["context"]; input["requestId"] = "configure"; input["action"] = "configure";
    input["expected"] = baseline; input["settings"] = baseline; input["settings"]["port"] = 8081;
    const std::string path = "/api/v1/web-service/operations";
    auto no_csrf = request("POST", path, input); no_csrf.headers.erase(no_csrf.headers.begin() + 3);
    require(api.handle(no_csrf).status == 403 && changes == 0);
    auto stale_context = input; stale_context["context"]["daemonEpoch"] = "old";
    require(api.handle(request("POST", path, stale_context)).status == 409 && changes == 0);
    auto invalid = input; invalid["settings"]["port"] = 80;
    require(api.handle(request("POST", path, invalid)).status == 400 && changes == 0);
    invalid = input; invalid["settings"]["publicOrigins"].append("http://host/path");
    require(api.handle(request("POST", path, invalid)).status == 400 && changes == 0);
    invalid = input; invalid["action"] = "restart";
    require(api.handle(request("POST", path, invalid)).status == 400 && changes == 0);
    auto finish = [&](const std::string& id) {
        Json::Value task; const auto deadline = std::chrono::steady_clock::now() + 5s;
        do {
            task = wire::parse(api.handle(request("GET", path + "/" + id)).body)["task"];
            if (task["state"] == "failed" || task["state"] == "succeeded") return task;
            std::this_thread::sleep_for(1ms);
        } while (std::chrono::steady_clock::now() < deadline);
        throw std::runtime_error("Web service task deadline exceeded");
    };
    require(api.handle(request("POST", path, input)).status == 202);
    const auto configured = finish("configure");
    require(configured["state"] == "succeeded" && configured["webService"]["applyPending"] == true
        && configured["webService"]["settings"]["port"] == 8081 && wire::stringify(configured).find("PRIVATE") == std::string::npos);
    require(api.handle(request("POST", path, input)).status == 202 && changes == 1);
    invalid = input; invalid["settings"]["port"] = 8083;
    require(api.handle(request("POST", path, invalid)).status == 409 && changes == 1);
    auto stale = input; stale["requestId"] = "stale"; stale["expected"]["port"] = 8083;
    require(api.handle(request("POST", path, stale)).status == 202);
    const auto conflict = finish("stale"); require(conflict["errorCode"] == "CONFLICT" && !conflict.isMember("webService"));
    auto uncertain = input; uncertain["requestId"] = "uncertain"; uncertain["settings"]["port"] = 8082;
    require(api.handle(request("POST", path, uncertain)).status == 202);
    const auto failed = finish("uncertain");
    require(failed["errorCode"] == "COMMIT_UNCERTAIN" && !failed.isMember("webService") && wire::stringify(failed).find("PRIVATE") == std::string::npos);
    const auto other = sessions.exchange(sessions.issue_pairing(local).token);
    auto foreign = request("GET", path + "/configure"); foreign.headers[1].second = "droidvm-session=" + other.token;
    require(wire::parse(api.handle(foreign).body)["task"].isNull());
    require(api.handle(request("GET", path + "/configure/extra")).status == 400);
    require(api.handle(request("GET", "/api/v1/web-service/pair")).status == 404);
    tasks.shutdown();
}
}
int main() {
    try { contract(); std::cout << "Web service control contract passed\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
