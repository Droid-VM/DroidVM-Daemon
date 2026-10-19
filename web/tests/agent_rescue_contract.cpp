// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/agent_rescue.h"
#include "web/task_adapter.h"
#include "web/vm_terminal.h"
#include "common/wire.h"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <source_location>
#include <thread>

using namespace droidvm;
using namespace droidvm::web;
using namespace std::chrono_literals;
namespace {
void require(bool value, const std::source_location& at = std::source_location::current()) {
    if (!value) throw std::runtime_error("Rescue API contract failed at line " + std::to_string(at.line()));
}
template<class Work> void rejected(Work work) {
    try { work(); } catch (const ServiceError&) { return; }
    throw std::runtime_error("Expected rescue access rejection");
}
struct Target final : agent::RescueTarget {
    vm::Observation observed{std::string(32, 'a'), 1};
    vm::ConsoleHistory history;
    agent::CleanupReport cleanup{true, true, true};
    int closes = 0;
    std::string input;
    vm::Observation observation() override { return observed; }
    vm::LogSlice read(const vm::Observation& expected, const std::optional<vm::LogCursor>& cursor, bool tail) override {
        require(expected == observed); return history.read(cursor, tail);
    }
    size_t write(const vm::Observation& expected, std::string_view bytes) override {
        require(expected == observed); const auto count = std::min<size_t>(2, bytes.size()); input.append(bytes.substr(0, count)); return count;
    }
    agent::CleanupReport close() override { ++closes; return cleanup; }
};
TaskView finished(TaskService& tasks, const CallContext& caller, const std::string& id) {
    const auto end = TaskService::Clock::now() + 5s;
    while (TaskService::Clock::now() < end) {
        auto value = tasks.get(caller, {tasks.epoch(), id});
        if (task_terminal(value.state)) return value;
        std::this_thread::sleep_for(1ms);
    }
    throw std::runtime_error("Rescue close task did not finish");
}
std::string header(const HttpResponse& response, const std::string& key) {
    for (const auto& [name, value] : response.headers) if (name == key) return value;
    return {};
}
void contract() {
    auto now = agent::RunnerClock::now();
    agent::RescueSessions registry(agent::RescueSessions::Limits{}, [&] { return now; });
    TaskLimits limits; limits.background_workers = 1;
    TaskService tasks(limits);
    SessionStore sessions;
    ResourceCatalogs resources;
    resources.agent_rescue = agent_rescue(tasks, registry, [&] { return now; });
    bool rescue_requested = false;
    resources.agent_actions = {
        [&](const CallContext&, const Json::Value& value) { rescue_requested = value["rescue"].asBool(); return Json::Value(); },
        [](const CallContext&, const std::string&) { return Json::Value(); }
    };
    HttpApi api(sessions, {{"127.0.0.1:8080", "http://127.0.0.1:8080"}},
        [](const CallContext&) { Json::Value result; result["items"] = Json::Value(Json::arrayValue); return result; },
        {"epoch", {"test", "1"}}, {}, {}, {}, {}, false, {}, resources);
    auto request = [](std::string method, std::string path) {
        return HttpRequest{std::move(method), std::move(path), {{"Host", "127.0.0.1:8080"}, {"Origin", "http://127.0.0.1:8080"}}, {}};
    };
    auto login = request("POST", "/api/v1/session");
    login.headers.emplace_back("Content-Type", "application/json");
    Json::Value pairing; pairing["pairingToken"] = sessions.issue_pairing({"local-admin", true, true, true}).token;
    login.body = wire::stringify(pairing);
    const auto logged = api.handle(login); require(logged.status == 201);
    const auto session = wire::parse(logged.body);
    const auto cookie = header(logged, "Set-Cookie");
    const auto cookie_pair = cookie.substr(0, cookie.find(';'));
    const auto caller = sessions.authenticate(cookie_pair.substr(cookie_pair.find('=') + 1)).caller;
    auto authorized = [&](std::string method, std::string path) {
        auto value = request(std::move(method), std::move(path));
        value.headers.emplace_back("Cookie", cookie_pair);
        return value;
    };
    auto target = std::make_shared<Target>();
    const std::string disk = "12345678-1234-4234-8234-123456789abc";
    const auto id = registry.publish(caller, disk, target);
    require(valid_rescue_session_id(id));
    auto list = api.handle(authorized("GET", "/api/v1/agent-rescue-sessions"));
    require(list.status == 200);
    const auto rows = wire::parse(list.body);
    require(rows["items"].size() == 1 && rows["items"][0]["id"] == id
        && rows["items"][0]["remainingMs"].asUInt64() == 900000);
    const auto metadata = api.handle(authorized("GET", "/api/v1/agent-rescue-terminals/" + id));
    require(metadata.status == 200 && wire::parse(metadata.body)["vmId"] == id
        && wire::parse(metadata.body)["streams"] == wire::parse("[\"uart\"]"));
    require(api.terminal_source("/api/v1/agent-rescue-terminal") == resources.agent_rescue.terminal_source);
    require(!api.terminal_source("/api/v1/terminal"));
    auto socket = authorized("GET", "/api/v1/agent-rescue-terminal");
    require(api.authorize_terminal(socket, Json::Value()).caller.principal == caller.principal);
    auto foreign_origin = socket; foreign_origin.headers[1].second = "http://foreign.invalid";
    rejected([&] { api.authorize_terminal(foreign_origin, Json::Value()); });
    const CallContext other{"other", true, true, true};
    require(resources.agent_rescue.list(other)["items"].empty());
    rejected([&] { resources.agent_rescue.terminal_source->list(other, id); });
    const auto expected = target->observed;
    require(resources.agent_rescue.terminal_source->write(caller, {id, "uart", expected, "abcd"}) == 2 && target->input == "ab");
    rejected([&] { resources.agent_rescue.terminal_source->write(caller, {id, "agent", expected, "secret"}); });
    target->observed.revision++;
    rejected([&] { resources.agent_rescue.terminal_source->list(caller, id); });
    target->observed = expected;

    auto operation = authorized("POST", "/api/v1/agent-operations");
    operation.headers.emplace_back("Content-Type", "application/json");
    operation.headers.emplace_back("X-DroidVM-CSRF", session["csrfToken"].asString());
    Json::Value body; body["context"] = rows["context"]; body["requestId"] = "agent-rescue";
    body["revision"] = "disks"; body["vmRevision"] = "vms"; body["operation"]["action"] = "autogrow";
    body["operation"]["diskId"] = disk; body["rescue"] = true; operation.body = wire::stringify(body);
    require(api.handle(operation).status == 202 && rescue_requested);
    ResourceCatalogs incomplete = resources; incomplete.agent_rescue.close.find = {};
    HttpApi limited(sessions, {{"127.0.0.1:8080", "http://127.0.0.1:8080"}},
        [](const CallContext&) { return Json::Value(); }, {"epoch", {"test", "1"}}, {}, {}, {}, {}, false, {}, incomplete);
    require(limited.handle(operation).status == 501);
    body["rescue"] = false; operation.body = wire::stringify(body);
    require(limited.handle(operation).status == 202 && !rescue_requested);
    body["rescue"] = "true"; operation.body = wire::stringify(body);
    require(api.handle(operation).status == 400);

    target->cleanup = {true, false, false};
    auto close = authorized("POST", "/api/v1/agent-rescue-operations");
    close.headers.emplace_back("Content-Type", "application/json");
    Json::Value close_body; close_body["context"] = rows["context"]; close_body["requestId"] = "close"; close_body["sessionId"] = id;
    close.body = wire::stringify(close_body);
    require(api.handle(close).status == 403); // CSRF still required for close.
    close.headers.emplace_back("X-DroidVM-CSRF", session["csrfToken"].asString());
    auto accepted = api.handle(close); require(accepted.status == 202);
    const auto task_id = wire::parse(accepted.body)["task"]["id"].asString();
    auto task = finished(tasks, caller, task_id);
    require(task.state == TaskState::failed && task.resource == "agent-rescue:" + id);
    const auto lookup = api.handle(authorized("GET", "/api/v1/agent-rescue-operations/close"));
    require(lookup.status == 200 && wire::parse(lookup.body)["task"]["agentRescueCleanup"]["cleanup"]["removed"] == false);
    require(api.handle(close).status == 409);
    rejected([&] { resources.agent_rescue.terminal_source->list(caller, id); });
    auto raw = task.result; raw["private"] = "/host/path"; raw["cleanup"]["password"] = "secret";
    require(wire::stringify(project_agent_rescue_cleanup(raw)).find("secret") == std::string::npos);
    target->cleanup = {true, true, true}; close_body["requestId"] = "close-again"; close.body = wire::stringify(close_body);
    accepted = api.handle(close); require(accepted.status == 202);
    require(finished(tasks, caller, wire::parse(accepted.body)["task"]["id"].asString()).state == TaskState::succeeded);
    require(registry.list(caller).empty());
    auto expired = std::make_shared<Target>(); const auto expired_id = registry.publish(caller, disk, expired);
    now += 15min;
    rejected([&] { resources.agent_rescue.terminal_source->list(caller, expired_id); });
    require(resources.agent_rescue.list(caller)["items"][0]["expired"].asBool());
    registry.shutdown(); tasks.shutdown();
}
}
int main() {
    try { contract(); std::cout << "Agent rescue API contract passed\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
