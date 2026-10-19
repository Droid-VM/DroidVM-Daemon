// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/vm_operations.h"
#include "web/task_adapter.h"
#include "web/vm_read_model.h"
#include "common/wire.h"
#include <atomic>
#include <future>
#include <iostream>
#include <thread>

using namespace droidvm;
using namespace droidvm::web;
namespace {
const CallContext admin{"local-admin", true, true, true};
void check(bool value) { if (!value) throw std::runtime_error("VM operation contract failed"); }
TaskLimits limits() { TaskLimits value; value.background_workers = 1; return value; }
struct Fixture {
    std::atomic<int> effects{0};
    TaskService tasks{limits()};
    SessionStore sessions;
    SessionGrant grant = sessions.exchange(sessions.issue_pairing(admin).token);
    HttpApi api{sessions, {{"localhost:8080", "http://localhost:8080"}}, [](const auto&) { return Json::Value(); },
        {tasks.epoch(), {"test", "1"}}, {}, task_operations(tasks), vm_operations(tasks, [this](const auto& caller, const auto& request) {
            check(caller.principal == grant.session.caller.principal && caller.principal != "local-admin");
            if (request.observed.revision != 1) throw ServiceError(ErrorCode::conflict, "Private conflict detail");
            ++effects;
            if (request.action == "suspend") throw ServiceError(ErrorCode::commit_uncertain, "Private control detail");
        })};
    Json::Value input() {
        Json::Value value;
        value["context"]["daemonEpoch"] = tasks.epoch(); value["context"]["sessionId"] = grant.session.id;
        value["requestId"] = "request-1"; value["vmId"] = "vm-1"; value["action"] = "start";
        value["expected"]["instanceId"] = std::string(32, 'a'); value["expected"]["revision"] = "1";
        value["expected"]["configRevision"] = "config-1";
        return value;
    }
    HttpRequest request(std::string method = "POST", std::string path = "/api/v1/vm-operations") {
        return {std::move(method), std::move(path), {{"Host", "localhost:8080"}, {"Origin", "http://localhost:8080"},
            {"Cookie", "droidvm-session=" + grant.token}, {"Content-Type", "application/json"}, {"X-DroidVM-CSRF", grant.session.csrf}}, {}};
    }
    HttpResponse submit(Json::Value body) { auto req = request(); req.body = wire::stringify(body); return api.handle(req); }
    TaskView finish(const std::string& id) {
        for (int i = 0; i < 3000; ++i) {
            auto task = tasks.get(grant.session.caller, {tasks.epoch(), id});
            if (task_terminal(task.state)) return task;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        throw std::runtime_error("Task timeout");
    }
};
template<class F> void test(const char* name, F work) { work(); std::cout << "PASS " << name << '\n'; }
}
int main() {
    try {
        test("HTTP admission uses browser identity and existing task", [] {
            Fixture f; const auto response = f.submit(f.input()); check(response.status == 202);
            const auto task = wire::parse(response.body)["task"];
            check(task["requestId"] == "request-1" && task["kind"] == "vm_start" && task["resource"] == "vm:vm-1");
            check(f.finish(task["id"].asString()).state == TaskState::succeeded && f.effects == 1);
            auto lookup = f.api.handle(f.request("GET", "/api/v1/vm-operations/request-1"));
            check(lookup.status == 200 && wire::parse(lookup.body)["task"]["phase"] == "admitted");
            check(lookup.body.find("owner") == std::string::npos && lookup.body.find("signature") == std::string::npos);
        });
        test("concurrent duplicate requests admit one effect; changed payload conflicts", [] {
            Fixture f; std::vector<std::future<HttpResponse>> writes;
            for (int i = 0; i < 16; ++i) writes.push_back(std::async(std::launch::async, [&] { return f.submit(f.input()); }));
            std::string id;
            for (auto& write : writes) {
                const auto reply = write.get(); check(reply.status == 202);
                const auto next = wire::parse(reply.body)["task"]["id"].asString();
                if (id.empty()) id = next; check(next == id);
            }
            f.finish(id); check(f.effects == 1);
            auto input = f.input(); input["action"] = "stop"; check(f.submit(input).status == 409 && f.effects == 1);
            check(!f.tasks.find_request(admin, "request-1")); // Admin does not inherit another session's correlation.
        });
        test("CSRF origin context and strict payload reject before queueing", [] {
            Fixture f; auto request = f.request(); request.body = wire::stringify(f.input());
            request.headers.pop_back(); check(f.api.handle(request).status == 403);
            request = f.request(); request.body = wire::stringify(f.input()); request.headers[1].second = "http://evil.invalid";
            check(f.api.handle(request).status == 403);
            auto input = f.input(); input["context"]["daemonEpoch"] = "stale"; check(f.submit(input).status == 409);
            input = f.input(); input["context"]["sessionId"] = "other"; check(f.submit(input).status == 409);
            input = f.input(); input["expected"]["revision"] = "18446744073709551616"; check(f.submit(input).status == 400);
            input["expected"]["revision"] = "01"; check(f.submit(input).status == 400);
            input = f.input(); input["expected"]["configRevision"] = Json::Value(); check(f.submit(input).status == 400);
            input = f.input(); input["caller"] = "local-admin"; check(f.submit(input).status == 400);
            check(!f.tasks.find_request(f.grant.session.caller, "request-1") && f.effects == 0);
            check(f.api.handle(f.request("GET", "/api/v1/vm-operations/request-1?token=x")).status == 400);
            check(f.api.handle(f.request("GET")).status == 405);
        });
        test("stale observations and uncertain controls remain actual task outcomes", [] {
            Fixture f; auto input = f.input(); input["expected"]["revision"] = "0";
            auto reply = f.submit(input); check(reply.status == 202);
            auto task = f.finish(wire::parse(reply.body)["task"]["id"].asString());
            check(task.state == TaskState::failed && task.error == ErrorCode::conflict && f.effects == 0);
            input = f.input(); input["requestId"] = "request-2"; input["action"] = "suspend";
            reply = f.submit(input); check(reply.status == 202);
            task = f.finish(wire::parse(reply.body)["task"]["id"].asString());
            check(task.state == TaskState::failed && task.error == ErrorCode::commit_uncertain && f.effects == 1);
            const auto lookup = f.api.handle(f.request("GET", "/api/v1/vm-operations/request-2"));
            check(lookup.body.find("Private") == std::string::npos && wire::parse(lookup.body)["task"]["errorCode"] == "COMMIT_UNCERTAIN");
            check(wire::parse(f.api.handle(f.request("GET", "/api/v1/vm-operations/missing")).body)["task"].isNull());
        });
        test("queued cancellation never enters runtime", [] {
            Fixture f; std::promise<void> started, release; auto wait = release.get_future().share();
            const auto blocker = f.tasks.submit(admin, {"blocker", "", 4, true, true}, [&](TaskControl&) {
                started.set_value(); wait.wait(); return TaskCompletion::success();
            });
            started.get_future().wait();
            auto reply = f.submit(f.input()); const auto id = wire::parse(reply.body)["task"]["id"].asString();
            auto cancelled = f.tasks.cancel(f.grant.session.caller, {f.tasks.epoch(), id});
            release.set_value();
            check(cancelled.state == TaskState::cancelled && f.finish(id).state == TaskState::cancelled && f.effects == 0);
        });
        test("deduplication expires with task retention and remains owner scoped", [] {
            auto time = TaskService::Clock::now(); TaskLimits config; config.retention = std::chrono::milliseconds(10);
            TaskService tasks(config, [&] { return time; });
            TaskSpec spec{"operation", "vm", 4, true, false, "request", "signature"};
            auto work = [](TaskControl&) { return TaskCompletion::success(); };
            auto first = tasks.submit(admin, spec, work);
            tasks.shutdown(); // Terminal records remain queryable after shutdown.
            check(tasks.find_request(admin, "request")->ref.id == first.id);
            check(!tasks.find_request({"different", true, true, true}, "request"));
            time += std::chrono::seconds(1); check(!tasks.find_request(admin, "request"));
        });
        test("VM list projects observations and hides temporary start", [] {
            Json::Value rows(Json::arrayValue), row;
            row["id"] = "vm-1"; row["state"] = "STOPPED"; row["password"] = "secret";
            row["runtime_instance"] = std::string(32, 'a'); row["runtime_revision"] = "9007199254740993";
            row["runtime_uncertain"] = false; row["runtime_actions"].append("start"); rows.append(row);
            VmConfigSnapshot config; config.revision = "configuration"; config.document["vms"] = Json::Value(Json::arrayValue);
            check(vm_snapshot(rows, &config)["items"][0]["lifecycle"]["actions"].empty());
            config.document["vms"].append(row);
            const auto result = vm_snapshot(rows, &config);
            check(result["items"][0]["lifecycle"]["revision"] == "9007199254740993");
            check(result["items"][0]["lifecycle"]["actions"][0] == "start" && wire::stringify(result).find("secret") == std::string::npos);
        });
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
