// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/task_adapter.h"
#include "web/task_receipts.h"
#include "common/wire.h"
#include <iostream>
#include <thread>
#include <future>
#include <atomic>

using namespace droidvm;
using namespace droidvm::web;
namespace {
const CallContext local{"local-admin", true, true, true};
void require(bool value) { if (!value) throw std::runtime_error("Task API contract assertion failed"); }
struct Fixture {
    TaskService tasks;
    SessionStore sessions;
    SessionGrant grant = sessions.exchange(sessions.issue_pairing(local).token);
    HttpApi api{sessions, {{"localhost:8080", "http://localhost:8080"}}, [](const auto&) { return Json::Value(); },
        {tasks.epoch(), {"test", "1"}}, {}, task_operations(tasks)};
    HttpRequest request(std::string method, std::string path = "/api/v1/tasks") {
        return {std::move(method), std::move(path), {{"Host", "localhost:8080"}, {"Origin", "http://localhost:8080"},
            {"Cookie", "droidvm-session=" + grant.token}, {"Content-Type", "application/json"}, {"X-DroidVM-CSRF", grant.session.csrf}}, {}};
    }
    HttpRequest cancel(const std::string& id) {
        auto req = request("POST", "/api/v1/tasks/cancel");
        Json::Value input;
        input["context"]["daemonEpoch"] = tasks.epoch(); input["context"]["sessionId"] = grant.session.id;
        input["taskId"] = id; req.body = wire::stringify(input); return req;
    }
};
TaskView finished(TaskService& tasks, const CallContext& caller, const TaskRef& ref) {
    for (size_t i = 0; i < 2000; ++i) {
        auto view = tasks.get(caller, ref);
        if (task_terminal(view.state)) return view;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    throw std::runtime_error("Task did not finish");
}
size_t passed = 0;
template<class F> void test(const char* name, F run) { run(); ++passed; std::cout << "PASS " << name << '\n'; }
}
int main() {
    try {
        test("receipt survives task expiry restart and a new authenticated administrator", [] {
            Json::Value saved;
            TaskReceiptPersistence persistence{[&] { return saved; }, [&](const Json::Value& value) { saved = value; }};
            TaskLimits limits; limits.retention = std::chrono::milliseconds(0);
            TaskService tasks(limits);
            bind_task_receipts(tasks, persistence);
            const auto host = tasks.receipt_host_id(), epoch = tasks.epoch();
            TaskSpec spec{"vm_configuration", "vms"};
            spec.request_id = "configuration-request"; spec.request_signature = "private-upload-signature";
            std::promise<void> ran;
            auto entered = ran.get_future();
            tasks.submit(local, spec, [&](TaskControl& control) {
                require(control.enter_commit());
                ran.set_value();
                return TaskCompletion::success(wire::parse(R"({"revision":"revision","persisted":true,"recovered":false,"durabilityUncertain":false,"password":"private-result"})"));
            });
            entered.wait(); tasks.shutdown();
            const CallContext next{"web:next-session", true, true, true};
            require(!tasks.find_request(next, spec.request_id));
            require(tasks.receipt(next, spec.request_id)["status"] == "terminal");
            require(wire::stringify(saved).find("private-") == std::string::npos);
            TaskService restarted;
            bind_task_receipts(restarted, persistence);
            require(restarted.receipt_host_id() == host && restarted.epoch() != epoch);
            const auto result = restarted.receipt(next, spec.request_id);
            require(result["epoch"] == epoch && result["status"] == "terminal");
            require(result["version"]["revision"] == "revision" && result["task"]["state"] == "succeeded");
            require(!result["task"]["cancellable"].asBool() && restarted.receipt(next, "missing").isNull());
            try { restarted.receipt({"reader", true, true, false}, spec.request_id); require(false); }
            catch (const ServiceError& error) { require(error.code() == ErrorCode::permission_denied); }
            try { restarted.receipt({"reader", false, true, true}, spec.request_id); require(false); }
            catch (const ServiceError& error) { require(error.code() == ErrorCode::unauthenticated); }
        });
        test("receipt persistence failure never starts work or invents a durable terminal outcome", [] {
            Json::Value saved;
            TaskService tasks;
            bool fail_start = false, fail_finish = false;
            bind_task_receipts(tasks, {[&] { return saved; }, [&](const Json::Value& value) {
                if (fail_start || (fail_finish && !value["records"].empty() &&
                    value["records"][value["records"].size() - 1]["receipt"]["status"] == "terminal"))
                    throw ServiceError(ErrorCode::io_error, "Receipt store unavailable");
                saved = value;
            }});
            TaskSpec spec{"agent_operation", "disk"};
            spec.request_id = "never-started"; spec.request_signature = "private-password";
            fail_start = true;
            std::atomic<int> effects{0};
            auto ref = tasks.submit(local, spec, [&](TaskControl&) { ++effects; return TaskCompletion::success(); });
            require(finished(tasks, local, ref).state == TaskState::failed && effects == 0);
            // Wait for the failed final callback before changing fault injection.
            tasks.shutdown();
            TaskService second;
            fail_start = false; fail_finish = true;
            bind_task_receipts(second, {[&] { return saved; }, [&](const Json::Value& value) {
                if (!value["records"].empty() && value["records"][value["records"].size() - 1]["receipt"]["status"] == "terminal")
                    throw ServiceError(ErrorCode::io_error, "Final receipt write unavailable");
                saved = value;
            }});
            spec.request_id = "uncertain-after-restart";
            ref = second.submit(local, spec, [&](TaskControl& control) { require(control.enter_commit()); ++effects; return TaskCompletion::success(); });
            require(finished(second, local, ref).state == TaskState::succeeded);
            second.shutdown();
            TaskService restarted;
            bind_task_receipts(restarted, {[&] { return saved; }, [&](const Json::Value& value) { saved = value; }});
            const auto result = restarted.receipt(local, spec.request_id);
            require(effects == 1 && result["status"] == "unknown" && result["epoch"] == second.epoch());
            spec.request_id = "rescue-lease";
            ref = restarted.submit(local, spec, [](TaskControl&) {
                auto value = wire::parse(R"({"diskId":"12345678-1234-1234-1234-123456789abc","action":"autogrow",
                    "outcome":"rescue_ready","guestOutcome":"pending","guestCode":null,"guestCleanup":"pending",
                    "cleanup":{"stopped":false,"removed":false,"diskSynced":false},"durabilityConfirmed":false,
                    "committed":true,"reason":"none","recoveryRequired":false,"actions":[]})");
                value["rescueSessionId"] = std::string(64, 'a');
                TaskView projected; projected.kind = "agent_operation"; projected.state = TaskState::succeeded; projected.result = value;
                require(task_view(projected)["agentResult"]["outcome"] == "rescue_ready");
                return TaskCompletion::success(value);
            });
            require(finished(restarted, local, ref).state == TaskState::succeeded);
            restarted.shutdown();
            const auto rescue = restarted.receipt(local, spec.request_id);
            require(rescue["status"] == "unknown" && !rescue["task"].isMember("agentResult"));
            require(wire::stringify(saved).find("rescueSessionId") == std::string::npos);
        });
        test("receipt HTTP reads authenticate and keep active work in its original epoch", [] {
            Json::Value saved;
            TaskService tasks;
            bind_task_receipts(tasks, {[&] { return saved; }, [&](const Json::Value& value) { saved = value; }});
            SessionStore sessions;
            const auto grant = sessions.exchange(sessions.issue_pairing(local).token);
            HttpApi api{sessions, {{"localhost:8080", "http://localhost:8080"}}, [](const auto&) { return Json::Value(); },
                {tasks.epoch(), {"test", "1"}}, {}, task_operations(tasks)};
            TaskSpec spec{"disk_operation", "disk"}; spec.request_id = "disk-request"; spec.request_signature = "resize";
            tasks.submit(local, spec, [](TaskControl& control) {
                while (!control.cancellation_requested()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
                return TaskCompletion::cancelled();
            });
            HttpRequest request{"GET", "/api/v1/tasks/receipts/disk-request", {{"Host", "localhost:8080"},
                {"Origin", "http://localhost:8080"}, {"Cookie", "droidvm-session=" + grant.token}}, {}};
            auto response = api.handle(request);
            require(response.status == 200);
            const auto result = wire::parse(response.body);
            require(result["hostId"] == tasks.receipt_host_id() && result["receipt"]["status"] == "active");
            require(result["receipt"]["epoch"] == tasks.epoch() && result["context"]["sessionId"] == grant.session.id);
            request.headers.pop_back(); require(api.handle(request).status == 401);
            tasks.shutdown();
        });
        test("snapshot uses existing tasks and redacts private fields", [] {
            Fixture f;
            auto ref = f.tasks.submit(local, {"test.success", "vm-id"}, [](TaskControl&) {
                Json::Value result; result["password"] = "private-result"; return TaskCompletion::success(result);
            });
            finished(f.tasks, local, ref);
            auto fail = f.tasks.submit(local, {"test.failure", "vm-id"}, [](TaskControl&) {
                return TaskCompletion::failure(ErrorCode::io_error, "private-path-or-credential");
            });
            finished(f.tasks, local, fail);
            for (size_t i = 0; i < 20; ++i) { // More than the existing snapshot quota: every read releases it.
                const auto response = f.api.handle(f.request("GET")); require(response.status == 200);
                require(response.body.find("private-") == std::string::npos && response.body.find("owner") == std::string::npos);
                const auto data = wire::parse(response.body);
                require(data["items"].size() == 2 && data["cursor"]["epoch"] == f.tasks.epoch());
                require(data["context"]["sessionId"] == f.grant.session.id && data["cursor"]["sequence"].isString());
                bool found = false;
                for (const auto& row : data["items"]) if (row["id"] == fail.id) { require(row["errorCode"] == "IO_ERROR"); found = true; }
                require(found);
            }
        });
        test("Agent terminal receipts have a strict projection even on failure", [] {
            TaskView task;
            task.ref = {"epoch", "agent-task"}; task.kind = "agent_operation";
            task.state = TaskState::failed; task.result_available = true;
            task.result = wire::parse(R"({
                "diskId":"12345678-1234-1234-1234-123456789abc","action":"chpasswd",
                "outcome":"uncertain","guestOutcome":"succeeded","guestCode":null,
                "guestCleanup":"failed","cleanup":{"stopped":true,"removed":true,"diskSynced":true,"path":"private-host-path"},
                "durabilityConfirmed":false,"committed":true,"reason":"guest_cleanup_failed","recoveryRequired":false,
                "actions":[{"action":"chpasswd","state":"succeeded","code":null,"password":"private-action-secret"}],
                "password":"private-root-secret","serial":"private-uart-output"
            })");
            const auto view = task_view(task);
            require(view["agentResult"]["guestOutcome"] == "succeeded" && view["agentResult"]["outcome"] == "uncertain");
            require(view["state"] == "failed" && view["resultAvailable"].asBool());
            require(wire::stringify(view).find("private-") == std::string::npos && !view.isMember("result"));
            const auto original = task.result;
            task.result["actions"][0]["code"] = "private-guest-diagnostic";
            require(!task_view(task).isMember("agentResult")); // No fallback to raw result.
            task.result = original; task.result["outcome"] = "succeeded";
            require(!task_view(task).isMember("agentResult")); // Guest success alone is insufficient.
            task.result = original; task.state = TaskState::running;
            require(!task_view(task).isMember("agentResult"));
            task.state = TaskState::failed; task.kind = "unrelated_operation";
            require(!task_view(task).isMember("agentResult"));
            task.kind = "agent_operation"; task.state = TaskState::cancelled;
            task.result["outcome"] = "cancelled"; task.result["guestOutcome"] = "pending";
            task.result["guestCleanup"] = "not_required"; task.result["committed"] = false;
            task.result["reason"] = "cancelled";
            require(task_view(task)["agentResult"]["outcome"] == "cancelled");
        });
        test("Agent recovery exposes only bounded terminal pending counts", [] {
            TaskView task;
            task.kind = "agent_recovery"; task.state = TaskState::succeeded;
            task.result["pendingRecords"] = 3; task.result["records"] = "private-recovery-paths";
            const auto view = task_view(task);
            require(view["pendingRecords"] == 3 && wire::stringify(view).find("private-") == std::string::npos);
            task.result["pendingRecords"] = 65;
            require(!task_view(task).isMember("pendingRecords"));
        });
        test("authentication origin method and unsupported routes never change tasks", [] {
            Fixture f; auto req = f.request("GET"); req.headers.erase(req.headers.begin() + 2);
            require(f.api.handle(req).status == 401);
            req = f.request("GET"); req.headers[1].second = "http://other.invalid"; require(f.api.handle(req).status == 403);
            require(f.api.handle(f.request("POST")).status == 405);
            require(f.api.handle(f.request("GET", "/api/v1/tasks?token=secret")).status == 404);
            require(f.api.handle(f.request("GET", "/api/v1/tasks/cancel")).status == 405);
        });
        test("cancellation binds CSRF daemon and session before admission", [] {
            Fixture f;
            auto ref = f.tasks.submit(local, {"test.wait", "vm-id"}, [](TaskControl& control) {
                while (!control.cancellation_requested()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
                return TaskCompletion::cancelled();
            });
            auto req = f.cancel(ref.id); req.headers.pop_back(); require(f.api.handle(req).status == 403);
            req = f.cancel(ref.id); auto body = wire::parse(req.body); body["context"]["daemonEpoch"] = "stale"; req.body = wire::stringify(body);
            require(f.api.handle(req).status == 409);
            body["context"]["daemonEpoch"] = f.tasks.epoch(); body["context"]["sessionId"] = "another-session"; req.body = wire::stringify(body);
            require(f.api.handle(req).status == 409);
            require(f.tasks.get(local, ref).cancellable);
            req = f.cancel(ref.id); body = wire::parse(req.body); body["role"] = "local-admin"; req.body = wire::stringify(body);
            require(f.api.handle(req).status == 400);
            require(f.api.handle(f.cancel(ref.id)).status == 200);
            require(finished(f.tasks, local, ref).state == TaskState::cancelled);
        });
        test("unknown tasks and irreversible phases are explicit", [] {
            Fixture f;
            require(f.api.handle(f.cancel("unknown-task")).status == 404);
            auto ref = f.tasks.submit(local, {"test.done", "vm-id"}, [](TaskControl&) { return TaskCompletion::success(); });
            finished(f.tasks, local, ref);
            const auto done = f.api.handle(f.cancel(ref.id));
            require(done.status == 200 && wire::parse(done.body)["task"]["state"] == "succeeded");
            std::promise<void> entered;
            auto running = f.tasks.submit(local, {"test.commit", "vm-id"}, [&entered](TaskControl& control) {
                require(control.enter_commit()); entered.set_value();
                std::this_thread::sleep_for(std::chrono::milliseconds(100)); return TaskCompletion::success();
            });
            entered.get_future().wait();
            require(f.api.handle(f.cancel(running.id)).status == 409);
            finished(f.tasks, local, running);
            auto req = f.cancel("bad/task"); require(f.api.handle(req).status == 400);
        });
        test("non-admin task scope remains enforced by existing service", [] {
            Fixture f;
            const CallContext owner{"owner", true, true, false}, other{"other", true, true, false};
            auto ref = f.tasks.submit(owner, {"test.private", "vm-id"}, [](TaskControl&) { return TaskCompletion::success(); });
            finished(f.tasks, owner, ref);
            auto operations = task_operations(f.tasks);
            require(operations.list(owner)["items"].size() == 1 && operations.list(other)["items"].empty());
            try { operations.cancel(other, ref.id); require(false); }
            catch (const ServiceError& error) { require(error.code() == ErrorCode::permission_denied); }
        });
        test("bounded view consumes fixed pages and releases snapshots on quota failure", [] {
            TaskLimits limits; limits.records = 1100; limits.queued = 1100;
            EventLimits events; events.max_snapshot_bytes = 32u << 20; events.snapshot_bytes = 64u << 20;
            TaskService tasks(limits, TaskService::Clock::now, events);
            auto operations = task_operations(tasks);
            for (size_t i = 0; i < 1025; ++i) {
                tasks.submit(local, {"test.paged", std::string(256, 'x'), 4}, [](TaskControl&) { return TaskCompletion::success(); });
                if (i == 599) {
                    auto page = tasks.snapshot(local); require(page.next.has_value()); tasks.release_snapshot(local, page.id);
                    require(operations.list(local)["items"].size() == 600);
                }
            }
            for (size_t i = 0; i < 20; ++i) {
                try { operations.list(local); require(false); }
                catch (const ServiceError& error) { require(error.code() == ErrorCode::resource_exhausted); }
                auto page = tasks.snapshot(local); tasks.release_snapshot(local, page.id);
            }
        });
        std::cout << passed << " task API groups passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
