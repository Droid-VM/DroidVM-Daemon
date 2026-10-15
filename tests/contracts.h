// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "services/tasks.h"
#include "common/wire.h"
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>

namespace droidvm::test {
using namespace std::chrono_literals;
inline const CallContext owner{"owner", true, true, false};
inline const CallContext other{"other", true, true, false};
inline const CallContext admin{"admin", true, true, true};
inline void check(bool value, const char* detail) { if (!value) throw std::runtime_error(detail); }
template<class F> void error(ErrorCode expected, F&& fn) {
    try { fn(); } catch (const ServiceError& actual) {
        check(actual.code() == expected, "wrong service error");
        return;
    }
    throw std::runtime_error("expected a service error");
}
struct Gate {
    std::mutex mutex;
    std::condition_variable ready;
    bool open = false;
    void release() { std::lock_guard lock(mutex); open = true; ready.notify_all(); }
    void wait() {
        std::unique_lock lock(mutex);
        check(ready.wait_for(lock, 5s, [&] { return open; }), "gate deadline");
    }
};
inline TaskView finished(TaskService& service, const TaskRef& ref, const CallContext& caller = owner) {
    const auto deadline = TaskService::Clock::now() + 5s;
    do {
        auto value = service.get(caller, ref);
        if (task_terminal(value.state)) return value;
        std::this_thread::sleep_for(1ms);
    } while (TaskService::Clock::now() < deadline);
    throw std::runtime_error("task deadline");
}
inline TaskSpec spec(size_t result_bytes = 256) { return {"contract", "vm:one", result_bytes, true}; }
inline TaskCompletion ok(TaskControl&) { return TaskCompletion::success(); }
inline int run(std::initializer_list<std::pair<const char*, void(*)()>> tests) {
    Json::Value report;
    auto& checks = report["checks"] = Json::Value(Json::arrayValue);
    try {
        for (auto [name, test] : tests) {
            report["current"] = name;
            test();
            checks.append(name);
        }
        report.removeMember("current");
        report["passed"] = true;
    } catch (const std::exception& e) {
        report["passed"] = false;
        report["error"] = e.what();
    }
    std::cout << wire::stringify(report, true) << std::endl;
    return report["passed"].asBool() ? 0 : 1;
}
}
