// SPDX-License-Identifier: GPL-3.0-or-later
// Test-only producer; the production daemon exposes no arbitrary-work command.
#include "runtime/instance.h"
#include "transport/dispatcher.h"
#include "transport/server.h"
#include <sys/signalfd.h>
#include <signal.h>
#include <iostream>
#include <thread>

int main(int argc, char** argv) {
    try {
        if (argc != 3) throw std::runtime_error("Usage: fixture <isolated-run-dir> <apk>");
        sigset_t signals;
        sigemptyset(&signals);
        sigaddset(&signals, SIGINT);
        sigaddset(&signals, SIGTERM);
        if (sigprocmask(SIG_BLOCK, &signals, nullptr)) throw std::runtime_error("block signals failed");
        droidvm::Fd signal_fd(signalfd(-1, &signals, SFD_CLOEXEC | SFD_NONBLOCK));
        if (signal_fd.get() < 0) throw std::runtime_error("signalfd failed");
        droidvm::Instance instance(argv[1], false);
        const auto hash = droidvm::apk_sha256(argv[2]);
        droidvm::TaskLimits limits;
        limits.workers = 1;
        droidvm::EventLimits event_limits;
        event_limits.events = 64; // Force history eviction within a short test.
        droidvm::TaskService tasks(limits, [] { return droidvm::TaskService::Clock::now(); }, event_limits);
        const droidvm::CallContext owner{"local-admin", true, true, true};
        tasks.submit(owner, {"migration.running", "isolated", 256, true}, [](droidvm::TaskControl& control) {
            const auto deadline = droidvm::TaskService::Clock::now() + std::chrono::seconds(70);
            uint64_t progress = 0;
            while (droidvm::TaskService::Clock::now() < deadline) {
                if (control.cancellation_requested()) return droidvm::TaskCompletion::cancelled();
                control.progress({"waiting", "ticks", ++progress, {}});
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
            return droidvm::TaskCompletion::failure(droidvm::ErrorCode::unavailable, "Fixture deadline");
        });
        tasks.submit(owner, {"migration.queued", "isolated", 256, true}, [](droidvm::TaskControl&) {
            return droidvm::TaskCompletion::failure(droidvm::ErrorCode::internal, "Queued fixture must be cancelled");
        });
        tasks.submit(owner, {"migration.result", "isolated", 256, true}, [](droidvm::TaskControl&) {
            Json::Value result;
            result["unicode"] = "任务 🧪";
            result["integer"] = Json::Int64(INT64_MAX);
            result["array"] = Json::Value(Json::arrayValue);
            return droidvm::TaskCompletion::success(result);
        });
        droidvm::SystemService system([&] { return instance.token_exists(); }, [&] { return instance.read_token(); }, hash, tasks.epoch());
        droidvm::RequestDispatcher dispatcher(system, tasks);
        const auto token = droidvm::random_id(false);
        return droidvm::serve(instance, dispatcher, token.c_str(), signal_fd.get());
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
