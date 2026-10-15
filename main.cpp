// SPDX-License-Identifier: GPL-3.0-or-later
#include "runtime/instance.h"
#include "runtime/layout.h"
#include "runtime/log.h"
#include "services/system.h"
#include "transport/server.h"
#include "transport/dispatcher.h"
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <iostream>
#include <stdexcept>
#include <memory>

int main(int argc, char** argv) {
    try {
        std::string directory, data_directory, apk;
        bool force = false;
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--help") {
                std::cout << "Usage: droidvmd (--data-dir <app-data-directory> | --run-dir <existing-directory>)\n"
                             "                --apk <installed-apk> [--force]\n"
                             "--data-dir creates run/ and cache/daemon.log owned by the data directory UID.\n"
                             "Development native daemon; system and task observation APIs only.\n";
                return 0;
            } else if (arg == "--force") force = true;
            else if (arg == "--run-dir" && i + 1 < argc) directory = argv[++i];
            else if (arg == "--data-dir" && i + 1 < argc) data_directory = argv[++i];
            else if (arg == "--apk" && i + 1 < argc) apk = argv[++i];
            else throw std::runtime_error("invalid arguments; use --help");
        }
        if ((directory.empty() == data_directory.empty()) || apk.empty())
            throw std::runtime_error("exactly one of --run-dir/--data-dir and --apk are required");
        sigset_t signals;
        sigemptyset(&signals);
        sigaddset(&signals, SIGINT);
        sigaddset(&signals, SIGTERM);
        if (sigprocmask(SIG_BLOCK, &signals, nullptr)) throw std::runtime_error("block signals failed");
        droidvm::Fd signal_fd(signalfd(-1, &signals, SFD_CLOEXEC | SFD_NONBLOCK));
        if (signal_fd.get() < 0) throw std::runtime_error("signalfd failed");
        prctl(PR_SET_NAME, "droidvmd");
        std::unique_ptr<droidvm::RuntimeLayout> layout;
        std::unique_ptr<droidvm::Instance> instance;
        if (!data_directory.empty()) {
            layout = std::make_unique<droidvm::RuntimeLayout>(data_directory);
            instance = std::make_unique<droidvm::Instance>(layout->take_run_directory(), force, layout->owner());
        } else instance = std::make_unique<droidvm::Instance>(directory, force);
        std::unique_ptr<droidvm::RuntimeLog> log;
        if (layout) {
            layout->prepare_cache();
            log = std::make_unique<droidvm::RuntimeLog>(layout->cache_fd(), layout->owner());
            log->write("INFO", "starting pid=" + std::to_string(getpid()));
        }
        try {
            const auto token = droidvm::random_id(false);
            const auto hash = droidvm::apk_sha256(apk); // fork before starting service threads.
            droidvm::TaskService tasks;
            droidvm::SystemService system([&] { return instance->token_exists(); }, [&] { return instance->read_token(); },
                                          hash, tasks.epoch());
            droidvm::RequestDispatcher dispatcher(system, tasks);
            const auto result = droidvm::serve(*instance, dispatcher, token.c_str(), signal_fd.get(), log.get());
            // Task teardown completes while both the instance lock and log are held.
            tasks.shutdown();
            if (log) log->write("INFO", "stopped exit=" + std::to_string(result));
            return result;
        } catch (const std::exception& error) {
            if (log) log->write("ERROR", error.what());
            throw;
        }
    } catch (const std::exception& error) {
        std::cerr << "droidvmd: " << error.what() << '\n';
        return 1;
    }
}
