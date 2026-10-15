// SPDX-License-Identifier: GPL-3.0-or-later
#include "runtime/instance.h"
#include "services/system.h"
#include "transport/server.h"
#include "transport/dispatcher.h"
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <iostream>
#include <stdexcept>

int main(int argc, char** argv) {
    try {
        std::string directory, apk;
        bool force = false;
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--help") {
                std::cout << "Usage: droidvmd --run-dir <existing-directory> --apk <installed-apk> [--force]\n"
                             "Development native daemon; system and task observation APIs only.\n";
                return 0;
            } else if (arg == "--force") force = true;
            else if (arg == "--run-dir" && i + 1 < argc) directory = argv[++i];
            else if (arg == "--apk" && i + 1 < argc) apk = argv[++i];
            else throw std::runtime_error("invalid arguments; use --help");
        }
        if (directory.empty() || apk.empty()) throw std::runtime_error("--run-dir and --apk are required");
        sigset_t signals;
        sigemptyset(&signals);
        sigaddset(&signals, SIGINT);
        sigaddset(&signals, SIGTERM);
        if (sigprocmask(SIG_BLOCK, &signals, nullptr)) throw std::runtime_error("block signals failed");
        droidvm::Fd signal_fd(signalfd(-1, &signals, SFD_CLOEXEC | SFD_NONBLOCK));
        if (signal_fd.get() < 0) throw std::runtime_error("signalfd failed");
        prctl(PR_SET_NAME, "droidvmd");
        droidvm::Instance instance(directory, force);
        const auto token = droidvm::random_id(false);
        const auto hash = droidvm::apk_sha256(apk); // fork before starting service threads.
        droidvm::TaskService tasks;
        droidvm::SystemService system([&] { return instance.token_exists(); }, [&] { return instance.read_token(); },
                                      hash, tasks.epoch());
        droidvm::RequestDispatcher dispatcher(system, tasks);
        return droidvm::serve(instance, dispatcher, token.c_str(), signal_fd.get());
    } catch (const std::exception& error) {
        std::cerr << "droidvmd: " << error.what() << '\n';
        return 1;
    }
}
