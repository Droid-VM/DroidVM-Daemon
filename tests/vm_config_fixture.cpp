// SPDX-License-Identifier: GPL-3.0-or-later
#include "runtime/instance.h"
#include "transport/dispatcher.h"
#include "transport/server.h"
#include <signal.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <iostream>

int main(int argc, char** argv) {
    try {
        if (argc != 3) throw std::runtime_error("Usage: vm-config-fixture <isolated-directory> <apk>");
        sigset_t signals;
        sigemptyset(&signals); sigaddset(&signals, SIGINT); sigaddset(&signals, SIGTERM);
        if (sigprocmask(SIG_BLOCK, &signals, nullptr)) throw std::runtime_error("block signals failed");
        droidvm::Fd signal(signalfd(-1, &signals, SFD_CLOEXEC | SFD_NONBLOCK));
        if (signal.get() < 0) throw std::runtime_error("signalfd failed");
        droidvm::Instance instance(argv[1], false);
        const auto hash = droidvm::apk_sha256(argv[2]);
        droidvm::vm::RuntimeContext context;
        context.cache_dir = argv[1]; context.owner = getuid();
        context.shutting_down = [] { return true; }; // no VMM/TAP/hugepage side effects
        droidvm::VmService inventory(context);
        droidvm::TaskService tasks;
        droidvm::VmConfigService configs(instance.directory_fd(), getuid(), {},
            [&](const Json::Value& value) { return inventory.prepare_config(value); }, &tasks);
        droidvm::SystemService system([&] { return instance.token_exists(); }, [&] { return instance.read_token(); }, hash, tasks.epoch());
        droidvm::RequestDispatcher dispatcher(system, tasks, nullptr, nullptr, nullptr, nullptr, &inventory);
        dispatcher.set_vm_config(&configs);
        const auto token = droidvm::random_id(false);
        try {
            const auto result = droidvm::serve(instance, dispatcher, token.c_str(), signal.get());
            tasks.shutdown(); // callbacks finish while configs/dispatcher still exist
            return result;
        } catch (...) { tasks.shutdown(); throw; }
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
