// SPDX-License-Identifier: GPL-3.0-or-later
#include "runtime/instance.h"
#include "transport/dispatcher.h"
#include "transport/server.h"
#include <signal.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <iostream>
#include <atomic>

namespace {
// This fixture never creates host networking or helper processes.
class MemoryBackend final : public droidvm::network::Backend {
public:
    void start(const Json::Value&) override { running_ = true; }
    bool healthy() const override { return running_; }
    void recover(const Json::Value& value) override { start(value); }
    void stop() override { running_ = false; }
private:
    bool running_ = false;
};
}

int main(int argc, char** argv) {
    try {
        const bool vm_disks = argc >= 4 && std::string_view(argv[3]) == "--vm-disks";
        const bool coordinated = vm_disks || (argc >= 4 && std::string_view(argv[3]) == "--coordinated");
        const bool disk_config = argc == 4 && std::string_view(argv[3]) == "--disk-config";
        if (!(argc == 3 || disk_config || (coordinated && (argc == 4 || argc == 6))))
            throw std::runtime_error("Usage: vm-config-fixture <isolated-directory> <apk> [--disk-config | --coordinated|--vm-disks [--fail-once|--crash-once <stage>]]");
        std::string fault;
        bool crash = false;
        if (argc == 6) {
            crash = std::string_view(argv[4]) == "--crash-once";
            if (!crash && std::string_view(argv[4]) != "--fail-once") throw std::runtime_error("Unknown injection mode");
            fault = argv[5];
            if (fault != "before_decision" && fault != "participant_synced" && fault != "decision_removed")
                throw std::runtime_error("Unknown injection stage");
        }
        std::atomic<bool> injected{false};
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
        auto gate = coordinated || disk_config ? std::make_shared<droidvm::ConfigurationGate>() : nullptr;
        context.configuration_gate = gate;
        droidvm::VmService inventory(context);
        droidvm::TaskLimits limits;
        if (vm_disks) limits.background_workers = 1; // disk operations
        droidvm::TaskService tasks(limits, [] { return droidvm::TaskService::Clock::now(); }, {}, gate);
        std::unique_ptr<droidvm::VmConfigService> configs;
        std::unique_ptr<droidvm::ConfigurationService> configuration;
        std::unique_ptr<droidvm::NetworkService> networks;
        std::unique_ptr<droidvm::DiskConfigService> disks;
        if (coordinated) {
            configuration = std::make_unique<droidvm::ConfigurationService>(instance.directory_fd(), getuid(), gate, inventory, tasks,
                [&](const char* stage, size_t) {
                    if (fault != stage || injected.exchange(true)) return;
                    if (crash) { ::kill(getpid(), SIGKILL); ::_exit(137); }
                    throw std::runtime_error("fixture transaction fault: " + fault);
                }, vm_disks);
            networks = std::make_unique<droidvm::NetworkService>(configuration->networks(), [](const Json::Value& value) {
                if (droidvm::config::string(value, "bridge_type") != "gvisor" || !droidvm::network::l3_vlans(value).empty())
                    throw std::runtime_error("fixture only supports gvisor without VLANs");
                return std::make_unique<MemoryBackend>();
            });
        } else {
            configs = std::make_unique<droidvm::VmConfigService>(instance.directory_fd(), getuid(), droidvm::config::JsonFile::Observer{},
                [&](const Json::Value& value) { return inventory.prepare_config(value); }, &tasks, gate);
        }
        if (disk_config) disks = std::make_unique<droidvm::DiskConfigService>(instance.directory_fd(), getuid(),
            droidvm::config::JsonFile::Observer{}, gate, droidvm::DiskConfigService::Prepare{}, &tasks);
        droidvm::SystemService system([&] { return instance.token_exists(); }, [&] { return instance.read_token(); }, hash, tasks.epoch());
        droidvm::RequestDispatcher dispatcher(system, tasks, configuration ? &configuration->networks() : nullptr, nullptr, networks.get(), nullptr, &inventory);
        if (configuration) dispatcher.set_configuration(configuration.get());
        else dispatcher.set_vm_config(configs.get());
        // The runner provides <isolated-directory>/usr/bin/qemu-img; images stay in test paths.
        std::unique_ptr<droidvm::pkg::DiskOperationService> operations;
        if (vm_disks) {
            droidvm::pkg::DiskOperationContext operation_context;
            operation_context.configuration = configuration.get();
            operation_context.data_dir = argv[1];
            operation_context.directory = instance.directory_fd(); operation_context.owner = getuid();
            operations = std::make_unique<droidvm::pkg::DiskOperationService>(std::move(operation_context));
            dispatcher.set_disk_operations(operations.get());
        }
        if (disks) dispatcher.set_disk_config(disks.get());
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
