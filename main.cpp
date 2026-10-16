// SPDX-License-Identifier: GPL-3.0-or-later
#include "runtime/instance.h"
#include "runtime/layout.h"
#include "runtime/log.h"
#include "services/system.h"
#include "network/switch_runtime.h"
#include "network/gvswitch.h"
#include "network/links.h"
#include "network/policy_rules.h"
#include "network/routes.h"
#include "network/firewall.h"
#include "network/linux_bridge.h"
#include "network/pd_ownership.h"
#include "network/ports.h"
#include "network/pbridge.h"
#include "network/host_watch.h"
#include "store/network_config.h"
#include "common/wire.h"
#include "transport/server.h"
#include "transport/dispatcher.h"
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <iostream>
#include <stdexcept>
#include <memory>
#include <filesystem>
#ifdef DROIDVM_NETWORK_DELAY_FIXTURE
#include <atomic>
#include <thread>
#endif

int main(int argc, char** argv) {
    try {
        std::string directory, data_directory, apk;
        bool force = false;
        droidvm::config::JsonFile::Observer observer;
#ifdef DROIDVM_NETWORK_DELAY_FIXTURE
        int write_delay_ms = 0;
#endif
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--help") {
                std::cout << "Usage: droidvmd (--data-dir <app-data-directory> | --run-dir <existing-directory>)\n"
                             "                --apk <installed-apk> [--force]\n"
                             "--data-dir creates run/ and cache/daemon.log owned by the data directory UID.\n"
                             "Development native daemon; system, tasks and network configuration APIs.\n";
                return 0;
            } else if (arg == "--force") force = true;
            else if (arg == "--run-dir" && i + 1 < argc) directory = argv[++i];
            else if (arg == "--data-dir" && i + 1 < argc) data_directory = argv[++i];
            else if (arg == "--apk" && i + 1 < argc) apk = argv[++i];
#ifdef DROIDVM_NETWORK_DELAY_FIXTURE
            else if (arg == "--test-write-delay-ms" && i + 1 < argc) {
                write_delay_ms = std::stoi(argv[++i]);
                if (write_delay_ms < 0 || write_delay_ms > 40000) throw std::runtime_error("invalid fixture delay");
            }
#endif
            else throw std::runtime_error("invalid arguments; use --help");
        }
        if ((directory.empty() == data_directory.empty()) || apk.empty())
            throw std::runtime_error("exactly one of --run-dir/--data-dir and --apk are required");
#ifdef DROIDVM_NETWORK_DELAY_FIXTURE
        auto first_write = std::make_shared<std::atomic<bool>>(true);
        observer = [first_write, write_delay_ms](const char* stage) {
            if (std::string_view(stage) == "before_write" && first_write->exchange(false)) {
                std::cerr << "fixture write delay started" << std::endl;
                std::this_thread::sleep_for(std::chrono::milliseconds(write_delay_ms));
            }
        };
#endif
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
            droidvm::network::SwitchRuntime switch_runtime(instance->directory_fd(), layout ? layout->owner() : getuid());
            const auto recovery_failures = switch_runtime.recover_all();
            if (!recovery_failures.empty())
                throw std::runtime_error("Network runtime recovery incomplete: " + droidvm::wire::stringify(recovery_failures));
            // Helpers are gone: finish their PD rule/route/sysctl cleanup.
            droidvm::network::PdOwnership pd_ownership(instance->directory_fd(), layout ? layout->owner() : getuid());
            const auto pd_failures = pd_ownership.recover_all();
            if (!pd_failures.empty())
                throw std::runtime_error("Network PD recovery incomplete: " + droidvm::wire::stringify(pd_failures));
            droidvm::network::Iptables iptables;
            droidvm::network::OwnedFirewall owned_firewall(instance->directory_fd(), layout ? layout->owner() : getuid(), iptables);
            std::unique_ptr<droidvm::network::Netbox> netbox;
            std::unique_ptr<droidvm::network::OwnedLinks> owned_links;
            std::unique_ptr<droidvm::network::OwnedRules> owned_rules;
            std::unique_ptr<droidvm::network::OwnedRoutes> owned_routes;
            std::unique_ptr<droidvm::network::OwnedPorts> owned_ports;
            std::unique_ptr<droidvm::network::PbridgeOwnership> owned_pbridge;
            if (layout) {
                netbox = std::make_unique<droidvm::network::Netbox>(
                    (std::filesystem::absolute(data_directory) / "bin/netbox").string());
                owned_links = std::make_unique<droidvm::network::OwnedLinks>(instance->directory_fd(), layout->owner(), *netbox);
                owned_rules = std::make_unique<droidvm::network::OwnedRules>(instance->directory_fd(), layout->owner(), *owned_links);
                const auto rule_failures = owned_rules->recover_all();
                if (!rule_failures.empty()) throw std::runtime_error("Network rule recovery incomplete: " + droidvm::wire::stringify(rule_failures));
                owned_routes = std::make_unique<droidvm::network::OwnedRoutes>(instance->directory_fd(), layout->owner(), *owned_links);
                // pbridge veth ends are foreign ports of owned bridges too.
                owned_pbridge = std::make_unique<droidvm::network::PbridgeOwnership>(instance->directory_fd(), layout->owner(), *netbox);
                const auto pbridge_failures = owned_pbridge->recover_all();
                if (!pbridge_failures.empty()) throw std::runtime_error("Network pbridge recovery incomplete: " + droidvm::wire::stringify(pbridge_failures));
                owned_ports = std::make_unique<droidvm::network::OwnedPorts>(instance->directory_fd(), layout->owner(), *netbox);
                const auto port_failures = owned_ports->recover_all(); // foreign uplinks leave owned bridges first
                if (!port_failures.empty()) throw std::runtime_error("Network port recovery incomplete: " + droidvm::wire::stringify(port_failures));
                const auto route_failures = owned_routes->recover_all();
                if (!route_failures.empty()) throw std::runtime_error("Network route recovery incomplete: " + droidvm::wire::stringify(route_failures));
                const auto failures = owned_links->recover_all();
                if (!failures.empty()) throw std::runtime_error("Network link recovery incomplete: " + droidvm::wire::stringify(failures));
            }
            // Retire stale guards only after their guest-facing links are gone.
            const auto firewall_failures = owned_firewall.recover_all();
            if (!firewall_failures.empty())
                throw std::runtime_error("Network firewall recovery incomplete: " + droidvm::wire::stringify(firewall_failures));
            droidvm::network::LinuxFirewall linux_firewall(owned_firewall);
            droidvm::Fd files;
            const auto token = droidvm::random_id(false);
            const auto hash = droidvm::apk_sha256(apk); // fork before starting service threads.
            std::unique_ptr<droidvm::NetworkConfigService> networks;
            std::unique_ptr<droidvm::NetworkHostService> host_network;
            std::unique_ptr<droidvm::NetworkService> network_runtime;
            std::unique_ptr<droidvm::network::HostIpv4Watch> host_ipv4;
            if (layout) {
                files = layout->open_files();
                networks = std::make_unique<droidvm::NetworkConfigService>(files.get(), layout->owner(), observer);
                host_network = std::make_unique<droidvm::NetworkHostService>(
                    (std::filesystem::absolute(data_directory) / "bin/netbox").string());
                const auto binaries = std::filesystem::absolute(data_directory) / "bin";
                network_runtime = std::make_unique<droidvm::NetworkService>(*networks,
                    [&, binaries](const Json::Value& config) -> std::unique_ptr<droidvm::network::Backend> {
                        if (droidvm::config::string(config, "bridge_type") == "gvisor")
                            return std::make_unique<droidvm::network::Gvswitch>((binaries / "gvswitch").string(), switch_runtime);
                        return std::make_unique<droidvm::network::LinuxBridge>(droidvm::network::LinuxBridge::Resources{
                            *netbox, *owned_links, *owned_rules, *owned_routes, linux_firewall, pd_ownership, *owned_ports, *owned_pbridge, switch_runtime,
                            (binaries / "bridgedhcp").string(), (binaries / "pbridge").string(), files.get()});
                    });
                network_runtime->request_autostart({"network-autostart", true, true, true});
                host_ipv4 = std::make_unique<droidvm::network::HostIpv4Watch>(*netbox, switch_runtime, [&](const std::vector<std::string>& addresses) {
                    linux_firewall.set_host_ipv4(addresses);
                    std::string text;
                    for (const auto& address : addresses) text += (text.empty() ? "" : ",") + address;
                    if (log) log->write("INFO", "host IPv4 set [" + text + "]");
                });
                if (log && networks->recovered()) log->write("WARN", "network configuration recovered from backup");
                if (log && networks->inactive()) log->write("WARN", "inactive network configurations retained: " + std::to_string(networks->inactive()));
            }
            droidvm::TaskService tasks;
            droidvm::SystemService system([&] { return instance->token_exists(); }, [&] { return instance->read_token(); },
                                          hash, tasks.epoch());
            droidvm::RequestDispatcher dispatcher(system, tasks, networks.get(), host_network.get(), network_runtime.get(), host_ipv4.get());
            const auto result = droidvm::serve(*instance, dispatcher, token.c_str(), signal_fd.get(), log.get());
            // Task teardown completes while both the instance lock and log are held.
            tasks.shutdown();
            if (host_ipv4) host_ipv4->stop();
            if (network_runtime) {
                const auto failures = network_runtime->shutdown();
                if (!failures.empty()) throw std::runtime_error("Network shutdown incomplete: " + droidvm::wire::stringify(failures));
                linux_firewall.stop(); // every Linux network was removed above
            }
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
