// SPDX-License-Identifier: GPL-3.0-or-later
#include "runtime/instance.h"
#include "store/vm_ownership.h"
#include "runtime/layout.h"
#include "runtime/log.h"
#include "runtime/cleanup.h"
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
#include "services/vm.h"
#include "services/legacy_events.h"
#include "input/keyboard_grab.h"
#include "usb/service.h"
#include "usb/watch.h"
#include "pkg/service.h"
#include "pkg/disk_operation.h"
#include "services/configuration.h"
#include "vm/host_facts.h"
#ifdef DROIDVM_PLATFORM_SERVICES
#include "audio_table.h"
#include "display_broker.h"
#endif
#include <fcntl.h>
#include "vm/command_common.h"
#include "vm/hugepage.h"
#include "vm/nic.h"
#include "build_metadata.h"
#include <fstream>
#include <sys/stat.h>
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

namespace {
// The VM store as UsbPassthroughManager reads it: fresh state on every call.
class UsbVmStore final : public droidvm::usb::UsbVms {
public:
    explicit UsbVmStore(std::unique_ptr<droidvm::VmService>& vms) : vms_(vms) {}
    std::optional<droidvm::usb::UsbVm> find(const std::string& id) const override {
        if (!vms_) return std::nullopt;
        try { return row(vms_->runtime(caller_, id)); } catch (const std::exception&) { return std::nullopt; }
    }
    std::vector<droidvm::usb::UsbVm> list() const override {
        std::vector<droidvm::usb::UsbVm> rows;
        if (!vms_) return rows;
        for (const auto& item : vms_->list(caller_))
            if (auto vm = find(droidvm::config::string(item, "id"))) rows.push_back(std::move(*vm));
        return rows;
    }
    std::optional<uint64_t> stderr_mark(const std::string& id) const override {
        try { if (auto* log = vms_->runtime(caller_, id)->log("stderr")) return log->mark(); } catch (const std::exception&) {}
        return std::nullopt;
    }
    std::string stderr_since(const std::string& id, uint64_t mark) const override {
        try { if (auto* log = vms_->runtime(caller_, id)->log("stderr")) return log->since(mark); } catch (const std::exception&) {}
        return {};
    }
private:
    std::unique_ptr<droidvm::VmService>& vms_;
    droidvm::CallContext caller_{"usb", true, true, true};
    static droidvm::usb::UsbVm row(const std::shared_ptr<droidvm::vm::VmRuntime>& vm) {
        droidvm::usb::UsbVm result;
        result.id = vm->id();
        result.config = vm->config();
        result.name = droidvm::config::string(result.config, "name");
        result.state = static_cast<droidvm::usb::VmState>(vm->state());
        result.control_socket = vm->crosvm_control_socket();
        return result;
    }
};
}

int main(int argc, char** argv) {
    try {
        std::string directory, data_directory, apk;
        bool force = false;
        bool configuration_owner = false;
        droidvm::config::JsonFile::Observer observer;
#ifdef DROIDVM_NETWORK_DELAY_FIXTURE
        int write_delay_ms = 0;
#endif
        std::string display_package = DROIDVM_PACKAGE_NAME;
        std::string usb_sys; // a fixture's fake sysfs root
#ifdef DROIDVM_KEYBOARD_FIXTURE
        std::string keyboard_name; // the only keyboard this test daemon may see
#endif
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--help") {
                std::cout << "Usage: droidvmd (--data-dir <app-data-directory> | --run-dir <existing-directory>)\n"
                             "                --apk <installed-apk> [--force] [--configuration-owner]\n"
                             "--configuration-owner permanently takes VM/network/disk configuration ownership.\n"
                             "--data-dir creates run/ and cache/daemon.log owned by the data directory UID.\n"
                             "Development native daemon; system, tasks and network configuration APIs.\n";
                return 0;
            } else if (arg == "--force") force = true;
            else if (arg == "--configuration-owner") configuration_owner = true;
            else if (arg == "--run-dir" && i + 1 < argc) directory = argv[++i];
            else if (arg == "--data-dir" && i + 1 < argc) data_directory = argv[++i];
            else if (arg == "--apk" && i + 1 < argc) apk = argv[++i];
#ifdef DROIDVM_KEYBOARD_FIXTURE
            else if (arg == "--test-keyboard-name" && i + 1 < argc) keyboard_name = argv[++i];
            else if (arg == "--test-display-package" && i + 1 < argc) display_package = argv[++i];
            else if (arg == "--test-usb-sys" && i + 1 < argc) usb_sys = argv[++i];
#endif
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
        if (configuration_owner && data_directory.empty())
            throw std::runtime_error("--configuration-owner requires --data-dir");
#ifdef DROIDVM_KEYBOARD_FIXTURE
        if (keyboard_name.empty()) throw std::runtime_error("--test-keyboard-name is required");
#endif
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
            // Without --configuration-owner this entry point uses the legacy VM inventory.
            // Refuse before --force can terminate a daemon that owns persistent configuration.
            auto files = layout->open_files();
            if (!configuration_owner) droidvm::config::require_legacy_vm_config(files.get(), layout->owner());
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
            // Outlives vms: their state hooks reach it until the last VM stops.
            std::unique_ptr<droidvm::input::KeyboardGrab> keyboard;
            std::unique_ptr<droidvm::vm::AcmPool> acm; // outlives vms: they release slots on exit
            std::unique_ptr<droidvm::usb::UsbService> usb;
            std::unique_ptr<droidvm::usb::CrosvmCli> usb_control;
            std::unique_ptr<UsbVmStore> usb_vms;
            std::unique_ptr<droidvm::VmService> vms;
            droidvm::LegacyEvents legacy_events;
            droidvm::TaskLimits task_limits;
            task_limits.background_workers = 2;
            // One gate admits configuration readers/writers and VM starts in coordinated mode.
            const auto configuration_gate = configuration_owner ? std::make_shared<droidvm::ConfigurationGate>() : nullptr;
            droidvm::TaskService tasks(task_limits, [] { return droidvm::TaskService::Clock::now(); }, {}, configuration_gate); // joins before legacy events and domain services disappear
            std::unique_ptr<droidvm::pkg::PkgService> packages; // reaches vms, networks and the events
            // Declared after vms/tasks: destroyed first, while both still exist.
            std::unique_ptr<droidvm::ConfigurationService> configuration;
            std::unique_ptr<droidvm::pkg::DiskOperationService> disk_operations;
            droidvm::NetworkConfigService* network_config = nullptr; // owned by networks or configuration
            std::string tool_data_dir;
#ifdef DROIDVM_PLATFORM_SERVICES
            droidvm::platform::AudioTable audio_table;
#endif
            droidvm::vm::HugepagePool hugepages;
            // The kernel keeps a reserve target after an owner dies; only a target this
            // daemon recorded in its run directory is ours to drop on startup.
            const auto pool_record = layout ? (std::filesystem::absolute(data_directory) / "run/vm-pool-target").string() : std::string();
            if (layout) {
                std::ifstream recorded(pool_record);
                long long pages = 0;
                if (recorded >> pages && pages > 0 && hugepages.resizable()) hugepages.set_reserved(0);
                std::filesystem::remove(pool_record);
            }
            droidvm::vm::PoolReservations pool([&](int64_t pages) {
                const bool done = hugepages.set_reserved(pages);
                if (pages > 0) std::ofstream(pool_record, std::ios::trunc) << pages;
                else std::filesystem::remove(pool_record);
                return done;
            });
            if (layout) {
                files = layout->open_files();
                droidvm::vm::RuntimeContext context;
                context.identities = &switch_runtime;
                context.events = &legacy_events;
                context.pool = &pool;
                context.owner = layout->owner();
                const auto data = std::filesystem::absolute(data_directory);
                // Legacy argv spells paths from /data/data/<package>; keep that when it is this directory.
                struct stat mine{}, legacy{};
                const auto legacy_data = std::string("/data/data/") + DROIDVM_PACKAGE_NAME;
                const bool same = stat(data.c_str(), &mine) == 0 && stat(legacy_data.c_str(), &legacy) == 0 &&
                    mine.st_dev == legacy.st_dev && mine.st_ino == legacy.st_ino;
                context.data_dir = same ? std::string() : data.string();
                context.cache_dir = (data / "cache").string();
                context.run_dir = (data / "run").string();
                context.lbx = (data / "bin/lbx").string();
                context.configuration_gate = configuration_gate;
                tool_data_dir = context.data_dir;
                // The USB gadget is global host state: only the app's own data directory owns the pool.
                if (same) {
                    droidvm::vm::AcmOptions options;
                    options.log = [&](const char* level, const std::string& text) { if (log) log->write(level, "UsbAcmPool: " + text); };
                    acm = std::make_unique<droidvm::vm::AcmPool>(std::move(options));
                    context.acm = acm.get();
                }
                const droidvm::CallContext internal{"vm-runtime", true, true, true};
                context.attach_nic = [&, internal](const std::string& network, const Json::Value& nic, const std::string& tap) {
                    Json::Value config;
                    try { config = network_config->get(internal, network); }
                    catch (const droidvm::ServiceError& error) {
                        if (error.code() == droidvm::ErrorCode::not_found) throw std::runtime_error("Network " + network + " not found");
                        throw;
                    }
                    droidvm::config::validate_network(config);
                    // Start first, as setupTap; then sanitizedFor and validate.
                    if (network_runtime->get(internal, network).state != droidvm::NetworkState::running) network_runtime->start(internal, network);
                    std::vector<std::string> dropped;
                    auto sane = droidvm::vm::sanitize_nic(nic, config, dropped);
                    droidvm::vm::validate_nic(sane, config);
                    network_runtime->attach_nic(internal, network, sane, tap);
                };
                context.detach_nic = [&, internal](const std::string& network, const Json::Value& nic, const std::string& tap) {
                    if (network_config->exists(internal, network)) network_runtime->detach_nic(internal, network, nic, tap);
                    else owned_links->cleanup(network + "/" + tap); // network gone: remove the TAP directly
                };
                context.warn = [&](const std::string& text) { if (log) log->write("WARN", text); };
                context.state_changed = [&](const std::string& id, const std::string& name, droidvm::VmState state) {
                    // VMInstance.setState: USB first, then the keyboard; each guarded.
                    if (usb) try { usb->on_vm_state(id, static_cast<droidvm::usb::VmState>(state)); }
                        catch (const std::exception& error) { if (log) log->write("WARN", std::string("usb: state hook failed: ") + error.what()); }
                    if (keyboard) try { keyboard->on_vm_state(id, name, droidvm::vm::command::lower(droidvm::vm_state_name(state))); }
                        catch (const std::exception& error) { if (log) log->write("WARN", std::string("keyboard: state hook failed: ") + error.what()); }
                };
                context.input_status = [&](const std::string& id, const std::string& screen, std::string records) {
                    if (keyboard) keyboard->on_guest_status(id, screen, records);
                };
                // The coordinator loads the inventory itself; it must attach to an empty service.
                vms = configuration_owner ? std::make_unique<droidvm::VmService>(context) : std::make_unique<droidvm::VmService>(files.get(), context);
                droidvm::input::KeyboardGrab::Hooks keys;
                keys.find = [&, internal](const std::string& id) -> std::optional<std::string> {
                    try { return vms->runtime(internal, id)->id(); }
                    catch (const droidvm::ServiceError&) { return std::nullopt; }
                };
                keys.running = [&, internal](const std::string& id) {
                    try { return vms->state(internal, id) == droidvm::VmState::running; }
                    catch (const droidvm::ServiceError&) { return false; }
                };
                keys.deliver = [&, internal](const std::string& id, const std::string& screen, std::string_view records) {
                    std::shared_ptr<droidvm::vm::VmRuntime> target;
                    try { target = vms->runtime(internal, id); }
                    catch (const droidvm::ServiceError&) { return false; }
                    // VMInstance.writeNativeInput: only a running VM; channel 1 is the keyboard.
                    return target->state() == droidvm::VmState::running && target->write_input(screen, 1, records);
                };
                keys.log = [&](const char* level, const std::string& text) { if (log) log->write(level, text); };
#ifdef DROIDVM_KEYBOARD_FIXTURE
                keys.scan = [keyboard_name] {
                    auto found = droidvm::input::scan_keyboards();
                    std::erase_if(found, [&](const droidvm::input::HostKeyboard& item) { return item.name != keyboard_name; });
                    return found;
                };
#endif
                keyboard = std::make_unique<droidvm::input::KeyboardGrab>(files.get(), std::move(keys));
                // Host USB state (drivers_autoprobe, bindings) is global: only the
                // app's own data directory, or a fixture's fake sysfs, may own it.
                if (same || !usb_sys.empty()) {
                    usb_vms = std::make_unique<UsbVmStore>(vms);
                    usb_control = std::make_unique<droidvm::usb::CrosvmCli>(data.string(), droidvm::vm::system_property("ro.build.version.release"));
                    droidvm::usb::UsbOptions options;
                    if (!usb_sys.empty()) { options.sys_root = usb_sys; options.dev_root = usb_sys + "/dev/bus/usb"; }
                    else options.watch = std::make_unique<droidvm::usb::HostUsbWatch>(options.dev_root, [&](const std::string& text) { if (log) log->write("WARN", text); });
                    options.files_dir = (data / "files").string();
                    options.vms = usb_vms.get();
                    options.control = usb_control.get();
                    options.publish = [&](const Json::Value& event) { legacy_events.publish(event); };
                    options.log = [&](const char* level, const std::string& text) { if (log) log->write(level, "UsbPassthrough: " + text); };
                    usb = std::make_unique<droidvm::usb::UsbService>(std::move(options));
                }
                if (log && !vms->load_error().empty() && vms->load_error() != "absent")
                    log->write("WARN", "VM inventory not loaded: " + vms->load_error());
                if (configuration_owner) {
                    // Claims VM/network/disk ownership and replays its journal before loading.
                    configuration = std::make_unique<droidvm::ConfigurationService>(files.get(), layout->owner(), configuration_gate, *vms, tasks,
                        droidvm::config::ConfigTransaction::Observer{}, true);
                    network_config = &configuration->networks();
                } else {
                    networks = std::make_unique<droidvm::NetworkConfigService>(files.get(), layout->owner(), observer, &tasks);
                    network_config = networks.get();
                }
                host_network = std::make_unique<droidvm::NetworkHostService>(
                    (std::filesystem::absolute(data_directory) / "bin/netbox").string());
                const auto binaries = std::filesystem::absolute(data_directory) / "bin";
                network_runtime = std::make_unique<droidvm::NetworkService>(*network_config,
                    [&, binaries](const Json::Value& config) -> std::unique_ptr<droidvm::network::Backend> {
                        if (droidvm::config::string(config, "bridge_type") == "gvisor")
                            return std::make_unique<droidvm::network::Gvswitch>((binaries / "gvswitch").string(), switch_runtime, netbox.get(), owned_links.get());
                        return std::make_unique<droidvm::network::LinuxBridge>(droidvm::network::LinuxBridge::Resources{
                            *netbox, *owned_links, *owned_rules, *owned_routes, linux_firewall, pd_ownership, *owned_ports, *owned_pbridge, switch_runtime,
                            (binaries / "bridgedhcp").string(), (binaries / "pbridge").string(), files.get(),
                            [&](const Json::Value& network) { return vms->statics(network); }});
                    });
                network_runtime->set_in_use([&](const std::string& network) { return vms->running_vm_using(network); });
                network_runtime->request_autostart({"network-autostart", true, true, true});
                host_ipv4 = std::make_unique<droidvm::network::HostIpv4Watch>(*netbox, switch_runtime, [&](const std::vector<std::string>& addresses) {
                    linux_firewall.set_host_ipv4(addresses);
                    std::string text;
                    for (const auto& address : addresses) text += (text.empty() ? "" : ",") + address;
                    if (log) log->write("INFO", "host IPv4 set [" + text + "]");
                });
#ifdef DROIDVM_PLATFORM_SERVICES
                {
                    // HostAudioTable.start: crosvm re-reads <run>/audio_devices per stream.
                    droidvm::Fd run(open((std::filesystem::absolute(data_directory) / "run").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
                    if (run.get() < 0 || !audio_table.start(run.get(), [&](const std::string& text) { if (log) log->write("WARN", text); }))
                        if (log) log->write("WARN", "host audio table unavailable");
                }
#endif
                droidvm::pkg::PkgContext package_context;
                package_context.vms = vms.get();
                package_context.networks = network_config;
                package_context.configuration = configuration.get();
                package_context.events = &legacy_events;
                package_context.tasks = &tasks;
                package_context.data_dir = context.data_dir;
                package_context.log = [&](const char* level, const std::string& text) { if (log) log->write(level, text); };
                packages = std::make_unique<droidvm::pkg::PkgService>(std::move(package_context));
                if (log && network_config->recovered()) log->write("WARN", "network configuration recovered from backup");
                if (log && network_config->inactive()) log->write("WARN", "inactive network configurations retained: " + std::to_string(network_config->inactive()));
            }
            droidvm::SystemService system([&] { return instance->token_exists(); }, [&] { return instance->read_token(); },
                                          hash, tasks.epoch());
            droidvm::RequestDispatcher dispatcher(system, tasks, network_config, host_network.get(), network_runtime.get(), host_ipv4.get(), vms.get(), &legacy_events, keyboard.get());
            if (packages) dispatcher.set_packages(packages.get());
            if (configuration) {
                dispatcher.set_configuration(configuration.get());
                droidvm::pkg::DiskOperationContext operation_context;
                operation_context.configuration = configuration.get();
                operation_context.directory = files.get(); operation_context.owner = layout->owner();
                operation_context.data_dir = tool_data_dir;
                operation_context.log = [&](const char* level, const std::string& text) { if (log) log->write(level, text); };
                // Replays interrupted disk operations before the socket serves anyone.
                disk_operations = std::make_unique<droidvm::pkg::DiskOperationService>(std::move(operation_context));
                dispatcher.set_disk_operations(disk_operations.get());
            }
            if (usb) {
                dispatcher.set_usb(usb.get());
                // Daemon.main starts the USB manager after the VM sweep is queued; its pass recovers leftovers.
                try { usb->start(); } catch (const std::exception& error) { if (log) log->write("WARN", std::string("USB start failed: ") + error.what()); }
            }
#ifdef DROIDVM_PLATFORM_SERVICES
            std::unique_ptr<droidvm::platform::DisplayBroker> display;
            if (vms) {
                droidvm::platform::DisplayBroker::Hooks hooks;
                const droidvm::CallContext internal{"display-broker", true, true, true};
                hooks.state = [&, internal](const std::string& vm) -> std::optional<std::string> {
                    try { return std::string(droidvm::vm_state_name(vms->state(internal, vm))); } catch (const std::exception&) { return std::nullopt; }
                };
                hooks.write_input = [&, internal](const std::string& vm, const std::string& screen, int channel, std::string_view data) {
                    try {
                        auto target = vms->runtime(internal, vm);
                        return target->state() == droidvm::VmState::running && target->write_input(screen, channel, data);
                    } catch (const std::exception&) { return false; }
                };
                hooks.keyboard = keyboard.get();
                hooks.package = display_package;
                hooks.log = [&](const std::string& level, const std::string& text) { if (log) log->write(level.c_str(), "NativeDisplayBinder: " + text); };
                display = std::make_unique<droidvm::platform::DisplayBroker>(std::move(hooks));
                dispatcher.set_display_attach([&](const std::string& nonce) { display->attach(nonce); });
            }
#endif
            droidvm::Cleanup cleanup;
            const auto report_failure = [&](const char* stage, const char* error) {
                if (log) log->write("ERROR", std::string(stage) + ": " + error);
            };
            int result = 1;
            cleanup.attempt("server", [&] {
                result = droidvm::serve(*instance, dispatcher, token.c_str(), signal_fd.get(), log.get());
            }, report_failure);
            // Task teardown completes while both the instance lock and log are held.
            cleanup.attempt("packages", [&] { if (packages) packages->shutdown(); }, report_failure);
            cleanup.attempt("disk operations", [&] { if (disk_operations) disk_operations->shutdown(); }, report_failure);
            cleanup.attempt("tasks", [&] { tasks.shutdown(); }, report_failure);
            // VMs leave before USB/networks: their taps and devices go with them.
            cleanup.attempt("VMs", [&] { if (vms) vms->stop_all(); }, report_failure);
            cleanup.attempt("USB", [&] { if (usb) usb->shutdown(); }, report_failure);
            cleanup.attempt("host address monitor", [&] { if (host_ipv4) host_ipv4->stop(); }, report_failure);
#ifdef DROIDVM_PLATFORM_SERVICES
            cleanup.attempt("audio", [&] { audio_table.stop(); }, report_failure);
#endif
            cleanup.attempt("networks", [&] { if (network_runtime) {
                const auto failures = network_runtime->shutdown();
                if (!failures.empty()) throw std::runtime_error("Network shutdown incomplete: " + droidvm::wire::stringify(failures));
                linux_firewall.stop(); // every Linux network was removed above
            } }, report_failure);
            if (cleanup.failed()) result = 1;
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
