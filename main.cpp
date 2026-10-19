// SPDX-License-Identifier: GPL-3.0-or-later
#include "runtime/instance.h"
#include "store/vm_ownership.h"
#include "runtime/layout.h"
#include "runtime/log.h"
#include "runtime/cleanup.h"
#include "services/system.h"
#include "services/system_blit_probe.h"
#include "services/hugepage.h"
#include "services/host_preferences_store.h"
#include "services/usb_acm_store.h"
#include "services/hugepage_processes.h"
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
#include "pkg/transfers.h"
#include "pkg/disk_operation.h"
#include "pkg/disk_inspection.h"
#include "web/disk_operations.h"
#include "web/agent_operations.h"
#include "agent/rescue_sessions.h"
#include "web/network_configuration.h"
#include "web/network_deletion.h"
#include "web/vm_terminal.h"
#include "web/vm_display_source.h"
#include "web/host_overview.h"
#include "web/hugepages.h"
#include "web/hugepage_processes.h"
#include "web/network_details.h"
#include "web/network_operations.h"
#include "web/host_network.h"
#include "services/configuration.h"
#include "vm/host_facts.h"
#include "vm/defaults.h"
#ifdef DROIDVM_PLATFORM_SERVICES
#include "audio_table.h"
#include "display_broker.h"
#endif
#include <fcntl.h>
#include "vm/command_common.h"
#include "vm/hugepage.h"
#include "vm/nic.h"
#include "build_metadata.h"
#ifdef DROIDVM_WEB_HTTP_TRANSPORT
#include "web/service.h"
#include "web/vm_read_model.h"
#include "web/vm_operations.h"
#include "web/host_preferences.h"
#include "web/usb_acm.h"
#include "web/vm_logs.h"
#include "web/vm_configuration.h"
#include "web/resource_catalog.h"
#include "web/usb_operations.h"
#include "web/usb_rules.h"
#include "web/agent_rescue.h"
#include "web/package_exports.h"
#include "web/package_imports.h"
#include "web/package_transfers.h"
#include "common/sha256.h"
#include "web/backup_config.h"
#include "web/image_imports.h"
#include "web/task_receipts.h"
#include "web/image_uploads.h"
#include "pkg/image_import.h"
#include "services/configuration_backup.h"
#include "store/disk_config.h"
#include "services/vm_lifecycle.h"
#endif
#include <fstream>
#include <sstream>
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
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <atomic>
#ifdef DROIDVM_NETWORK_DELAY_FIXTURE
#include <thread>
#endif

namespace {
// The old single-number record did not retain a manual baseline. Never infer
// zero from it. Only restore a versioned target which still matches the kernel.
std::optional<int64_t> restore_hugepage_baseline(droidvm::Instance& instance,
        const droidvm::vm::HugepagePool& pool) {
    auto current = pool.read("pool_want");
    droidvm::Fd file(openat(instance.directory_fd(), "vm-pool-target",
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (file.get() < 0 || !current) return current;
    struct stat info{};
    if (fstat(file.get(), &info) != 0 || !S_ISREG(info.st_mode) || info.st_size < 0 || info.st_size > 256)
        return current;
    char bytes[257]{};
    const auto size = read(file.get(), bytes, 256);
    if (size < 0 || size != info.st_size) return current;
    std::istringstream record(std::string(bytes, static_cast<size_t>(size)));
    std::string version, extra;
    int64_t target = -1, manual = -1;
    if (!(record >> version >> target >> manual) || version != "v2" || target < 0 || manual < 0 ||
            (record >> extra) || target != *current || target == manual) return current;
    if (!pool.set_reserved(manual)) throw std::runtime_error("Cannot restore recorded hugepage baseline");
    current = pool.read("pool_want");
    if (!current) throw std::runtime_error("Hugepage baseline readback unavailable");
    instance.publish("vm-pool-target", "v2 " + std::to_string(*current) + " " + std::to_string(*current) + "\n");
    return current;
}

[[noreturn]] void incomplete_worker_shutdown() noexcept {
    // A detached VM worker may still hold raw runtime dependencies. Do not
    // unwind those objects beneath it after the bounded stop attempt fails.
    std::fputs("droidvmd: incomplete worker shutdown; terminating without dependency teardown\n", stderr);
    std::_Exit(EXIT_FAILURE);
}
void close_rescue_sessions(const std::shared_ptr<droidvm::agent::RescueSessions>& sessions,
        std::unique_ptr<droidvm::VmService>& vms) {
    if (!sessions) return;
    sessions->shutdown();
    if (sessions->empty()) return;
    // A timed-out managed owner must not outlive its raw VM dependencies.
    // Reuse the existing stop_all proof, then let the original custody object
    // release its retained inode leases and registry reservation without reopen.
    if (vms) vms->stop_all();
    sessions->shutdown();
    if (!sessions->empty()) incomplete_worker_shutdown();
}
// Declared after worker dependencies, before any work can be admitted. On an
// exceptional setup/serve exit the later WebService first closes its listener,
// then accepted tasks join while configuration and runtime services still live.
class WorkerShutdown final {
public:
    WorkerShutdown(droidvm::TaskService& tasks,
        std::unique_ptr<droidvm::pkg::PkgService>& packages,
        std::unique_ptr<droidvm::pkg::DiskOperationService>& disks,
        std::unique_ptr<droidvm::VmService>& vms, std::shared_ptr<droidvm::agent::RescueSessions> rescue,
        std::shared_ptr<droidvm::pkg::TransferService>& transfers,
        std::function<void()> close_ingress = {})
        : tasks_(tasks), packages_(packages), disks_(disks), vms_(vms), rescue_(std::move(rescue)), transfers_(transfers), close_ingress_(std::move(close_ingress)) {}
    ~WorkerShutdown() {
        try { if (close_ingress_) close_ingress_(); } catch (...) { incomplete_worker_shutdown(); }
        try { if (packages_) packages_->shutdown(); } catch (...) {}
        try { if (disks_) disks_->shutdown(); } catch (...) {}
        try { tasks_.shutdown(); } catch (...) { incomplete_worker_shutdown(); }
        try { if (transfers_) transfers_->shutdown(); } catch (...) {}
        try { close_rescue_sessions(rescue_, vms_); } catch (...) { incomplete_worker_shutdown(); }
        try { if (vms_) vms_->stop_all(); } catch (...) { incomplete_worker_shutdown(); }
    }
private:
    droidvm::TaskService& tasks_;
    std::unique_ptr<droidvm::pkg::PkgService>& packages_;
    std::unique_ptr<droidvm::pkg::DiskOperationService>& disks_;
    std::unique_ptr<droidvm::VmService>& vms_;
    std::shared_ptr<droidvm::agent::RescueSessions> rescue_;
    std::shared_ptr<droidvm::pkg::TransferService>& transfers_;
    std::function<void()> close_ingress_;
};

#ifdef DROIDVM_WEB_HTTP_TRANSPORT
droidvm::web::ConfigurationBackupOperations bind_configuration_backup(droidvm::TaskService& tasks,
        droidvm::ConfigUploads* uploads,
        const std::shared_ptr<droidvm::ConfigurationBackup>& backups) {
    return droidvm::web::backup_configuration(tasks, {
        [uploads](const auto& caller, size_t bytes) { return uploads->begin_backup(caller, bytes); },
        [uploads](const auto& caller, const auto& id, size_t offset, std::string_view bytes) {
            return uploads->append_backup(caller, id, offset, bytes);
        },
        [uploads](const auto& caller, const auto& id) { return uploads->preview_backup(caller, id); },
        [uploads](const auto& caller, const auto& id, const auto& token) { return uploads->commit_backup(caller, id, token); },
        [uploads](const auto& caller, const auto& id) { uploads->abort_backup(caller, id); },
        [backups](const auto& caller) {
            const auto bytes = backups->export_file(caller);
            auto stream = std::make_shared<droidvm::web::HttpStreamBody>();
            stream->length = bytes->size();
            stream->read = [bytes](uint64_t offset, size_t maximum) {
                if (offset > bytes->size() || maximum > (256u << 10))
                    throw droidvm::ServiceError(droidvm::ErrorCode::invalid_argument, "Invalid backup read");
                return bytes->substr(static_cast<size_t>(offset), maximum);
            };
            return stream;
        }
    });
}
droidvm::web::PackageTransferOperations bind_package_transfers(droidvm::TaskService& tasks,
        const std::shared_ptr<droidvm::pkg::TransferService>& transfers) {
    if (!transfers) return {};
    return droidvm::web::package_transfers(tasks, {
        [transfers](const auto& caller, const auto& id, const std::vector<droidvm::web::PackageTransferFile>& files) {
            std::vector<droidvm::pkg::TransferFile> native;
            native.reserve(files.size());
            for (const auto& file : files) native.push_back({file.name, file.size});
            return transfers->begin(caller, id, native);
        },
        [transfers](const auto& caller, const auto& id) { return transfers->status(caller, id); },
        [transfers](const auto& caller, const auto& id) { return transfers->finish(caller, id); },
        [transfers](const auto& caller, const auto& id, size_t index, uint64_t offset, std::string_view bytes) {
            return transfers->append(caller, id, index, offset, bytes);
        },
        [transfers](const auto& caller, const auto& id) { transfers->erase(caller, id); },
        [transfers](const auto& caller, const auto& id, const auto& exported) { return transfers->prepare_download(caller, id, exported); },
        [transfers](const auto& caller, const auto& id, size_t index) {
            const auto reader = transfers->open_download(caller, id, index);
            auto stream = std::make_shared<droidvm::web::HttpStreamBody>();
            stream->length = reader->size();
            stream->read = [reader](uint64_t offset, size_t maximum) { return reader->read(offset, maximum); };
            return stream;
        }
    });
}
droidvm::web::ImageUploadOperations bind_image_uploads(droidvm::TaskService& tasks,
        const std::shared_ptr<droidvm::pkg::TransferService>& transfers, droidvm::ConfigurationService& configuration,
        const std::string& qemu_img) {
    if (!transfers) return {};
    return droidvm::web::image_uploads(tasks, {
        [transfers](const auto& caller, const auto& id, const droidvm::web::PackageTransferFile& file) {
            return transfers->begin_image(caller, id, {file.name, file.size});
        },
        [transfers](const auto& caller, const auto& id) { return transfers->status(caller, id, true); },
        [transfers](const auto& caller, const auto& id) { return transfers->finish(caller, id, true); },
        [transfers](const auto& caller, const auto& id, uint64_t offset, std::string_view bytes) {
            return transfers->append(caller, id, 0, offset, bytes, true);
        },
        [transfers](const auto& caller, const auto& id) { transfers->erase(caller, id, true); },
        [transfers, &configuration, qemu_img](const auto& caller, const auto& id, const auto& folder, const auto& name, auto& control) {
            return transfers->install_image(caller, id, folder, name, qemu_img, control,
                [&](const std::string& path, const std::function<void()>& publish) {
                    configuration.with_unreferenced_disk_path(caller, path, publish);
                });
        }
    });
}
// Driven by the existing IPC loop regardless of whether WebUI is enabled or a
// browser session still exists. Only the pre-existing TaskService worker may
// call expire: at most one queued/running sweep, with no extra thread or timer.
struct RescueMaintenance {
    RescueMaintenance(std::shared_ptr<droidvm::agent::RescueSessions> value,
        std::shared_ptr<droidvm::pkg::TransferService> transfer_service)
        : sessions(std::move(value)), transfers(std::move(transfer_service)) {}
    std::shared_ptr<droidvm::agent::RescueSessions> sessions;
    std::shared_ptr<droidvm::pkg::TransferService> transfers;
    std::atomic<bool> pending{false};
    std::chrono::steady_clock::time_point next{}; // IPC loop only
};
void schedule_rescue_maintenance(droidvm::TaskService& tasks, const std::shared_ptr<RescueMaintenance>& state) {
    const auto now = std::chrono::steady_clock::now();
    if (now < state->next || state->pending.exchange(true)) return;
    state->next = now + std::chrono::seconds(5);
    try {
        tasks.post({"rescue-maintenance", true, true, false}, [state](bool discarded) {
            try { if (!discarded) state->sessions->expire(); } catch (...) {}
            try { if (!discarded && state->transfers) state->transfers->maintenance(); } catch (...) {}
            state->pending = false;
        });
    } catch (...) { state->pending = false; }
}
#endif

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
        result.observed = vm->observation();
        return result;
    }
};
}

int main(int argc, char** argv) {
    try {
        // Internal self-exec helper: before locks, services or persistence.
        if (argc == 2 && std::string_view(argv[1]) == "--probe-vulkan-blit")
            return droidvm::SystemBlitProbe::child_main();
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
            std::unique_ptr<droidvm::HostPreferencesService> host_preferences;
            std::unique_ptr<droidvm::HostPreferencesService> disk_defaults;
            std::unique_ptr<droidvm::UsbAcmService> usb_acm;
            std::unique_ptr<droidvm::VmService> vms;
            droidvm::LegacyEvents legacy_events;
            droidvm::TaskLimits task_limits;
            task_limits.background_workers = 2;
            task_limits.max_result_bytes = 256u << 10; // Bounded package previews; shared retained quota is unchanged.
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
            const auto initial_pool_baseline = layout ? restore_hugepage_baseline(*instance, hugepages) : hugepages.read("pool_want");
            droidvm::vm::PoolReservations pool([&](int64_t pages, int64_t baseline) {
                // Persist intent before touching sysfs. An interrupted or rounded
                // write is recovered only after an exact kernel observation.
                if (!layout) return false;
                try {
                    instance->publish("vm-pool-target", "v2 " + std::to_string(pages) + " " + std::to_string(baseline) + "\n");
                } catch (...) { return false; }
                const bool done = hugepages.set_reserved(pages);
                if (done) {
                    const auto actual = hugepages.read("pool_want");
                    if (!actual) return false;
                    try {
                        instance->publish("vm-pool-target", "v2 " + std::to_string(*actual) + " " + std::to_string(baseline) + "\n");
                    } catch (...) { return false; }
                }
                return done;
            });
            pool.initialize_manual(initial_pool_baseline);
            std::unique_ptr<droidvm::HugepageService> hugepage_service;
            std::unique_ptr<droidvm::HugepageProcessService> hugepage_process_service;
            // Both exceptional-exit guards join tasks and close these owners
            // before configuration, VM, pool or runtime dependencies disappear.
            auto rescue_sessions = std::make_shared<droidvm::agent::RescueSessions>();
            std::shared_ptr<droidvm::pkg::TransferService> package_transfers;
            WorkerShutdown worker_shutdown(tasks, packages, disk_operations, vms, rescue_sessions, package_transfers);
            if (layout) {
                files = layout->open_files();
                host_preferences = std::make_unique<droidvm::HostPreferencesService>(tasks,
                    droidvm::host_preferences_store(files.get(), layout->owner()));
                disk_defaults = std::make_unique<droidvm::HostPreferencesService>(tasks,
                    droidvm::host_preferences_store(files.get(), layout->owner(), droidvm::HostPreferenceDomain::disk_operations));
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
                // The module is host-global: only the installed app's data owner
                // exposes manual administration, as with the USB gadget owner.
                if (same) {
                    droidvm::HugepageOptions options;
                    options.manual_changed = [&](int64_t baseline) {
                        auto actual = hugepages.read("pool_want");
                        if (!actual && !hugepages.has("pool_want")) actual = hugepages.read("pool_target");
                        if (!actual && hugepages.has("pool_want"))
                            throw std::runtime_error("Hugepage target readback unavailable");
                        instance->publish("vm-pool-target", "v2 " + std::to_string(actual.value_or(baseline)) + " " + std::to_string(baseline) + "\n");
                    };
                    hugepage_service = std::make_unique<droidvm::HugepageService>(tasks, pool, std::move(options));
                }
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
                    usb_acm = std::make_unique<droidvm::UsbAcmService>(tasks,
                        droidvm::usb_acm_store(files.get(), layout->owner(), *acm));
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
                context.info = [&](const std::string& text) { if (log) log->write("INFO", text); };
                context.state_changed = [&](const std::string& id, const std::string& name, droidvm::VmState state) {
                    tasks.publish_vm_runtime(id);
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
                vms = configuration_owner ? std::make_unique<droidvm::VmService>(context, host_preferences.get(), usb_acm.get(), disk_defaults.get())
                    : std::make_unique<droidvm::VmService>(files.get(), context, host_preferences.get(), usb_acm.get(), disk_defaults.get());
                if (same) {
                    droidvm::HugepageProcessOptions options;
                    options.running_vms = [&, internal] {
                        std::vector<droidvm::HugepageVmProcess> result;
                        // VmService hides private managed/Agent runtimes. Never
                        // enumerate all /proc or expose their private identities.
                        for (const auto& row : vms->list(internal)) {
                            const auto id = droidvm::config::uuid(row);
                            std::shared_ptr<droidvm::vm::VmRuntime> runtime;
                            try { runtime = vms->runtime(internal, id); }
                            catch (const droidvm::ServiceError& error) {
                                if (error.code() == droidvm::ErrorCode::not_found) continue;
                                throw;
                            }
                            runtime->inspect_process([&](int64_t pid, const droidvm::vm::Observation& observed) {
                                const auto process_id = static_cast<int>(pid); // Child owns a pid_t.
                                const auto birth = droidvm::hugepage_process_start_ticks(process_id);
                                result.push_back({id, droidvm::config::string(row, "name"), process_id,
                                    birth.value_or(""), observed.instance, observed.revision});
                            });
                        }
                        return result;
                    };
                    options.signal_vm = [&, internal](const droidvm::HugepageVmProcess& process, int number) {
                        return vms->runtime(internal, process.id)->signal_process(process.pid,
                            {process.runtime_instance, process.runtime_revision}, number);
                    };
                    hugepage_process_service = std::make_unique<droidvm::HugepageProcessService>(tasks, std::move(options));
                }
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
#ifdef DROIDVM_WEB_HTTP_TRANSPORT
                if (configuration) {
                    package_transfers = std::make_shared<droidvm::pkg::TransferService>(layout->cache_fd(),
                        (std::filesystem::absolute(data_directory) / "cache").string(), layout->owner(), configuration->disk_files());
                    package_context.import_source_pin = [transfers = package_transfers](const auto& caller, const auto& source) {
                        return transfers->pin_source(caller, source);
                    };
                }
#endif
                package_context.data_dir = context.data_dir;
                package_context.log = [&](const char* level, const std::string& text) { if (log) log->write(level, text); };
                packages = std::make_unique<droidvm::pkg::PkgService>(std::move(package_context));
                if (log && network_config->recovered()) log->write("WARN", "network configuration recovered from backup");
                if (log && network_config->inactive()) log->write("WARN", "inactive network configurations retained: " + std::to_string(network_config->inactive()));
            }
            droidvm::SystemService system([&] { return instance->token_exists(); }, [&] { return instance->read_token(); },
                                          hash, tasks.epoch());
            droidvm::RequestDispatcher dispatcher(system, tasks, network_config, host_network.get(), network_runtime.get(), host_ipv4.get(), vms.get(), &legacy_events, keyboard.get());
            if (hugepage_service) dispatcher.set_hugepages(hugepage_service.get());
            if (host_preferences) dispatcher.set_host_preferences(host_preferences.get());
            if (disk_defaults) dispatcher.set_disk_defaults(disk_defaults.get());
            if (usb_acm) dispatcher.set_usb_acm(usb_acm.get());
            if (configuration) dispatcher.set_configuration(configuration.get());
            if (usb && dispatcher.config_uploads()) dispatcher.config_uploads()->bind_usb_rules(
                [&](const droidvm::CallContext&) { return usb->rules_snapshot(); },
                [&](const droidvm::CallContext&, const std::string& revision, const Json::Value& rules) {
                    return usb->set_rules_checked(rules, revision);
                });
#ifdef DROIDVM_WEB_HTTP_TRANSPORT
            droidvm::SystemBlitProbe system_blit_probe;
            std::unique_ptr<droidvm::pkg::DiskInspectionService> disk_inspection;
            std::unique_ptr<droidvm::web::WebService> web;
            std::shared_ptr<droidvm::ConfigurationBackup> backups;
            std::shared_ptr<droidvm::pkg::ImageImportService> image_importer;
            // Also keep HTTP readers' inspection/probe dependencies alive until
            // their queued handlers have drained. The earlier guard covers setup.
            WorkerShutdown web_workers(tasks, packages, disk_operations, vms, rescue_sessions, package_transfers,
                [&] { if (web) web->stop(); });
            if (layout && vms && host_network && configuration) {
                backups = std::make_shared<droidvm::ConfigurationBackup>(*configuration);
                image_importer = std::make_shared<droidvm::pkg::ImageImportService>(*configuration,
                    (tool_data_dir.empty() ? std::string("/data/data/") + DROIDVM_PACKAGE_NAME : tool_data_dir) + "/usr/bin/qemu-img",
                    [transfers = package_transfers](const std::string& path, int fd) {
                        if (!transfers) throw droidvm::ServiceError(droidvm::ErrorCode::unavailable,
                            "Temporary image ownership service is unavailable");
                        transfers->require_persistent_source(path, fd);
                    });
                dispatcher.config_uploads()->bind_backup(
                    [backups](const auto& caller, std::string_view bytes) { return backups->preview(caller, bytes); },
                    [backups](const auto& caller, std::string_view bytes, const auto& proof) {
                        return backups->commit(caller, bytes, proof);
                    });
                auto terminals = std::make_shared<droidvm::web::VmTerminalSource>(droidvm::web::VmTerminalSource{
                    [&](const droidvm::CallContext& caller, const std::string& id) {
                        const auto target = vms->runtime(caller, id)->console_target();
                        return droidvm::web::VmTerminalTarget{id, target.observed, target.streams};
                    },
                    [&](const droidvm::CallContext& caller, const droidvm::web::VmTerminalRead& request) {
                        return vms->runtime(caller, request.vm_id)->console_read(request.stream, request.observed, request.cursor, request.tail);
                    },
                    [&](const droidvm::CallContext& caller, const droidvm::web::VmTerminalWrite& request) {
                        return vms->runtime(caller, request.vm_id)->console_write(request.stream, request.observed, request.bytes);
                    }
                });
                auto displays = std::make_shared<droidvm::web::VmDisplaySource>(droidvm::web::VmDisplaySource{
                    [&](const droidvm::CallContext& caller, const std::string& id) {
                        const auto native = vms->runtime(caller, id)->display_target();
                        droidvm::web::VmDisplayTarget result{id, native.observed, {}};
                        for (const auto& screen : native.screens)
                            result.screens.push_back({screen.id, screen.available, screen.reason, screen.input_enabled});
                        return result;
                    },
                    [&](const droidvm::CallContext& caller, const std::string& id, const std::string& screen,
                        const droidvm::vm::Observation& expected) {
                        auto opened = vms->runtime(caller, id)->open_display(screen, expected);
                        const auto stream = opened.stream;
                        return droidvm::web::VmDisplayStream{
                            [stream] { return stream->connected(); },
                            [stream](size_t maximum) { return stream->read(maximum); },
                            [stream](std::string_view bytes) { return stream->write(bytes); },
                            [stream] { stream->close(); }, std::move(opened.password)};
                    }
                });
                droidvm::HostOverviewOptions overview_options;
                overview_options.data_directory = tool_data_dir.empty()
                    ? std::string("/data/data/") + DROIDVM_PACKAGE_NAME : tool_data_dir;
                overview_options.daemon.version = DROIDVM_VERSION_NAME;
                overview_options.host.soc_model = droidvm::vm::host_soc_name();
                if (const auto model = droidvm::vm::system_property("ro.product.model"); !model.empty())
                    overview_options.host.device_model = model;
                auto host_overview = std::make_shared<droidvm::HostOverviewService>(std::move(overview_options));
                disk_inspection = std::make_unique<droidvm::pkg::DiskInspectionService>(*configuration,
                    (tool_data_dir.empty() ? std::string("/data/data/") + DROIDVM_PACKAGE_NAME : tool_data_dir) + "/usr/bin/qemu-img");
                auto disk_capacity = std::make_shared<droidvm::HostDiskCapacity>(
                    [&](const std::string& id, const std::string& revision) -> std::optional<uint64_t> {
                        const auto detail = disk_inspection->read({"host-capacity", true, true, true}, id);
                        if (detail.state == "ready" && detail.disks.revision == revision &&
                            detail.image["virtual-size"].isUInt64()) return detail.image["virtual-size"].asUInt64();
                        return std::nullopt;
                    },
                    [&](std::function<void(bool)> work) {
                        tasks.post({"host-capacity", true, true, true}, std::move(work));
                    });
                auto store = std::make_shared<droidvm::config::JsonFile>(files.get(), "webui.json", layout->owner(),
                    droidvm::config::JsonFile::Observer{}, 8192, droidvm::config::JsonSyntax::strict);
                auto load = [store] {
                    const auto saved = store->load();
                    return saved ? droidvm::web::WebSettings::parse(saved->value) : droidvm::web::WebSettings{};
                };
                // Authorization must never be restored from an older .bak after revocation.
                auto credentials = std::make_shared<droidvm::config::JsonFile>(files.get(), "webui-sessions.json", layout->owner(),
                    droidvm::config::JsonFile::Observer{}, 64u << 10, droidvm::config::JsonSyntax::strict, false);
                auto receipts = std::make_shared<droidvm::config::JsonFile>(files.get(), "webui-task-receipts.json", layout->owner(),
                    droidvm::config::JsonFile::Observer{}, 2u << 20, droidvm::config::JsonSyntax::strict, false);
                // A corrupt receipt store must not restore a stale host identity
                // from backup, nor prevent the daemon's normal VM services.
                try {
                    droidvm::web::bind_task_receipts(tasks, {
                        [receipts] { const auto saved = receipts->load(); return saved ? saved->value : Json::Value(); },
                        [receipts](const Json::Value& value) { receipts->save(value); }
                    });
                } catch (...) { if (log) log->write("WARN", "WebUI operation history unavailable"); }
                droidvm::web::SessionPersistence session_persistence{
                    [credentials] { const auto saved = credentials->load(); return saved ? saved->value : Json::Value(); },
                    [credentials](const Json::Value& value) { credentials->save(value); },
                    [](std::string_view value) {
                        unsigned char bytes[32]; droidvm_sha256(reinterpret_cast<const unsigned char*>(value.data()), value.size(), bytes);
                        constexpr char hex[] = "0123456789abcdef";
                        std::string result; result.reserve(64);
                        for (const auto byte : bytes) { result += hex[byte >> 4]; result += hex[byte & 15]; }
                        return result;
                    }
                };
                droidvm::web::WebSettings settings;
                try { settings = load(); }
                catch (...) { if (log) log->write("WARN", "WebUI configuration unavailable; listener disabled"); }
                web = std::make_unique<droidvm::web::WebService>(tasks, settings,
                    [&] { return host_network->snapshot({"web-discovery", true, true, true}); },
                    [&](const droidvm::CallContext& caller) {
                        auto config = configuration->vms().snapshot(caller);
                        return droidvm::web::vm_snapshot(vms->list(caller), config.get(),
                            [&](const std::string& network) {
                                return network_runtime ? network_runtime->observed_leases(caller, network) : Json::Value();
                            },
                            [&](const std::string& id, const std::string& instance, const std::string& revision) {
                                const auto current = vms->runtime(caller, id)->snapshot();
                                return droidvm::config::string(current, "state") == "RUNNING" &&
                                    droidvm::config::string(current, "runtime_instance") == instance &&
                                    droidvm::config::string(current, "runtime_revision") == revision;
                            });
                    },
                    [store](const Json::Value& value) { store->save(value); }, load,
                    droidvm::web::WebBuild{DROIDVM_VERSION_NAME, std::to_string(DROIDVM_VERSION_CODE)}, droidvm::web::ipv6_available,
                    droidvm::web::vm_operations(tasks, [&](const droidvm::CallContext& caller, const droidvm::web::VmOperation& request) {
                        if (request.action == "start") {
                            droidvm::VmLifecycleService(configuration->vms(), *vms).start(caller,
                                {request.config_revision, request.vm_id, {}, {}, std::nullopt, request.observed});
                            return;
                        }
                        auto runtime = vms->runtime(caller, request.vm_id);
                        bool admitted = false;
                        if (request.action == "stop") admitted = runtime->stop(request.observed);
                        else if (request.action == "reboot") admitted = runtime->reboot(request.observed);
                        else if (request.action == "suspend") admitted = runtime->suspend(request.observed);
                        else if (request.action == "resume") admitted = runtime->resume(request.observed);
                        if (!admitted) throw droidvm::ServiceError(droidvm::ErrorCode::conflict, "VM operation was not admitted");
                    }), droidvm::web::vm_logs({
                        [&](const droidvm::CallContext& caller, const std::string& id) {
                            auto runtime = vms->runtime(caller, id);
                            return droidvm::web::VmLogTarget{id, runtime->observation().instance, runtime->streams()};
                        },
                        [&](const droidvm::CallContext& caller, const droidvm::web::VmLogRead& request) {
                            auto runtime = vms->runtime(caller, request.vm_id);
                            if (runtime->observation().instance != request.instance_id)
                                throw droidvm::ServiceError(droidvm::ErrorCode::conflict, "VM instance changed");
                            auto* log = runtime->log(request.stream);
                            if (!log) throw droidvm::ServiceError(droidvm::ErrorCode::not_found, "Log stream not found");
                            return log->read(request.cursor, request.tail);
                        }
                    }), droidvm::web::vm_configuration(tasks, {
                        [uploads = dispatcher.config_uploads()](const droidvm::CallContext& caller, const std::string& revision, size_t bytes) {
                            return uploads->begin(caller, revision, bytes);
                        },
                        [uploads = dispatcher.config_uploads()](const droidvm::CallContext& caller, const std::string& id, size_t offset, std::string_view bytes) {
                            return uploads->append(caller, id, offset, bytes);
                        },
                        [uploads = dispatcher.config_uploads()](const droidvm::CallContext& caller, const std::string& id) {
                            return uploads->commit(caller, id);
                        },
                        [uploads = dispatcher.config_uploads()](const droidvm::CallContext& caller, const std::string& id) { uploads->abort(caller, id); }
                    }, [&](const droidvm::CallContext&) {
                        droidvm::vm::HostFacts host;
                        host.has_kvm = std::filesystem::exists("/dev/kvm");
                        host.has_gunyah = std::filesystem::exists("/dev/gunyah");
                        host.has_gzvm = std::filesystem::exists("/dev/gzvm");
                        const auto hypervisor = droidvm::vm::command::resolve_hypervisor(
                            Json::Value(Json::objectValue), host, droidvm::vm::command::Backend::crosvm).value_or("KVM");
                        auto soc = droidvm::vm::system_property("ro.vendor.qti.soc_model");
                        if (soc.empty()) soc = droidvm::vm::system_property("ro.soc.model");
                        return droidvm::vm::new_vm_defaults(
                            tool_data_dir.empty() ? std::string("/data/data/") + DROIDVM_PACKAGE_NAME : tool_data_dir,
                            hypervisor, soc);
                    }), droidvm::web::ResourceCatalogs{
                        [&](const droidvm::CallContext& caller) {
                            if (!configuration->disks()) throw droidvm::ServiceError(droidvm::ErrorCode::unavailable, "Disk registry unavailable");
                            const auto snapshot = configuration->disks()->snapshot(caller);
                            const auto references = droidvm::config::disk_references(Json::Value(Json::objectValue), snapshot->document);
                            auto result = droidvm::web::disk_catalog(*snapshot, droidvm::config::disk_path,
                                droidvm::config::valid_disk_paths(snapshot->document), references.bases);
                            result["vmRevision"] = configuration->vms().snapshot(caller)->revision;
                            return result;
                        },
                        [&](const droidvm::CallContext& caller) {
                            return droidvm::web::network_catalog(network_config->list(caller));
                        }
#ifdef DROIDVM_PLATFORM_SERVICES
                        , [&](const droidvm::CallContext&) {
                            return droidvm::web::audio_catalog(audio_table.snapshot());
                        }
#else
                        , {}
#endif
                        , usb ? std::function<Json::Value(const droidvm::CallContext&)>([&](const droidvm::CallContext&) {
                            return droidvm::web::usb_catalog(usb->host_catalog());
                        }) : std::function<Json::Value(const droidvm::CallContext&)>{}
                        , [](const droidvm::CallContext&) {
                            return droidvm::web::cpu_catalog(droidvm::vm::read_cpu_topology());
                        }
                        , [&](const droidvm::CallContext&) {
                            return droidvm::web::host_device_catalog(droidvm::vm::probe_host_devices(
                                tool_data_dir.empty() ? std::string("/data/data/") + DROIDVM_PACKAGE_NAME : tool_data_dir),
                                system_blit_probe.snapshot());
                        }
                        , [&](const droidvm::CallContext& caller, const std::string& id) {
                            const auto detail = disk_inspection->read(caller, id);
                            const auto references = droidvm::config::disk_references(detail.vms.document, detail.disks.document);
                            return droidvm::web::disk_detail(droidvm::web::disk_catalog(detail.disks, droidvm::config::disk_path,
                                droidvm::config::valid_disk_paths(detail.disks.document), references.bases),
                                detail.vms, id, detail.state, detail.image);
                        }
                        , droidvm::web::disk_operations(tasks, [&](const droidvm::CallContext& caller, const Json::Value& request, droidvm::TaskControl& control) {
                            if (!disk_operations) throw droidvm::ServiceError(droidvm::ErrorCode::unavailable, "Disk operations unavailable");
                            return disk_operations->execute(caller, request, control);
                        })
                        , droidvm::web::disk_recovery(tasks,
                            [&](const droidvm::CallContext&) {
                                if (!disk_operations) throw droidvm::ServiceError(droidvm::ErrorCode::unavailable, "Disk operations unavailable");
                                return disk_operations->pending();
                            },
                            [&](const droidvm::CallContext& caller) {
                                if (!disk_operations) throw droidvm::ServiceError(droidvm::ErrorCode::unavailable, "Disk operations unavailable");
                                return disk_operations->recover(caller);
                            })
                        , droidvm::web::network_configuration(tasks, {
                            [uploads = dispatcher.config_uploads()](const droidvm::CallContext& caller, const std::string&, size_t bytes) { return uploads->begin_network(caller, bytes); },
                            [uploads = dispatcher.config_uploads()](const droidvm::CallContext& caller, const std::string& id, size_t offset, std::string_view bytes) { return uploads->append_network(caller, id, offset, bytes); },
                            [uploads = dispatcher.config_uploads()](const droidvm::CallContext& caller, const std::string& id) { return uploads->commit_network(caller, id); },
                            [uploads = dispatcher.config_uploads()](const droidvm::CallContext& caller, const std::string& id) { uploads->abort_network(caller, id); }
                        })
                        , [&](const droidvm::CallContext& caller, const std::string& id) {
                            if (!network_runtime) throw droidvm::ServiceError(droidvm::ErrorCode::unavailable, "Network runtime unavailable");
                            const auto config = network_config->get_with_revision(caller, id);
                            const auto vms_snapshot = configuration->vms().snapshot(caller);
                            const auto before = network_runtime->get(caller, id);
                            Json::Value live;
                            try { live = network_runtime->live(caller, id); }
                            catch (const droidvm::ServiceError& error) {
                                if (error.code() != droidvm::ErrorCode::unavailable && error.code() != droidvm::ErrorCode::io_error && error.code() != droidvm::ErrorCode::conflict) throw;
                            }
                            const auto after = network_runtime->get(caller, id);
                            if (network_config->get_with_revision(caller, id).revision != config.revision ||
                                configuration->vms().snapshot(caller)->revision != vms_snapshot->revision)
                                throw droidvm::ServiceError(droidvm::ErrorCode::conflict, "Network references changed during observation");
                            const auto observation = [](const droidvm::NetworkView& view) {
                                return droidvm::web::NetworkObservation{view.id, droidvm::network_state_name(view.state), view.generation, view.desired_running};
                            };
                            return droidvm::web::network_detail(config.config, *vms_snapshot, observation(before), observation(after), live, config.revision);
                        }
                        , [&](const droidvm::CallContext& caller) {
                            if (!host_network) throw droidvm::ServiceError(droidvm::ErrorCode::unavailable, "Host discovery unavailable");
                            return droidvm::web::host_network_catalog(host_network->available_interfaces(caller), host_network->uplinks(caller), host_network->addresses(caller));
                        }
                        , droidvm::web::network_operations(tasks, [&](const droidvm::CallContext& caller, const droidvm::web::NetworkOperation& operation) {
                            if (!network_runtime) throw droidvm::ServiceError(droidvm::ErrorCode::unavailable, "Network runtime unavailable");
                            network_runtime->change_if_matches(caller, operation.network_id, operation.start, operation.generation, operation.state, operation.configuration_revision);
                        })
                        , droidvm::web::network_deletion(tasks, {
                            [uploads = dispatcher.config_uploads()](const droidvm::CallContext& caller, const std::string& revision, size_t bytes) { return uploads->begin_delete(caller, revision, bytes); },
                            [uploads = dispatcher.config_uploads()](const droidvm::CallContext& caller, const std::string& id, size_t offset, std::string_view bytes) { return uploads->append_delete(caller, id, offset, bytes); },
                            [uploads = dispatcher.config_uploads()](const droidvm::CallContext& caller, const std::string& id) {
                                const auto deleted = uploads->commit_delete(caller, id);
                                Json::Value result; result["networkId"] = deleted.id;
                                result["vmRevision"] = deleted.vms->revision; result["persistence"] = "persisted";
                                return result;
                            },
                            [uploads = dispatcher.config_uploads()](const droidvm::CallContext& caller, const std::string& id) { uploads->abort_delete(caller, id); }
                        })
                        , droidvm::web::configuration_recovery(tasks, [&](const droidvm::CallContext& caller) { configuration->recover(caller); })
                        , [terminals](const droidvm::CallContext& caller, const std::string& id) { return droidvm::web::vm_terminal_list(*terminals, caller, id); }
                        , terminals
                        , droidvm::web::agent_operations(tasks,
                            [&, sessions = rescue_sessions](const droidvm::CallContext& caller, droidvm::agent::Request request,
                                const droidvm::agent::Confirmation& confirmed, droidvm::TaskControl& control, bool rescue) {
                                return droidvm::agent::run_managed(*configuration, caller, std::move(request), confirmed,
                                    tool_data_dir.empty() ? std::string("/data/data/") + DROIDVM_PACKAGE_NAME : tool_data_dir,
                                    control, rescue ? droidvm::agent::NativeRunOptions{sessions.get()} : droidvm::agent::NativeRunOptions{});
                            })
                        , droidvm::web::agent_recovery(tasks,
                            [&](const droidvm::CallContext&) { return vms->pending_orphaned_managed().size(); },
                            [&](const droidvm::CallContext&) {
                                Json::Value result(Json::objectValue);
                                result["pending"] = Json::UInt64(vms->recover_managed().size());
                                return result;
                            })
                        , droidvm::web::agent_rescue(tasks, *rescue_sessions)
                        , packages ? droidvm::web::package_exports(tasks,
                            [&](const droidvm::CallContext& caller, const std::string& id) {
                                return packages->export_plan(caller, id);
                            },
                            [&](const droidvm::CallContext& caller, const Json::Value& request,
                                const droidvm::pkg::ExportConfirmation& confirmed, const std::string& request_id) {
                                const auto result = packages->vm_export_checked(caller, request, confirmed, request_id);
                                return droidvm::TaskRef{result["epoch"].asString(), result["task_id"].asString()};
                            }) : droidvm::web::PackageExportOperations{}
                        , packages ? droidvm::web::package_imports(tasks,
                            [&](const droidvm::CallContext& caller, const std::string& source, const std::string& request_id) {
                                const auto result = packages->preview_import(caller, source, request_id);
                                return droidvm::TaskRef{result["epoch"].asString(), result["task_id"].asString()};
                            },
                            [&](const droidvm::CallContext& caller, const Json::Value& request,
                                const std::string& plan_request_id, const std::string& request_id) {
                                const auto result = packages->vm_import_checked(caller, request, plan_request_id, request_id);
                                return droidvm::TaskRef{result["epoch"].asString(), result["task_id"].asString()};
                            }) : droidvm::web::PackageImportOperations{}
                        , bind_package_transfers(tasks, package_transfers)
                        , bind_configuration_backup(tasks, dispatcher.config_uploads(), backups)
                        , {}
                        , droidvm::web::image_imports(tasks, {
                            [image_importer](const auto& caller, const auto& source, const auto& cancelled) {
                                return image_importer->preview(caller, source, cancelled);
                            },
                            [image_importer](const auto& caller, const auto& plan, auto& control) {
                                return image_importer->commit(caller, plan, control);
                            }
                        })
                        , bind_image_uploads(tasks, package_transfers, *configuration,
                            (tool_data_dir.empty() ? std::string("/data/data/") + DROIDVM_PACKAGE_NAME : tool_data_dir) + "/usr/bin/qemu-img")
                        , displays
                        , [&, host_overview, disk_capacity](const droidvm::CallContext& caller) {
                            auto result = host_overview->snapshot();
                            // These are independent service observations. A failed
                            // resource query stays unknown, never a fabricated zero.
                            try {
                                const auto rows = vms->list(caller);
                                if (rows.isArray()) {
                                    result.inventory.vm_count = static_cast<uint32_t>(rows.size());
                                    uint32_t running = 0;
                                    for (const auto& row : rows) if (droidvm::config::string(row, "state") == "RUNNING") ++running;
                                    result.inventory.running_vm_count = running;
                                }
                            } catch (const droidvm::ServiceError&) {}
                            try {
                                const auto rows = network_config->list(caller);
                                if (rows.isArray()) {
                                    result.inventory.network_count = static_cast<uint32_t>(rows.size());
                                    if (network_runtime) {
                                        uint32_t running = 0;
                                        for (const auto& row : rows)
                                            if (network_runtime->get(caller, droidvm::config::uuid(row)).state == droidvm::NetworkState::running) ++running;
                                        result.inventory.running_network_count = running;
                                    }
                                }
                            } catch (const droidvm::ServiceError&) {}
                            try {
                                if (configuration->disks()) {
                                    const auto snapshot = configuration->disks()->snapshot(caller);
                                    const auto& rows = snapshot->document["disks"];
                                    if (rows.isArray()) {
                                        result.inventory.disk_count = static_cast<uint32_t>(rows.size());
                                        std::vector<std::string> ids;
                                        ids.reserve(rows.size());
                                        for (const auto& row : rows) ids.push_back(droidvm::config::uuid(row));
                                        const auto capacity = disk_capacity->read(snapshot->revision, std::move(ids));
                                        result.inventory.disk_virtual_bytes = capacity.total_bytes;
                                        result.inventory.disk_virtual_known_count = capacity.known_count;
                                        result.inventory.disk_virtual_observed_at_ms = capacity.observed_at_ms;
                                    }
                                }
                            } catch (const droidvm::ServiceError&) {}
                            return droidvm::web::host_overview_catalog(result);
                        }
                        , hugepage_service ? droidvm::web::hugepage_operations({
                            [&](const droidvm::CallContext& caller) { return hugepage_service->snapshot(caller); },
                            [&](const droidvm::CallContext& caller, const Json::Value& request) { return hugepage_service->start(caller, request); },
                            [&](const droidvm::CallContext& caller, const std::string& request) { return hugepage_service->status(caller, request); }
                        }) : droidvm::web::HugepageOperations{}
                        , hugepage_process_service ? droidvm::web::hugepage_process_operations({
                            [&](const droidvm::CallContext& caller, const std::string& source) { return hugepage_process_service->snapshot(caller, source); },
                            [&](const droidvm::CallContext& caller, const Json::Value& expected) { return hugepage_process_service->stack(caller, expected); },
                            [&](const droidvm::CallContext& caller, const Json::Value& request) { return hugepage_process_service->start(caller, request); },
                            [&](const droidvm::CallContext& caller, const std::string& request) { return hugepage_process_service->status(caller, request); }
                        }) : droidvm::web::HugepageProcessOperations{}
                        , host_preferences ? droidvm::web::host_preference_operations({
                            [&](const droidvm::CallContext& caller) { return host_preferences->snapshot(caller); },
                            [&](const droidvm::CallContext& caller, const Json::Value& request) { return host_preferences->start(caller, request); },
                            [&](const droidvm::CallContext& caller, const std::string& request) { return host_preferences->status(caller, request); }
                        }) : droidvm::web::WebServiceOperations{}
                        , usb_acm ? droidvm::web::usb_acm_operations({
                            [&](const droidvm::CallContext& caller) { return usb_acm->snapshot(caller); },
                            [&](const droidvm::CallContext& caller, const Json::Value& request) { return usb_acm->start(caller, request); },
                            [&](const droidvm::CallContext& caller, const std::string& request) { return usb_acm->status(caller, request); }
                        }) : droidvm::web::WebServiceOperations{}
                        , disk_defaults ? droidvm::web::host_preference_operations({
                            [&](const droidvm::CallContext& caller) { return disk_defaults->snapshot(caller); },
                            [&](const droidvm::CallContext& caller, const Json::Value& request) { return disk_defaults->start(caller, request); },
                            [&](const droidvm::CallContext& caller, const std::string& request) { return disk_defaults->status(caller, request); }
                        }, droidvm::HostPreferenceDomain::disk_operations) : droidvm::web::WebServiceOperations{}
                        , [&](const droidvm::CallContext& caller, const std::string& id) {
                            const auto detail = disk_inspection->read(caller, id, true);
                            const auto references = droidvm::config::disk_references(detail.vms.document, detail.disks.document);
                            return droidvm::web::disk_detail(droidvm::web::disk_catalog(detail.disks, droidvm::config::disk_path,
                                droidvm::config::valid_disk_paths(detail.disks.document), references.bases),
                                detail.vms, id, detail.state, detail.image, detail.effective_compression);
                        }
                        , true
                    }, usb ? droidvm::web::usb_operations(tasks, [&](const droidvm::CallContext&, const droidvm::web::UsbOperation& operation) {
                        Json::Value params;
                        params["device"] = operation.sysfs;
                        params["target"] = operation.target["kind"] == "idle" ? Json::Value("sink") : operation.target["kind"];
                        if (operation.vm_observation) {
                            params["vm_id"] = operation.target["vmId"];
                            params["controller"] = operation.target["controllerId"];
                        }
                        try {
                            usb->set_target_checked(params, [&](const Json::Value& current) {
                                droidvm::web::require_usb_observation(operation, droidvm::web::usb_catalog(current));
                            }, operation.vm_observation);
                        } catch (const droidvm::usb::RequestError& error) {
                            throw droidvm::ServiceError(droidvm::ErrorCode::io_error, error.what());
                        }
                    }) : droidvm::web::UsbOperations{}, usb ? droidvm::web::usb_rules_configuration(tasks, {
                        [uploads = dispatcher.config_uploads()](const droidvm::CallContext& caller, const std::string& revision, size_t bytes) {
                            return uploads->begin_usb_rules(caller, revision, bytes);
                        },
                        [uploads = dispatcher.config_uploads()](const droidvm::CallContext& caller, const std::string& id, size_t offset, std::string_view bytes) {
                            return uploads->append_usb_rules(caller, id, offset, bytes);
                        },
                        [uploads = dispatcher.config_uploads()](const droidvm::CallContext& caller, const std::string& id) {
                            return uploads->commit_usb_rules(caller, id);
                        },
                        [uploads = dispatcher.config_uploads()](const droidvm::CallContext& caller, const std::string& id) { uploads->abort_usb_rules(caller, id); }
                    }, [&](const droidvm::CallContext&) { return usb->rules_snapshot(); },
                    [&](const droidvm::CallContext&) { return usb->rule_targets(); },
                    [&](const droidvm::CallContext&, const std::string& revision) { return usb->rules_preview(revision); }) : droidvm::web::ConfigOperations{}, std::move(session_persistence));
                auto rescue_maintenance = std::make_shared<RescueMaintenance>(rescue_sessions, package_transfers);
                dispatcher.set_web([&](const auto& caller, const auto& command, const auto& request) { return web->execute(caller, command, request); },
                    [&, rescue_maintenance] {
                        schedule_rescue_maintenance(tasks, rescue_maintenance);
                        web->schedule();
                    }, [&] { web->stop(); });
            }
#endif
            if (packages) dispatcher.set_packages(packages.get());
            if (configuration) {
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
                dispatcher.set_display_attach([&](const std::string& nonce, const Json::Value& profile) { display->attach(nonce, profile); });
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
#ifdef DROIDVM_WEB_HTTP_TRANSPORT
            if (!cleanup.attempt("WebUI", [&] { if (web) web->stop(); }, report_failure)) incomplete_worker_shutdown();
#endif
            cleanup.attempt("packages", [&] { if (packages) packages->shutdown(); }, report_failure);
            cleanup.attempt("disk operations", [&] { if (disk_operations) disk_operations->shutdown(); }, report_failure);
            if (!cleanup.attempt("tasks", [&] { tasks.shutdown(); }, report_failure)) incomplete_worker_shutdown();
            if (!cleanup.attempt("rescue sessions", [&] { close_rescue_sessions(rescue_sessions, vms); }, report_failure))
                incomplete_worker_shutdown();
            // VMs leave before USB/networks: their taps and devices go with them.
            if (!cleanup.attempt("VMs", [&] { if (vms) vms->stop_all(); }, report_failure)) incomplete_worker_shutdown();
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
