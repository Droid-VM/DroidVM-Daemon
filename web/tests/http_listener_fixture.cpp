// SPDX-License-Identifier: GPL-3.0-or-later
// Host/ABI integration fixture. Control is stdin, never a remote HTTP endpoint.
// Uses actual session/API/DTO/listener/TaskService; the VM inventory is synthetic.
#include "web/http_listener.h"
#include "web/listen_plan.h"
#include "web/vm_read_model.h"
#include "web/task_adapter.h"
#include "web/vm_operations.h"
#include "web/vm_logs.h"
#include "web/vm_terminal.h"
#include "web/vm_display.h"
#include "vm/vnc_stream.h"
#include "web/agent_rescue.h"
#include "web/event_channel.h"
#include "web/vm_configuration.h"
#include "web/resource_catalog.h"
#include "web/disk_operations.h"
#include "disk_fixture.h"
#include "agent_fixture.h"
#include "package_fixture.h"
#include "package_transfer_fixture.h"
#include "backup_fixture.h"
#include "image_import_fixture.h"
#include "image_upload_fixture.h"
#include "network_fixture.h"
#include "web/host_network.h"
#include "web/host_overview.h"
#include "hugepage_fixture.h"
#include "hugepage_process_fixture.h"
#include "host_preference_fixture.h"
#include "usb_acm_fixture.h"
#include "web/usb_operations.h"
#include "web/usb_rules.h"
#include "vm/defaults.h"
#include "common/wire.h"
#include "common/identity.h"
#include "services/tasks.h"
#include <algorithm>
#include <atomic>
#include <charconv>
#include <future>
#include <iostream>
#include <mutex>
#include <thread>

using namespace droidvm;
using namespace droidvm::web;
namespace {
const CallContext local{"local-admin", true, true, true};
struct SyntheticVm {
    std::mutex mutex;
    std::unique_ptr<vm::RuntimeVersion> version = std::make_unique<vm::RuntimeVersion>();
    std::string state = "RUNNING";
    unsigned effects = 0;
    unsigned terminal_writes = 0;
    size_t terminal_accepted = 0;
    bool terminal_partial = false;
    std::string terminal_input;
    uint16_t display_port = 0, display_secondary_port = 0;
    uint64_t display_opens = 0, display_reads = 0, display_writes = 0, display_closes = 0;
    vm::ConsoleHistory history;
    SyntheticVm() { history.append("Boot log\n<script>plain text</script>\n"); }
    Json::Value actions() const {
        Json::Value result(Json::arrayValue);
        if (state == "STOPPED") result.append("start");
        else result.append("stop");
        if (state == "RUNNING") { result.append("reboot"); result.append("suspend"); }
        if (state == "SUSPENDED") result.append("resume");
        return result;
    }
    void apply(const CallContext& caller, const VmOperation& request) {
        if (!caller.principal.starts_with("web:")) throw std::runtime_error("Wrong operation identity");
        std::lock_guard lock(mutex);
        if (request.vm_id != "native-http-vm") throw ServiceError(ErrorCode::not_found, "VM not found");
        version->require(request.observed);
        if (request.action == "start" && request.config_revision != "fixture-config") throw ServiceError(ErrorCode::conflict, "Config changed");
        bool allowed = false;
        for (const auto& action : actions()) if (action == request.action) allowed = true;
        if (!allowed) throw ServiceError(ErrorCode::conflict, "Wrong VM state");
        version->admit(request.observed);
        ++effects;
        state = request.action == "stop" ? "STOPPED" : request.action == "suspend" ? "SUSPENDED" : "RUNNING";
        version->changed();
    }
};
// In-memory persistence stand-in only. Production binds the App's ConfigUploads
// and ConfigurationService; this fixture exercises HTTP, bytes, journal and tasks.
struct FixtureConfiguration {
    std::mutex mutex;
    TaskService& tasks;
    std::shared_ptr<SyntheticVm> runtime;
    std::shared_ptr<VmConfigSnapshot> saved;
    std::string upload, principal, expected, data;
    size_t total = 0;
    FixtureConfiguration(TaskService& pool, std::shared_ptr<SyntheticVm> vm) : tasks(pool), runtime(std::move(vm)) {
        saved = std::make_shared<VmConfigSnapshot>();
        saved->document = wire::parse(R"({"extension":{"counter":18446744073709551615},"vms":[{"id":"native-http-vm","name":"原生 HTTP 虚拟机","backend":"qemu","cpu_count":4,"memory_mb":2048,"opaque":{"counter":9007199254740993},"boot":{"protocol":"uefi"}}]})");
        saved->revision = "fixture-config"; saved->persisted = true;
        saved->encoded = std::make_shared<const std::string>(wire::stringify(saved->document));
        tasks.publish_vm_config(saved);
    }
    std::shared_ptr<const VmConfigSnapshot> snapshot() { std::lock_guard lock(mutex); return saved; }
    ConfigStaging staging() {
        return {
            [this](const CallContext& caller, const std::string& revision, size_t bytes) {
                std::lock_guard lock(mutex);
                if (!upload.empty()) throw ServiceError(ErrorCode::resource_exhausted, "Fixture upload occupied");
                if (revision != saved->revision) throw ServiceError(ErrorCode::conflict, "Revision changed");
                upload = random_id(true); principal = caller.principal; expected = revision; total = bytes; data.clear();
                return upload;
            },
            [this](const CallContext& caller, const std::string& id, size_t offset, std::string_view bytes) {
                std::lock_guard lock(mutex);
                if (id != upload || principal != caller.principal) throw ServiceError(ErrorCode::not_found, "Upload missing");
                if (offset != data.size() || bytes.size() > total - data.size()) throw ServiceError(ErrorCode::invalid_argument, "Wrong offset");
                data.append(bytes); return data.size();
            },
            [this](const CallContext& caller, const std::string& id) -> std::shared_ptr<const VmConfigSnapshot> {
                std::lock_guard lock(mutex);
                if (id != upload || principal != caller.principal) throw ServiceError(ErrorCode::not_found, "Upload missing");
                upload.clear();
                if (data.size() != total) throw ServiceError(ErrorCode::invalid_argument, "Incomplete upload");
                if (expected != saved->revision) throw ServiceError(ErrorCode::conflict, "Revision changed");
                { std::lock_guard vm_lock(runtime->mutex); if (runtime->state != "STOPPED") throw ServiceError(ErrorCode::conflict, "VM running"); }
                auto next = std::make_shared<VmConfigSnapshot>(); next->document = wire::parse(data);
                if (!next->document["vms"].isArray()) throw ServiceError(ErrorCode::invalid_argument, "Missing VMs");
                next->revision = random_id(true); next->persisted = true;
                next->encoded = std::make_shared<const std::string>(wire::stringify(next->document));
                saved = std::move(next); data.clear(); tasks.publish_vm_config(saved);
                return saved;
            },
            [this](const CallContext& caller, const std::string& id) {
                std::lock_guard lock(mutex);
                if (id == upload && principal == caller.principal) { upload.clear(); data.clear(); }
            }
        };
    }
};
struct FixtureUsb {
    std::mutex mutex;
    Json::Value native = wire::parse(R"({"available":true,"devices":[
        {"sysfs":"1-1.2","busnum":1,"devnum":3,"vid":"1234","pid":"abcd","manufacturer":"Fixture","product":"USB 键盘","serial":"same-serial","speed":"12","state":"hostuse","lock":false,"node":"/private/node"},
        {"sysfs":"1-1.3","busnum":1,"devnum":4,"vid":"1234","pid":"abcd","manufacturer":"Fixture","product":"USB 键盘","serial":"same-serial","speed":"12","state":"vmuse","lock":true,"attached_vm":"native-http-vm","attached_vm_name":"测试虚拟机","attached_controller":"xhci-0","attached_port":2,"auto_rule":{"private":"omit"}},
        {"sysfs":"2-1","busnum":2,"devnum":7,"vid":"abcd","pid":"0001","product":"USB 存储","state":"vmuse","lock":false}
    ],"targets":[{"vmId":"usb-fixture-vm","vmName":"USB 测试虚拟机","instanceId":"0123456789abcdef0123456789abcdef","revision":"9007199254740993","controllerId":"xhci-0"}]})");
    Json::Value list() { std::lock_guard lock(mutex); return usb_catalog(native); }
    void apply(const UsbOperation& operation) {
        std::lock_guard lock(mutex);
        require_usb_observation(operation, usb_catalog(native));
        for (auto& row : native["devices"]) if (row["sysfs"] == operation.sysfs) {
            const bool vm = operation.target["kind"] == "vm";
            row["state"] = vm ? "vmuse" : operation.target["kind"] == "host" ? "hostuse" : "idle";
            row["lock"] = !vm;
            row["attached_vm"] = vm ? operation.target["vmId"] : Json::Value();
            row["attached_vm_name"] = vm ? Json::Value("USB 测试虚拟机") : Json::Value();
            row["attached_controller"] = vm ? operation.target["controllerId"] : Json::Value();
            row["attached_port"] = vm ? Json::Value(3) : Json::Value();
        }
    }
};
// USB persistence remains an explicit in-memory stand-in. The actual shared
// ConfigUploads and JsonFile fault paths are covered by Android contracts.
struct FixtureUsbRules {
    std::mutex mutex;
    Json::Value document = wire::parse(R"({"version":1,"enabled":false,"exact":[],"port":[],"device":[],"any":[]})");
    std::string revision = "fixture-usb-rules", persistence = "persisted";
    std::string upload, principal, expected, data;
    size_t total = 0;
    bool uncertain = false;
    Json::Value snapshot() {
        std::lock_guard lock(mutex);
        Json::Value result; result["available"] = true; result["revision"] = revision;
        result["persistence"] = persistence; result["rules"] = document;
        result["private"] = "not-in-http";
        return result;
    }
    JsonConfigurationStaging staging() {
        return {
            [this](const CallContext& caller, const std::string& observed, size_t bytes) {
                std::lock_guard lock(mutex);
                if (!upload.empty()) throw ServiceError(ErrorCode::resource_exhausted, "Fixture upload occupied");
                if (observed != revision) throw ServiceError(ErrorCode::conflict, "Rules changed");
                upload = random_id(true); principal = caller.principal; expected = observed; total = bytes; data.clear();
                return upload;
            },
            [this](const CallContext& caller, const std::string& id, size_t offset, std::string_view bytes) {
                std::lock_guard lock(mutex);
                if (id != upload || principal != caller.principal) throw ServiceError(ErrorCode::not_found, "Rules upload missing");
                if (offset < data.size() && offset + bytes.size() <= data.size() && std::string_view(data).substr(offset, bytes.size()) == bytes) return data.size();
                if (offset != data.size() || bytes.size() > total - data.size()) throw ServiceError(ErrorCode::invalid_argument, "Wrong offset");
                data.append(bytes); return data.size();
            },
            [this](const CallContext& caller, const std::string& id) {
                std::lock_guard lock(mutex);
                if (id != upload || principal != caller.principal) throw ServiceError(ErrorCode::not_found, "Rules upload missing");
                if (data.size() != total) throw ServiceError(ErrorCode::invalid_argument, "Incomplete upload");
                upload.clear();
                if (expected != revision) throw ServiceError(ErrorCode::conflict, "Rules changed");
                auto next = wire::parse(data); data.clear();
                if (!next.isObject() || !next["enabled"].isBool()) throw ServiceError(ErrorCode::invalid_argument, "Invalid rules fixture");
                document = std::move(next); revision = random_id(true);
                if (uncertain) {
                    uncertain = false; persistence = "uncertain";
                    throw ServiceError(ErrorCode::commit_uncertain, "Fixture persistence uncertain");
                }
                persistence = "persisted";
                Json::Value result; result["revision"] = revision; result["persistence"] = persistence; result["applied"] = 0;
                return result;
            },
            [this](const CallContext& caller, const std::string& id) {
                std::lock_guard lock(mutex);
                if (id == upload && principal == caller.principal) { upload.clear(); data.clear(); }
            }
        };
    }
};
struct Owner {
    std::atomic<int64_t> clock_offset{0};
    SessionStore sessions{{}, [this] { return SessionStore::Clock::now() + std::chrono::seconds(clock_offset.load()); }};
    std::atomic<unsigned> delay{0}, size{0}, reads{0};
    std::atomic<unsigned> overview_mode{0}; // 0 ready, 1 first sample, 2 unavailable.
    std::atomic<bool> deny_peer{false};
    std::shared_ptr<SyntheticVm> runtime = std::make_shared<SyntheticVm>();
    std::shared_ptr<VmTerminalSource> terminal = make_terminal_source();
    std::shared_ptr<VmDisplaySource> displays = make_display_source();
    FixtureConfiguration configuration;
    FixtureUsb usb;
    FixtureUsbRules rules;
    FixtureHugepages hugepages;
    FixtureHugepageProcesses hugepage_processes;
    FixtureHostPreferences host_preferences;
    FixtureHostPreferences disk_defaults;
    FixtureUsbAcm usb_acm;
    std::shared_ptr<FixtureDisks> disks = std::make_shared<FixtureDisks>();
    std::shared_ptr<FixtureImageImport> image_import_storage = std::make_shared<FixtureImageImport>(disks);
    std::shared_ptr<FixtureImageUploads> image_upload_storage = std::make_shared<FixtureImageUploads>();
    FixtureAgent agent;
    FixtureNetworks networks;
    std::shared_ptr<FixturePackageTransfers> package_transfer_storage = std::make_shared<FixturePackageTransfers>();
    std::shared_ptr<FixtureBackup> backup_storage = std::make_shared<FixtureBackup>();
    HttpApi api;
    std::shared_ptr<VmTerminalSource> make_terminal_source() {
        // Synthetic echo only: real VM fd ownership and nonblocking writes have
        // a separate native contract. All stream access shares this VM mutex.
        return std::make_shared<VmTerminalSource>(VmTerminalSource{
            [state = runtime](const CallContext&, const std::string& id) {
                if (id != "native-http-vm") throw ServiceError(ErrorCode::not_found, "VM not found");
                std::lock_guard lock(state->mutex);
                return VmTerminalTarget{id, state->version->observe(), state->state == "RUNNING"
                    ? std::vector<std::string>{"uart"} : std::vector<std::string>{}};
            },
            [state = runtime](const CallContext&, const VmTerminalRead& request) {
                std::lock_guard lock(state->mutex);
                state->version->require(request.observed);
                if (request.vm_id != "native-http-vm" || request.stream != "uart")
                    throw ServiceError(ErrorCode::not_found, "Terminal not found");
                if (state->state != "RUNNING") throw ServiceError(ErrorCode::conflict, "VM stopped");
                return state->history.read(request.cursor, request.tail);
            },
            [state = runtime](const CallContext&, const VmTerminalWrite& request) {
                std::lock_guard lock(state->mutex);
                state->version->require(request.observed);
                if (request.vm_id != "native-http-vm" || request.stream != "uart")
                    throw ServiceError(ErrorCode::not_found, "Terminal not found");
                if (state->state != "RUNNING") throw ServiceError(ErrorCode::conflict, "VM stopped");
                if (request.bytes.empty() || request.bytes.size() > 512)
                    throw ServiceError(ErrorCode::invalid_argument, "Invalid terminal input size");
                const auto accepted = state->terminal_partial ? std::min<size_t>(2, request.bytes.size()) : request.bytes.size();
                state->terminal_partial = false;
                ++state->terminal_writes; state->terminal_accepted += accepted;
                state->terminal_input.append(request.bytes, 0, accepted);
                state->history.append(std::string_view(request.bytes).substr(0, accepted));
                return accepted;
            }
        });
    }
    std::shared_ptr<VmDisplaySource> make_display_source() {
        return std::make_shared<VmDisplaySource>(VmDisplaySource{
            [state = runtime](const CallContext&, const std::string& id) {
                if (id != "native-http-vm") throw ServiceError(ErrorCode::not_found, "VM not found");
                std::lock_guard lock(state->mutex);
                const std::string reason = state->state != "RUNNING" ? "not-running" : !state->display_port ? "invalid-endpoint" : "";
                // Opt-in independent TCP endpoint for the existing second screen.
                // Legacy probes retain the unavailable, non-VNC simplefb entry.
                const std::string secondary_reason = !state->display_secondary_port ? "not-vnc" : state->state != "RUNNING" ? "not-running" : "";
                return VmDisplayTarget{id, state->version->observe(), {
                    {"gpu-0", reason.empty(), reason, true},
                    {"simplefb", secondary_reason.empty(), secondary_reason, state->display_secondary_port != 0}
                }};
            },
            [state = runtime](const CallContext&, const std::string& id, const std::string& screen, const vm::Observation& expected) {
                uint16_t port = 0;
                {
                    std::lock_guard lock(state->mutex); state->version->require(expected);
                    port = screen == "gpu-0" ? state->display_port : screen == "simplefb" ? state->display_secondary_port : 0;
                    if (id != "native-http-vm" || state->state != "RUNNING" || !port)
                        throw ServiceError(ErrorCode::conflict, "Display unavailable");
                }
                auto stream = std::make_shared<vm::VncStream>("127.0.0.1", port,
                    [state, expected](const std::function<void()>& work) {
                        std::lock_guard lock(state->mutex); state->version->require(expected);
                        if (state->state != "RUNNING") throw ServiceError(ErrorCode::conflict, "VM stopped");
                        work();
                    });
                { std::lock_guard lock(state->mutex); ++state->display_opens; }
                auto closed = std::make_shared<std::atomic<bool>>(false);
                return VmDisplayStream{
                    [stream] { return stream->connected(); },
                    [stream, state](size_t maximum) { auto bytes = stream->read(maximum); std::lock_guard lock(state->mutex); state->display_reads += bytes.size(); return bytes; },
                    [stream, state](std::string_view bytes) { const auto accepted = stream->write(bytes); std::lock_guard lock(state->mutex); state->display_writes += accepted; return accepted; },
                    [stream, state, closed] { stream->close(); if (!closed->exchange(true)) { std::lock_guard lock(state->mutex); ++state->display_closes; } },
                    "web-test"
                };
            }
        });
    }
    explicit Owner(uint16_t port, TaskService& tasks) : configuration(tasks, runtime), host_preferences(tasks), disk_defaults(tasks, HostPreferenceDomain::disk_operations), usb_acm(tasks), networks(tasks), api(sessions, {
        {"127.0.0.1:" + std::to_string(port), "http://127.0.0.1:" + std::to_string(port)},
        {"[::1]:" + std::to_string(port), "http://[::1]:" + std::to_string(port)},
        {"127.0.0.1:5178", "http://127.0.0.1:5178"}
    }, [this](const CallContext& caller) {
        if (!caller.authenticated || !caller.principal.starts_with("web:")) throw std::runtime_error("wrong service identity");
        ++reads;
        std::this_thread::sleep_for(std::chrono::milliseconds(delay.load()));
        const auto config = configuration.snapshot();
        Json::Value rows(Json::arrayValue), vm;
        if (config->document["vms"].empty()) return vm_snapshot(rows, config.get());
        const Json::Value* original = nullptr;
        for (const auto& definition : config->document["vms"])
            if (definition["id"] == "native-http-vm") original = &definition;
        if (original) {
            vm["id"] = "native-http-vm"; vm["name"] = size ? std::string(size, 'x') : "原生 HTTP 虚拟机";
            if (!size) vm["name"] = (*original)["name"];
            std::lock_guard lock(runtime->mutex);
            vm["state"] = runtime->state; vm["backend"] = "qemu";
            const auto observed = runtime->version->observe();
            vm["runtime_instance"] = observed.instance; vm["runtime_revision"] = std::to_string(observed.revision);
            vm["runtime_actions"] = runtime->actions(); vm["runtime_uncertain"] = false;
            vm["cpu_count"] = 4; vm["memory_mb"] = 2048;
            vm["password"] = "fixture-private-password"; rows.append(vm);
        }
        // Newly saved configurations appear as stopped fixture VMs. Lifecycle
        // execution remains available only for the original synthetic runtime.
        for (const auto& definition : config->document["vms"]) {
            if (definition["id"] == "native-http-vm") continue;
            Json::Value added = definition;
            added["state"] = "STOPPED";
            added["runtime_instance"] = "cccccccccccccccccccccccccccccccc";
            added["runtime_revision"] = "0";
            added["runtime_actions"] = Json::Value(Json::arrayValue);
            added["runtime_uncertain"] = false;
            rows.append(std::move(added));
        }
        return vm_snapshot(rows, config.get());
    }, {tasks.epoch(), {"native-fixture", "9007199254740993"}}, embedded_assets(), task_operations(tasks),
        vm_operations(tasks, [state = runtime, &tasks](const auto& caller, const auto& request) {
            state->apply(caller, request); tasks.publish_vm_runtime(request.vm_id);
        }),
        vm_logs({
            [state = runtime](const CallContext&, const std::string& id) {
                if (id != "native-http-vm") throw ServiceError(ErrorCode::not_found, "VM not found");
                std::lock_guard lock(state->mutex);
                return VmLogTarget{id, state->version->observe().instance, {"stdio", "agent"}};
            },
            [state = runtime](const CallContext&, const VmLogRead& request) {
                if (request.vm_id != "native-http-vm" || request.stream != "stdio") throw ServiceError(ErrorCode::not_found, "Log not found");
                std::lock_guard lock(state->mutex);
                if (state->version->observe().instance != request.instance_id) throw ServiceError(ErrorCode::conflict, "VM replaced");
                return state->history.read(request.cursor, request.tail);
            }
        }), true, vm_configuration(tasks, configuration.staging(), [](const CallContext&) {
            return vm::new_vm_defaults("/fixture/data", "GUNYAH", "SM8650");
        }), {
            [storage = disks](const CallContext&) { return storage->catalog(); },
            [this](const CallContext&) { return networks.catalog(); },
            [](const CallContext&) {
                return audio_catalog(wire::parse(R"({"available":true,"fingerprint":"private-omit","devices":[
                    {"key":"BUILTIN_SPEAKER|","name":"手机扬声器","input":false,"kind":1,"selectable":true,"id":3},
                    {"key":"BUILTIN_MIC|bottom","name":"手机麦克风","input":true,"kind":6,"selectable":true,"id":4},
                    {"key":"BUILTIN_SPEAKER|","name":"重复端点","input":false,"kind":1,"selectable":true,"id":5},
                    {"key":"REMOTE_SUBMIX|","name":"内部路由","input":false,"kind":1,"selectable":false,"id":6}
                ]})"));
            },
            [this](const CallContext&) { return usb.list(); },
            [](const CallContext&) {
                // Fixed hardware observation; the sysfs reader has a separate contract.
                return cpu_catalog({{0, 1800000, 512, false, true}, {1, 1800000, 512, false, true},
                    {4, 2800000, 896, true, true}, {7, 3200000, 1024, false, false},
                    {9, 0, 0, false, {}}});
            },
            [](const CallContext&) {
                vm::HostDeviceFacts facts;
                facts.kvm = true; facts.gunyah = false; facts.geniezone = {};
                facts.kgsl = false; facts.turnip = false; facts.system_vulkan = true;
                facts.system_vulkan_hal = "/private/vendor/vulkan.fixture.so";
                return host_device_catalog(facts, wire::parse(R"({"state":"known","missingExtensions":["VK_EXT_image_drm_format_modifier"],"checkedAtMs":1792339200000,"private":"omit"})"));
            },
            [storage = disks](const CallContext&, const std::string& id) { return storage->detail(id); },
            disk_operations(tasks, [storage = disks](const CallContext&, const Json::Value& request, TaskControl& control) { return storage->execute(request, control); }),
            disk_recovery(tasks, [storage = disks](const CallContext&) { return storage->pending(); }, [storage = disks](const CallContext&) { return storage->recover(); }),
            network_configuration(tasks, networks.staging()),
            [this](const CallContext&, const std::string& id) { return networks.detail(id, *configuration.snapshot()); },
            [](const CallContext&) {
                return host_network_catalog(
                    wire::parse(R"([{"name":"wlan0","state":"UP","master":"","private":"omit"},{"name":"eth0","state":"UP","master":""}])"),
                    wire::parse(R"({"identifiers":[{"id":"WiFi","name":"wlan0","bridgeable":false},{"id":"Ethernet","name":"eth0","bridgeable":true},{"id":"Tethering","name":"","bridgeable":false}],"devices":[{"name":"eth0","bridgeable":true}]})"),
                    wire::parse(R"([{"addr":"192.0.2.10","ifname":"wlan0","family":4},{"addr":"2001:db8::10","ifname":"wlan0","family":6}])"));
            },
            network_operations(tasks, [this](const CallContext&, const NetworkOperation& operation) { networks.execute(operation); }),
            network_deletion(tasks, networks.deletion_staging([this](const Json::Value& expected, const std::string& revision) {
                std::lock_guard lock(configuration.mutex);
                return networks.erase(expected, revision, configuration.saved, [this] {
                    std::lock_guard vm_lock(runtime->mutex);
                    if (runtime->state != "STOPPED") throw ServiceError(ErrorCode::conflict, "Referenced VM is running");
                });
            })),
            configuration_recovery(tasks, [this](const CallContext&) { networks.recover_configuration(); }),
            [this](const CallContext& caller, const std::string& id) { return vm_terminal_list(*terminal, caller, id); },
            terminal,
            agent_operations(tasks, [this](const CallContext& caller, droidvm::agent::Request request,
                const droidvm::agent::Confirmation& confirmed, TaskControl& control, bool rescue) {
                return agent.execute(caller, std::move(request), confirmed, control, rescue);
            }),
            agent_recovery(tasks, [this](const CallContext&) { return agent.pending(); },
                [this](const CallContext&) { return agent.recover(); }),
            agent_rescue(tasks, agent.rescues),
            fixture_package_exports(tasks),
            fixture_package_imports(tasks),
            package_transfers(tasks, package_transfer_storage->bindings()),
            backup_configuration(tasks, backup_storage->bindings()),
            {},
            image_imports(tasks, image_import_storage->bindings()),
            image_uploads(tasks, image_upload_storage->bindings()),
            displays,
            [this](const CallContext&) {
                // Deliberate fixed observations for browser contracts; never a
                // native hardware probe or production statistics fallback.
                HostOverview value;
                value.observed_at_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
                value.daemon = {4242, "native-fixture"};
                const auto mode = overview_mode.load();
                if (mode != 2) {
                    value.host = {"6.1.0-fixture", "aarch64", "Fixture Phone", "SM8650"};
                    value.cpu.logical_count = 8;
                    if (mode == 0) { value.cpu.usage_percent = 37.5; value.cpu.sample_window_ms = 3000; }
                    value.memory = {8589934592ULL, 3221225472ULL};
                    value.storage = {137438953472ULL, 68719476736ULL, 64424509440ULL};
                    value.inventory = {3, 1, 2, 1, 4, {}, {}, {}};
                }
                return host_overview_catalog(value);
            },
            hugepage_operations(hugepages.bindings(tasks)),
            hugepage_process_operations(hugepage_processes.bindings(tasks)),
            host_preference_operations(host_preferences.bindings()),
            usb_acm_operations(usb_acm.bindings()),
            host_preference_operations(disk_defaults.bindings(), HostPreferenceDomain::disk_operations),
            [storage = disks](const CallContext&, const std::string& id) { return storage->detail(id, true); },
            true
        }, usb_operations(tasks, [this](const CallContext&, const UsbOperation& operation) { usb.apply(operation); }),
        usb_rules_configuration(tasks, rules.staging(), [this](const CallContext&) { return rules.snapshot(); },
            [](const CallContext&) { return wire::parse(R"([
                {"vmId":"stopped-fixture-vm","vmName":"已停止的规则虚拟机","controllerId":"xhci-0","private":"omit"},
                {"vmId":"no-usb-fixture-vm","vmName":"没有 USB 控制器","controllerId":null}
            ])"); }, [this](const CallContext&, const std::string& expected) {
                // Deterministic projection fixture only, not a second rule engine.
                // The browser scenario uses an any[0] sink or the default host.
                std::scoped_lock lock(rules.mutex, usb.mutex);
                if (expected != rules.revision) throw ServiceError(ErrorCode::conflict, "Rules changed");
                auto result = usb.native;
                result["targets"] = Json::Value(Json::arrayValue);
                result["revision"] = rules.revision; result["persistence"] = rules.persistence;
                result["enabled"] = rules.document["enabled"];
                for (auto& device : result["devices"]) {
                    const bool enabled = rules.document["enabled"].asBool();
                    device["eligible"] = enabled && device["state"] != "vmuse" && !device["lock"].asBool();
                    device["result"] = Json::Value();
                    if (enabled) {
                        auto decision = wire::parse(R"({"layer":null,"index":-1,"target":"host","vm":null,"controller":null,"private":"omit"})");
                        if (rules.document["any"].isArray() && !rules.document["any"].empty() && rules.document["any"][0]["target"] == "sink") {
                            decision["layer"] = "any"; decision["index"] = 0; decision["target"] = "sink";
                        }
                        device["result"] = std::move(decision);
                    }
                }
                return result;
            })) {}
};
void output(Json::Value value) {
    Json::StreamWriterBuilder writer; writer["indentation"] = "";
    std::cout << Json::writeString(writer, value) << std::endl;
}
}
int main(int argc, char** argv) {
    if (argc != 2 && (argc != 3 || std::string_view(argv[2]) != "--dual-stack")) return 2;
    const bool dual_stack = argc == 3;
    unsigned port = 0; const std::string text = argv[1];
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), port);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() || port < 1024 || port > 65535) return 2;
    try {
        TaskLimits limits; limits.background_workers = 1;
        limits.max_result_bytes = 256u << 10;
        TaskService workers(limits);
        std::shared_ptr<Owner> owner;
        std::vector<std::unique_ptr<HttpListener>> listeners;
        const auto start = [&] {
            owner = std::make_shared<Owner>(static_cast<uint16_t>(port), workers);
            // Empty trusted discovery yields only loopback, never LAN/all.
            const auto plan = make_listen_plan({}, ListenScope::lan, dual_stack);
            for (const auto& endpoint : plan.endpoints) {
                HttpListenConfig config; config.port = static_cast<uint16_t>(port); config.address = endpoint.address;
                config.request_timeout = std::chrono::seconds(3);
                config.allow_peer = [state = owner, endpoint](std::string_view peer) { return !state->deny_peer && endpoint.allows(peer); };
                auto listener = std::make_unique<HttpListener>(std::move(config), workers,
                    [state = owner](const auto& request) {
                        auto response = state->api.handle(request);
                        if (response.stream) {
                            auto read = std::move(response.stream->read);
                            response.stream->read = [state, read = std::move(read)](uint64_t offset, size_t maximum) {
                                return read(offset, maximum);
                            };
                        }
                        return response;
                    },
                    [state = owner, &workers](const HttpRequest& request) -> AsyncHttp::Handle {
                        if (request.path == "/api/v1/display") {
                            auto quota = state->api.reserve_display(request);
                            auto channel = std::make_shared<VmDisplayChannel>(*state->api.display_source(), workers.epoch(),
                                [state, request](const Json::Value& frame) { return state->api.authorize_display(request, frame); }, std::move(quota));
                            return [channel](const HttpRequest& frame) { return channel->next(frame); };
                        }
                        if (request.path == "/api/v1/terminal" || request.path == "/api/v1/agent-rescue-terminal") {
                            auto channel = std::make_shared<VmTerminalChannel>(*state->api.terminal_source(request.path), workers.epoch(),
                                [state, request](const Json::Value& frame) { return state->api.authorize_terminal(request, frame); });
                            return [channel](const HttpRequest& frame) { return channel->next(frame); };
                        }
                        auto channel = std::make_shared<EventChannel>(workers, [state, request](const Json::Value& frame) {
                            return state->api.authorize_events(request, frame);
                        });
                        return [channel](const HttpRequest& frame) { return channel->next(frame); };
                    });
                listener->start(); listeners.push_back(std::move(listener));
            }
        };
        start(); Json::Value ready; ready["ready"] = true; output(ready);
        for (std::string line; std::getline(std::cin, line);) {
            Json::Value result(Json::objectValue);
            if (line == "pair") result["pairingToken"] = owner->sessions.issue_pairing(local).token;
            else if (line == "transfer-stats") result = owner->package_transfer_storage->stats();
            else if (line == "backup-stats") result = owner->backup_storage->stats();
            else if (line == "image-import-stats") result = owner->image_import_storage->stats();
            else if (line == "image-upload-stats") result = owner->image_upload_storage->stats();
            else if (line == "host-preferences-stats") result = owner->host_preferences.stats(local);
            else if (line == "disk-defaults-stats") result = owner->disk_defaults.stats(local);
            else if (line == "disk-defaults-external") {
                owner->disk_defaults.external(); result = owner->disk_defaults.stats(local);
            } else if (line == "disk-defaults-legacy") {
                Json::Value legacy; legacy["vm_optimize_compression"] = "ask"; legacy["qemu_img_cpu_affinity"] = "0-1";
                owner->disk_defaults.service.sync_legacy(local, legacy); result = owner->disk_defaults.stats(local);
            } else if (line.starts_with("disk-defaults-mode ")) {
                const auto mode = line.substr(std::string_view("disk-defaults-mode ").size());
                if (mode != "ready" && mode != "not-saved" && mode != "installed-uncertain")
                    throw std::invalid_argument("Invalid disk defaults fixture mode");
                { std::lock_guard lock(owner->disk_defaults.mutex); owner->disk_defaults.mode = mode; }
                result = owner->disk_defaults.stats(local);
            }
            else if (line == "usb-acm-stats") result = owner->usb_acm.stats(local);
            else if (line == "usb-acm-external") {
                owner->usb_acm.external(); result = owner->usb_acm.stats(local);
            } else if (line == "usb-acm-legacy") {
                Json::Value legacy; legacy["usb_acm_enable"] = false; legacy["usb_acm_ports"] = 4;
                owner->usb_acm.service.sync_legacy(local, legacy); result = owner->usb_acm.stats(local);
            } else if (line.starts_with("usb-acm-mode ")) {
                owner->usb_acm.set_mode(line.substr(std::string_view("usb-acm-mode ").size()));
                result = owner->usb_acm.stats(local);
            }
            else if (line == "host-preferences-external") {
                owner->host_preferences.external(); result = owner->host_preferences.stats(local);
            } else if (line == "host-preferences-legacy") {
                Json::Value legacy;
                legacy["vm_hugepage_auto_reserve"] = true; legacy["optimize_sdcard"] = true;
                legacy["vm_clear_logs_before_start"] = false;
                owner->host_preferences.service.sync_legacy(local, legacy);
                result = owner->host_preferences.stats(local);
            } else if (line.starts_with("host-preferences-mode ")) {
                const auto mode = line.substr(std::string_view("host-preferences-mode ").size());
                if (mode != "ready" && mode != "not-saved" && mode != "installed-uncertain")
                    throw std::invalid_argument("Invalid host preference fixture mode");
                { std::lock_guard lock(owner->host_preferences.mutex); owner->host_preferences.mode = mode; }
                result = owner->host_preferences.stats(local);
            }
            else if (line == "hugepage-process-stats" || line == "hugepage-process-touch" || line.starts_with("hugepage-process-mode ")) {
                std::lock_guard lock(owner->hugepage_processes.mutex);
                if (line == "hugepage-process-touch") ++owner->hugepage_processes.revision;
                if (line.starts_with("hugepage-process-mode ")) {
                    const auto mode = line.substr(std::string_view("hugepage-process-mode ").size());
                    if (mode != "ready" && mode != "fallback" && mode != "empty" && mode != "unknown" && mode != "partial" &&
                        mode != "legacy" && mode != "d-state" && mode != "uncertain" && mode != "exited" && mode != "reused")
                        throw std::invalid_argument("Invalid hugepage process fixture mode");
                    owner->hugepage_processes.mode = mode; ++owner->hugepage_processes.revision;
                }
                result["mode"] = owner->hugepage_processes.mode;
                result["reads"] = Json::UInt64(owner->hugepage_processes.reads);
                result["stackReads"] = Json::UInt64(owner->hugepage_processes.stack_reads);
                result["effects"] = Json::UInt64(owner->hugepage_processes.effects);
            }
            else if (line == "hugepage-stats" || line == "hugepage-touch" || line.starts_with("hugepage-mode ")) {
                std::lock_guard lock(owner->hugepages.mutex);
                if (line == "hugepage-touch") ++owner->hugepages.revision;
                if (line.starts_with("hugepage-mode ")) {
                    const auto mode = line.substr(14);
                    if (mode != "ready" && mode != "unknown" && mode != "busy" && mode != "uncertain" && mode != "partial" &&
                        mode != "idle" && mode != "unloaded" && mode != "legacy" && mode != "readonly")
                        throw std::invalid_argument("Invalid hugepage fixture mode");
                    owner->hugepages.set_mode(mode);
                }
                result["mode"] = owner->hugepages.mode;
                result["reads"] = Json::UInt64(owner->hugepages.reads);
                result["effects"] = Json::UInt64(owner->hugepages.effects);
                result["loaded"] = owner->hugepages.module_loaded;
                result["consumerCount"] = owner->hugepages.consumers;
            }
            else if (line.starts_with("host-overview-mode ")) {
                const auto mode = line.substr(19);
                if (mode != "ready" && mode != "first" && mode != "unavailable")
                    throw std::invalid_argument("Invalid host overview fixture mode");
                owner->overview_mode = mode == "ready" ? 0u : mode == "first" ? 1u : 2u;
                result["mode"] = mode;
            }
            else if (line == "display-stats" || line.starts_with("display-endpoint ") || line.starts_with("display-secondary-endpoint ")) {
                std::lock_guard lock(owner->runtime->mutex);
                if (line != "display-stats") {
                    const bool secondary = line.starts_with("display-secondary-endpoint ");
                    const auto value = line.substr(secondary ? 27 : 17); uint32_t endpoint_port = 0;
                    const auto converted = std::from_chars(value.data(), value.data() + value.size(), endpoint_port);
                    if (converted.ec != std::errc() || converted.ptr != value.data() + value.size() || endpoint_port < 1024 || endpoint_port > 65535)
                        throw std::invalid_argument("Invalid display fixture port");
                    if (endpoint_port == (secondary ? owner->runtime->display_port : owner->runtime->display_secondary_port))
                        throw std::invalid_argument("Display fixture endpoints must be independent");
                    (secondary ? owner->runtime->display_secondary_port : owner->runtime->display_port) = static_cast<uint16_t>(endpoint_port);
                    owner->runtime->version->changed();
                }
                result["opens"] = Json::UInt64(owner->runtime->display_opens); result["readBytes"] = Json::UInt64(owner->runtime->display_reads);
                result["writeBytes"] = Json::UInt64(owner->runtime->display_writes); result["closes"] = Json::UInt64(owner->runtime->display_closes);
            }
            else if (line == "terminal-stats" || line == "terminal-partial" || line == "terminal-change" || line == "terminal-replace" || line == "terminal-output") {
                std::lock_guard lock(owner->runtime->mutex);
                if (line == "terminal-partial") owner->runtime->terminal_partial = true;
                if (line == "terminal-change") owner->runtime->version->changed();
                if (line == "terminal-replace") owner->runtime->version = std::make_unique<vm::RuntimeVersion>();
                if (line == "terminal-output") owner->runtime->history.append("\x1b[31m" "红色终端" "\x1b[0m\r\n" "中文输出\r\n");
                result["writes"] = owner->runtime->terminal_writes;
                result["accepted"] = Json::UInt64(owner->runtime->terminal_accepted);
                result["input"] = wire::encode_base64(owner->runtime->terminal_input);
            }
            else if (line == "network-deletion-uncertain" || line == "network-deletion-stats") {
                std::lock_guard lock(owner->networks.mutex);
                if (line == "network-deletion-uncertain") owner->networks.uncertain_deletion = true;
                result["deletions"] = owner->networks.deletions; result["recoveries"] = owner->networks.recoveries;
                result["recoveryPending"] = owner->networks.recovery_pending;
                unsigned running = 0;
                for (const auto& [id, state] : owner->networks.runtime) { (void)id; if (state.running) ++running; }
                result["runningNetworks"] = running;
            }
            else if (line == "usb-rules-touch" || line == "usb-rules-uncertain") {
                std::lock_guard lock(owner->rules.mutex);
                if (line == "usb-rules-touch") owner->rules.revision = random_id(true);
                else owner->rules.uncertain = true;
                result["changed"] = true;
            }
            else if (line == "vm-event") { workers.publish_vm_runtime("native-http-vm"); result["published"] = true; }
            else if (line == "agent-grow-success" || line == "agent-grow-uncertain") {
                owner->agent.set_grow_success(line == "agent-grow-success"); result["configured"] = true;
            }
            else if (line == "config-touch") {
                std::lock_guard lock(owner->configuration.mutex);
                auto next = std::make_shared<VmConfigSnapshot>(*owner->configuration.saved);
                next->revision = random_id(true); owner->configuration.saved = next;
                workers.publish_vm_config(next); result["changed"] = true;
            }
            else if (line.starts_with("log ") && line.size() <= (128u << 10)) {
                std::lock_guard lock(owner->runtime->mutex); owner->runtime->history.append(line.substr(4) + "\n"); result["appended"] = true;
            }
            else if (line == "log-clear" || line == "log-fill") {
                std::lock_guard lock(owner->runtime->mutex); owner->runtime->history.clear();
                if (line == "log-fill") owner->runtime->history.append(std::string(65535, 'x') + "\xe4\xb8\xad-end\n");
                result["configured"] = true;
            }
            else if (line == "task") {
                const auto ref = workers.submit(local, {"disk_operation", "fixture-disk", 4096, true, true}, [](TaskControl& control) {
                    control.progress({"copy", "bytes", 9007199254740993ULL, 18014398509481986ULL});
                    while (!control.cancellation_requested()) std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    return TaskCompletion::cancelled();
                });
                result["taskId"] = ref.id;
            }
            else if (line.starts_with("revoke ")) { owner->sessions.revoke(local, line.substr(7)); result["revoked"] = true; }
            else if (line == "expire") { owner->clock_offset += 1801; result["expired"] = true; }
            else if (line.starts_with("delay ") || line.starts_with("large ")) {
                unsigned value = 0; const auto number = std::string_view(line).substr(6);
                const auto read = std::from_chars(number.data(), number.data() + number.size(), value);
                if (read.ec != std::errc{} || read.ptr != number.data() + number.size() || value > (line[0] == 'd' ? 4000u : 5u << 20)) return 2;
                if (line[0] == 'd') owner->delay = value; else owner->size = value;
                result["configured"] = true;
            } else if (line == "deny" || line == "allow") { owner->deny_peer = line == "deny"; result["configured"] = true; }
            else if (line == "stats") {
                result["reads"] = owner->reads.load(); result["epoch"] = workers.epoch();
                std::lock_guard lock(owner->runtime->mutex); result["vmEffects"] = owner->runtime->effects;
            }
            else if (line == "stop") {
                listeners.clear(); owner->sessions.clear();
                // This must still succeed: stopping WebUI must not shut workers.
                auto completed = std::make_shared<std::promise<bool>>(); auto future = completed->get_future();
                workers.post(local, [completed](bool discarded) { completed->set_value(!discarded); });
                if (future.wait_for(std::chrono::seconds(5)) != std::future_status::ready || !future.get()) return 1;
                result["workersAlive"] = true;
            } else if (line == "start" && listeners.empty()) { start(); result["ready"] = true; }
            else if (line == "quit") break;
            else return 2;
            output(result);
        }
        listeners.clear(); workers.shutdown(); owner->agent.rescues.shutdown();
        return 0;
    } catch (...) { std::cerr << "HTTP fixture failed\n"; return 1; }
}
