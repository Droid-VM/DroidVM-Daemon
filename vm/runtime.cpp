// SPDX-License-Identifier: GPL-3.0-or-later
// Port of daemon/vm/VMInstance's lifecycle and the crosvm/QEMU backend
// instances' start, cleanup and runControlCommand.
#include "runtime.h"
#include "vm/boot_plan.h"
#include "vm/crosvm_command.h"
#include "vm/qemu_command.h"
#include "vm/host_facts.h"
#include "vm/command_common.h"
#include "runtime/helper_identity.h"
#include "services/legacy_events.h"
#include "store/network_config.h"
#include "store/vm_config.h"
#include "common/identity.h"
#include "vm/qmp_control.h"
#include "vm/console_write.h"
#include "vm/console_busy.h"
#include <algorithm>
#include <array>
#include <bit>
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <climits>
#include <fcntl.h>
#include <filesystem>
#include <glob.h>
#include <netinet/in.h>
#include <poll.h>
#include <random>
#include <set>
#include <signal.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <thread>
#include <tuple>
#include <unistd.h>

extern char** environ;

namespace droidvm::vm {
namespace {
using namespace std::chrono_literals;
constexpr std::array state_names{"STOPPED", "STARTING", "RUNNING", "SUSPENDED", "STOPPING", "REBOOTING"};
constexpr int crosvm_reset = 32; // CrosvmExit.RESET
std::string lower(std::string text) { for (auto& c : text) if (c >= 'A' && c <= 'Z') c += 'a' - 'A'; return text; }
Json::Value& child(Json::Value& parent, const char* key) {
    if (!parent[key].isObject()) parent[key] = Json::Value(Json::objectValue);
    return parent[key];
}
void require_private_config(const Json::Value& value) {
    // This is a trusted rescue-runtime capability, not a user-facing VM option.
    // Restrict channels before any command construction can create file/USB/
    // syslog consoles or inject tracing and alternative character devices.
    auto reject = [] { throw std::invalid_argument("Invalid private VM configuration"); };
    if (!value.isObject()) reject();
    const auto& backend = config::member(value, "backend");
    const auto& agent = config::member(value, "agent_mode");
    const auto& strace = config::member(value, "strace");
    if (!backend.isString() || (backend.asString() != "qemu" && backend.asString() != "QEMU") ||
        !agent.isBool() || !agent.asBool() || (!strace.isNull() && (!strace.isBool() || strace.asBool()))) reject();
    for (const char* key : {"extra_options", "environment_variables", "networks", "peripherals", "shared_dirs", "serial_ports"}) {
        const auto& entries = config::member(value, key);
        if (!entries.isNull() && (!entries.isArray() || !entries.empty())) reject();
    }
}
// new String(bytes, UTF_8): malformed sequences become U+FFFD.
std::string utf8_lossy(std::string_view bytes) {
    std::string out;
    out.reserve(bytes.size());
    for (size_t i = 0; i < bytes.size();) {
        const auto c = static_cast<unsigned char>(bytes[i]);
        size_t length = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
        bool valid = length && i + length <= bytes.size();
        for (size_t k = 1; valid && k < length; ++k) valid = (static_cast<unsigned char>(bytes[i + k]) >> 6) == 2;
        if (valid && length > 1) {
            uint32_t code = c & (0xff >> (length + 1));
            for (size_t k = 1; k < length; ++k) code = code << 6 | (static_cast<unsigned char>(bytes[i + k]) & 0x3f);
            valid = code <= 0x10ffff && !(code >= 0xd800 && code <= 0xdfff) &&
                code >= (length == 2 ? 0x80u : length == 3 ? 0x800u : 0x10000u);
        }
        if (!valid) { out += "\xef\xbf\xbd"; ++i; continue; }
        out.append(bytes.substr(i, length));
        i += length;
    }
    return out;
}
void write_quiet(const std::string& path, const std::string& value) {
    int fd = open(path.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0) return;
    const auto text = value + "\n";
    while (write(fd, text.data(), text.size()) < 0 && errno == EINTR) {}
    close(fd);
}
bool port_available(int port) {
    Fd socket_fd(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (socket_fd.get() < 0) return false;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<uint16_t>(port));
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return bind(socket_fd.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0;
}
int random_port() {
    std::vector<int> ports;
    for (int port = 12000; port <= 13000; ++port) ports.push_back(port);
    std::random_device device;
    std::shuffle(ports.begin(), ports.end(), std::mt19937_64(device()));
    for (const auto port : ports) if (port_available(port)) return port;
    return -1;
}
std::string random_password(size_t length) {
    static constexpr char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device device;
    std::uniform_int_distribution<size_t> pick(0, sizeof(chars) - 2);
    std::string result;
    for (size_t i = 0; i < length; ++i) result += chars[pick(device)];
    return result;
}
// VMInstance.resolveVncConfig: fill each VNC screen's unset port/password.
void resolve_vnc(Json::Value& config) {
    std::vector<int64_t> taken;
    for (const char* id : {"gpu-0", "simplefb"}) {
        auto& screens = config["screens"];
        if (!screens.isObject() || !screens[id].isObject()) continue;
        auto& screen = screens[id];
        if (!config::boolean(screen, "enabled") || config::java_enum(screen, "exporter", "NONE", {"NATIVE", "VNC", "NONE"}) != "VNC") continue;
        auto& vnc = child(screen, "vnc");
        auto port = config::integer(vnc, "port", -1);
        if (port <= 0 || std::find(taken.begin(), taken.end(), port) != taken.end()) {
            int fresh = random_port();
            while (fresh > 0 && std::find(taken.begin(), taken.end(), fresh) != taken.end()) fresh = random_port();
            if (fresh > 0) { vnc["port"] = fresh; port = fresh; }
        }
        if (port > 0) taken.push_back(port);
        if (config::boolean(vnc, "password_auth") && config::string(vnc, "password").empty()) vnc["password"] = random_password(8);
    }
}
std::vector<std::string> merged_environment(const std::vector<std::pair<std::string, std::string>>& overrides) {
    // NativeProcess.Builder: System.getenv() order, later puts replace in place.
    std::vector<std::pair<std::string, std::string>> rows;
    for (char** entry = environ; entry && *entry; ++entry) {
        const std::string text = *entry;
        const auto eq = text.find('=');
        if (eq == std::string::npos) continue;
        rows.emplace_back(text.substr(0, eq), text.substr(eq + 1));
    }
    for (const auto& [key, value] : overrides) {
        auto at = std::find_if(rows.begin(), rows.end(), [&](const auto& row) { return row.first == key; });
        if (at != rows.end()) at->second = value; else rows.emplace_back(key, value);
    }
    std::vector<std::string> result;
    for (const auto& [key, value] : rows) result.push_back(key + "=" + value);
    return result;
}
}
const char* state_name(State state) { return state_names[static_cast<size_t>(state)]; }
void require_crosvm_disk_capabilities(const std::string& executable, const std::string& library_dir,
                                    const std::function<bool()>& cancelled) {
    if (!crosvm_disk_capabilities_supported(executable, library_dir, cancelled))
        throw std::runtime_error("Installed crosvm lacks the required explicit backing-chain capability; upgrade the backend");
}
bool crosvm_disk_capabilities_supported(const std::string& executable, const std::string& library_dir,
                                        const std::function<bool()>& cancelled) {
    ChildOptions probe;
    probe.argv = {executable, "disk-capabilities"};
    probe.environment = merged_environment({{"LD_LIBRARY_PATH", library_dir}, {"LD_PRELOAD", ""}});
    const auto capabilities = Child(probe).communicate({}, 2s, 4096, cancelled);
    if (capabilities.cancelled) throw std::runtime_error("crosvm disk capability check cancelled");
    bool supported = false;
    if (capabilities.exit_code == 0 && !capabilities.timed_out && !capabilities.truncated) {
        try { supported = crosvm_retained_chain_supported(config::parse_json(capabilities.output)); }
        catch (const std::exception&) {}
    }
    return supported;
}
VmRuntime::VmRuntime(std::string id, Json::Value config, const RuntimeContext& context)
    : id_(std::move(id)), context_(context), config_(std::move(config)) {
    if (context_.private_console) {
        require_private_config(config_);
        // Clear the copied callbacks once so all startup, worker, cleanup and
        // exception paths share the same boundary. Safety/admission callbacks
        // and process identities remain intact for leases and stop_all.
        context_.events = nullptr;
        context_.state_changed = {};
        context_.input_status = {};
        context_.warn = [](const std::string&) {};
        context_.info = [](const std::string&) {};
    }
    create_streams();
}
VmRuntime::~VmRuntime() = default;
void VmRuntime::create_streams() {
    for (const auto& name : config::vm_streams(config_)) {
        const auto stream = name.asString();
        if (logs_.contains(stream)) continue;
        // Disabling persistence alone still reloads history. A private runtime
        // has no log path at all, including stdout/stderr and the agent stream.
        const auto path = context_.private_console ? std::string() : console_log_path(context_.cache_dir, id_, stream);
        logs_[stream] = std::make_unique<ConsoleLog>(path, context_.owner, !context_.private_console && stream != "agent");
        order_.push_back(stream);
    }
}
State VmRuntime::state() const { std::lock_guard lock(state_mutex_); return state_; }
int64_t VmRuntime::pid() const { return pid_.load(); }
Json::Value VmRuntime::config() const { std::lock_guard lock(state_mutex_); return config_; }
Observation VmRuntime::observation() const { std::lock_guard lock(state_mutex_); return version_.observe(); }
bool VmRuntime::inspect_process(const std::function<void(int64_t, const Observation&)>& visitor) const {
    std::lock_guard lock(state_mutex_);
    if (retired_ || context_.private_console || !process_ ||
        (state_ != State::running && state_ != State::suspended && state_ != State::stopping)) return false;
    pollfd descriptor{process_->pidfd(), POLLIN, 0};
    int ready;
    do { ready = poll(&descriptor, 1, 0); } while (ready < 0 && errno == EINTR);
    if (ready < 0 || (descriptor.revents & POLLNVAL))
        throw ServiceError(ErrorCode::unavailable, "VM process identity is unavailable");
    if (ready != 0) return false;
    visitor(process_->pid(), version_.observe());
    return true;
}
bool VmRuntime::signal_process(int64_t pid, const Observation& expected, int number) {
    if (number != SIGTERM && number != SIGKILL)
        throw ServiceError(ErrorCode::invalid_argument, "Unsupported VM process signal");
    std::lock_guard lock(lock_);
    {
        std::lock_guard state(state_mutex_);
        version_.require(expected);
        if (retired_ || context_.private_console || !process_ || pid <= 1 || process_->pid() != pid ||
            (state_ != State::running && state_ != State::suspended && state_ != State::stopping))
            throw ServiceError(ErrorCode::conflict, "VM process changed before signalling");
        version_.admit(expected);
        if (!process_->signal(number)) return false;
        stopped_by_user_ = true;
        reboot_requested_ = false;
    }
    // A delivered signal is not an observed exit. Keep resources until the
    // normal worker reaps this exact Child and publishes STOPPED.
    set_state(State::stopping);
    return true;
}
Json::Value VmRuntime::snapshot() const {
    std::lock_guard lock(state_mutex_);
    auto row = config_;
    row["state"] = state_name(state_); row["pid"] = Json::Int64(pid_.load());
    row["runtime_uptime_ms"] = Json::Value();
    if (process_ && process_started_ && (state_ == State::running || state_ == State::suspended || state_ == State::stopping)) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - *process_started_).count();
        if (elapsed >= 0) row["runtime_uptime_ms"] = std::to_string(elapsed);
    }
    row["streams"] = Json::Value(Json::arrayValue);
    for (const auto& name : order_) row["streams"].append(name);
    const auto observed = version_.observe();
    row["runtime_instance"] = observed.instance;
    row["runtime_revision"] = std::to_string(observed.revision);
    row["runtime_uncertain"] = control_uncertain_;
    auto& actions = row["runtime_actions"] = Json::Value(Json::arrayValue);
    if (retired_) return row;
    if (state_ == State::stopped && !worker_) actions.append("start");
    if (state_ == State::starting || state_ == State::running || state_ == State::suspended || state_ == State::rebooting) actions.append("stop");
    if (state_ == State::running && !reboot_requested_ && !control_uncertain_) { actions.append("reboot"); actions.append("suspend"); }
    if (state_ == State::suspended && !reboot_requested_ && !control_uncertain_) actions.append("resume");
    return row;
}
VmRuntime::StoppedLease::StoppedLease(std::shared_ptr<VmRuntime> target)
    : target_(std::move(target)), lock_(target_->lock_, std::try_to_lock) {
    if (!lock_.owns_lock()) return;
    std::lock_guard state(target_->state_mutex_);
    if (target_->retired_ || target_->state_ != State::stopped || target_->worker_) lock_.unlock();
}
void VmRuntime::StoppedLease::retire() {
    if (!lock_.owns_lock()) throw std::logic_error("Stopped VM lease required");
    std::lock_guard state(target_->state_mutex_);
    target_->retired_ = true;
    target_->version_.changed();
}
VmRuntime::StoppedLease VmRuntime::try_edit() { return StoppedLease(shared_from_this()); }
std::vector<std::string> VmRuntime::streams() const { std::lock_guard lock(state_mutex_); return order_; }
ConsoleLog* VmRuntime::log(const std::string& stream) const {
    std::lock_guard lock(state_mutex_);
    const auto at = logs_.find(stream);
    return at == logs_.end() ? nullptr : at->second.get();
}
void VmRuntime::clear_logs() { std::lock_guard lock(state_mutex_); for (auto& [name, log] : logs_) log->clear(); }
void VmRuntime::set_state(State next) {
    // Release before publishing STOPPED so a new start keeps its reservation.
    if (next == State::stopped && context_.pool) context_.pool->release(id_, hugepage_generation_.load());
    {
        std::lock_guard lock(state_mutex_);
        if (next == State::stopped && session_base_) {
            config_.swap(*session_base_);
            session_base_.reset();
        }
        state_ = next;
        if (next != State::stopping) control_uncertain_ = false;
        version_.changed();
    }
    if (context_.info && (next == State::running || next == State::rebooting || next == State::stopping))
        context_.info("VM " + id_ + " (" + config::string(config(), "name") + "): " + lower(state_name(next)) +
                      (next == State::running ? " pid=" + std::to_string(pid()) : std::string()));
    fire("state");
    if (context_.state_changed) {
        // Guarded: a state change never fails because of the keyboard.
        try { context_.state_changed(id_, config::string(config(), "name"), next); }
        catch (const std::exception& error) { context_.warn(std::string("state hook failed: ") + error.what()); }
    }
    if (next == State::stopped) idle_.notify_all();
}
void VmRuntime::fire(const std::string& event, const Json::Value& extra) {
    if (!context_.events) return;
    Json::Value data;
    {
        std::lock_guard lock(state_mutex_);
        data["vm_id"] = id_;
        data["vm_name"] = config::member(config_, "name");
        data["state"] = lower(state_name(state_));
    }
    data["event"] = event;
    if (event == "exited") {
        data["exit_code"] = exit_code_;
        if (context_.info) context_.info("VM " + id_ + " (" + data["vm_name"].asString() + "): exited code=" + std::to_string(exit_code_));
        if (auto* stdio = log("stdio")) data["stdio"] = utf8_lossy(stdio->contents());
    }
    if (extra.isObject()) for (const auto& key : extra.getMemberNames()) data[key] = extra[key];
    context_.events->publish(data);
}
bool VmRuntime::start(std::optional<std::string> boot_entry, const Json::Value& overrides, bool clear_logs, std::optional<Observation> expected) {
    std::unique_lock lock(lock_);
    if (retired_) return false;
    {
        std::lock_guard state(state_mutex_);
        version_.require(expected);
        if (state_ != State::stopped || worker_) return false;
        std::optional<Json::Value> session;
        if (!overrides.isNull()) {
            if (!overrides.isObject()) throw std::invalid_argument("Invalid VM start overrides");
            session = config_;
            for (const auto& key : overrides.getMemberNames()) {
                if (key == "pseudo_unprotected") {
                    if (!overrides[key].isBool() || !overrides[key].asBool())
                        throw std::invalid_argument("Invalid protection override");
                    (*session)["protected_vm"] = "pseudo_unprotected";
                } else if (key == "readonly_disks") {
                    if (!overrides[key].isArray()) throw std::invalid_argument("Invalid read-only disk overrides");
                    std::set<Json::ArrayIndex> seen;
                    for (const auto& slot : overrides[key]) {
                        if (!slot.isUInt() || (slot.type() != Json::intValue && slot.type() != Json::uintValue))
                            throw std::invalid_argument("Invalid read-only disk slot");
                        const auto index = slot.asUInt();
                        if (!(*session)["disks"].isArray() || index >= (*session)["disks"].size() ||
                            !(*session)["disks"][index].isObject() || !seen.insert(index).second)
                            throw std::invalid_argument("Invalid or repeated read-only disk slot");
                        (*session)["disks"][index]["readonly"] = true;
                    }
                } else throw std::invalid_argument("Unknown VM start override");
            }
        }
        version_.admit(expected);
        if (session) { session_base_ = config_; config_.swap(*session); }
        boot_entry_ = std::move(boot_entry);
    }
    try {
        if (start_locked(false, clear_logs)) return true;
    } catch (...) {
        std::lock_guard state(state_mutex_);
        if (session_base_) { config_.swap(*session_base_); session_base_.reset(); }
        throw;
    }
    std::lock_guard state(state_mutex_);
    if (session_base_) { config_.swap(*session_base_); session_base_.reset(); }
    return false;
}
bool VmRuntime::start_locked(bool relaunch, bool clear_logs) {
    // Covers stale runtime references and automatic relaunch as well as the
    // configured-start adapter. Keep admission through NIC setup and STARTING.
    std::optional<ConfigurationGate::Admission> admission;
    try { admission.emplace(ConfigurationGate::enter(context_.configuration_gate)); }
    catch (const ServiceError& error) {
        if (error.code() == ErrorCode::unavailable) return false;
        throw;
    }
    if (retired_ || context_.shutting_down()) return false;
    {
        std::unique_lock state(state_mutex_);
        if (state_ != State::stopped && state_ != State::rebooting) return false;
        relaunch = state_ == State::rebooting;
        idle_.wait_for(state, 1s, [&] { return !worker_; });
        if (worker_) return false;
    }
    try {
        if (context_.private_console) require_private_config(config());
        if (context_.validate_start) {
            if (!*context_.validate_start) throw std::runtime_error("VM start validation is not available");
            (*context_.validate_start)(config());
        }
        std::shared_ptr<config::DiskFileLeases::Lease> held;
        { std::lock_guard state(state_mutex_); held = disk_lease_; }
        if (held) held->verify();
        else if (context_.acquire_disks) {
            if (!*context_.acquire_disks) throw std::runtime_error("Disk lease admission is not available");
            held = (*context_.acquire_disks)(config());
            std::lock_guard state(state_mutex_); disk_lease_ = std::move(held);
        }
    } catch (const std::exception& error) {
        context_.warn("Cannot start VM: " + std::string(error.what()));
        if (auto* output = log("stdio")) output->append(std::string("start validation failed: ") + error.what() + "\n");
        release_disks();
        return false;
    }
    try {
        // Clear only after validation and stopped admission, before new startup diagnostics.
        if (clear_logs) this->clear_logs();
        if (!setup_taps()) { release_disks(); return false; }
        { std::lock_guard state(state_mutex_); resolve_vnc(config_); }
        if (!relaunch) reboot_requested_ = false;
        stopped_by_user_ = false;
        exit_code_ = -1;
        const auto config = this->config();
        HostFacts facts;
        facts.has_kvm = access("/dev/kvm", F_OK) == 0;
        facts.has_gunyah = access("/dev/gunyah", F_OK) == 0;
        if (!relaunch && context_.pool && resolves_to_gunyah(config, facts)) {
            static std::atomic<uint64_t> next_consumer{1};
            hugepage_generation_ = next_consumer.fetch_add(1);
            const auto mb = std::max<int64_t>(config::integer(config, "memory_mb", 512), 64) + boot_guest_prealloc_mb(config);
            const bool automatic = context_.hugepages.resizable() && context_.hugepage_auto_reserve();
            if (!context_.pool->admit(id_, hugepage_generation_.load(), (mb + HugepagePool::page_mb - 1) / HugepagePool::page_mb, automatic))
                throw std::runtime_error("Huge-page control is busy or reserve target could not be set");
        }
        set_state(State::starting);
        { std::lock_guard state(state_mutex_); worker_ = true; }
        std::thread([self = shared_from_this()] { self->run(); }).detach();
    } catch (const std::exception& error) {
        context_.warn("Cannot start VM " + config::string(config(), "name") + ": " + error.what());
        cleanup_taps();
        cleanup_backend();
        release_disks();
        { std::lock_guard state(state_mutex_); worker_ = false; }
        set_state(State::stopped);
        return false;
    }
    return true;
}
bool VmRuntime::setup_taps() {
    const auto config = this->config();
    const auto& nets = config::member(config, "networks");
    if (!nets.isArray() || nets.empty()) return true;
    if (!context_.attach_nic) return false; // "has networks but no network store"
    std::vector<std::tuple<std::string, Json::Value, std::string>> created;
    try {
        for (Json::ArrayIndex i = 0; i < nets.size(); ++i) {
            auto nic = nets[i];
            const auto network = config::string(nic, "network_id");
            if (network.empty()) continue;
            auto tap = config::string(nic, "tap_name");
            if (tap.empty()) {
                tap = "vm" + id_.substr(0, 8) + "-" + std::to_string(i);
                nic["tap_name"] = tap;
                std::lock_guard lock(state_mutex_);
                config_["networks"][i]["tap_name"] = tap;
            }
            context_.attach_nic(network, nic, tap);
            created.emplace_back(network, nic, tap);
        }
    } catch (const std::exception& error) {
        if (auto* stdio = log("stdio")) stdio->append(std::string("network setup failed: ") + error.what() + "\n");
        for (const auto& [network, nic, tap] : created) try { context_.detach_nic(network, nic, tap); } catch (const std::exception&) {}
        return false;
    }
    return true;
}
void VmRuntime::cleanup_taps() {
    if (!context_.detach_nic) return;
    const auto config = this->config();
    const auto& nets = config::member(config, "networks");
    if (!nets.isArray()) return;
    for (const auto& nic : nets) {
        const auto tap = config::string(nic, "tap_name");
        if (tap.empty()) continue;
        try { context_.detach_nic(config::string(nic, "network_id"), nic, tap); }
        catch (const std::exception& error) { context_.warn("VM " + id_ + ": detaching " + tap + " failed: " + error.what()); }
    }
}
void VmRuntime::run() {
    auto stdio = [&](const std::string& text) { if (auto* log = this->log("stdio")) log->append(text); };
    if (context_.validate_disks) {
        try {
            if (!*context_.validate_disks) throw std::runtime_error("Disk image validation is not available");
            std::shared_ptr<config::DiskFileLeases::Lease> lease;
            { std::lock_guard lock(state_mutex_); lease = disk_lease_; }
            if (!lease) throw std::runtime_error("Disk lease is missing before image validation");
            auto images = (*context_.validate_disks)(config(), *lease, [this] { return stopped_by_user_ || context_.shutting_down(); });
            { std::lock_guard lock(state_mutex_); disk_images_ = std::move(images); }
        } catch (const std::exception& error) {
            stdio(std::string("disk image validation failed: ") + error.what() + "\n");
            finish_stopped(-1);
            return;
        }
    }
    BootPlan plan;
    try {
        std::optional<std::string> entry;
        Json::Value config;
        { std::lock_guard lock(state_mutex_); entry = boot_entry_; boot_entry_.reset(); config = config_; }
        plan = resolve_boot(config, entry, {context_.lbx, context_.cache_dir + "/boot"});
        std::lock_guard lock(state_mutex_);
        config_["boot"] = config["boot"]; // BootConfig's accessors create what they read
    } catch (const std::exception& error) {
        stdio(std::string("boot resolution failed: ") + error.what() + "\n");
        context_.warn("VM " + id_ + ": boot resolution failed: " + error.what());
        finish_stopped(-1);
        return;
    }
    if (plan.entry_fallback) fire("boot_entry_fallback");
    auto aborted = [&] { return stopped_by_user_ || context_.shutting_down(); };
    const auto config = this->config();
    HostFacts facts;
    facts.has_kvm = access("/dev/kvm", F_OK) == 0;
    facts.has_gunyah = access("/dev/gunyah", F_OK) == 0;
    bool ready = true;
    if (resolves_to_gunyah(config, facts)) {
        const bool required = context_.pool && context_.pool->automatic(id_);
        // Automatic sizing off: start on the reserve as the user left it, without waiting.
        if (required || (context_.hugepages.present() && context_.hugepage_auto_reserve())) {
            const auto mb = std::max<int64_t>(config::integer(config, "memory_mb", 512), 64) + boot_guest_prealloc_mb(config);
            ready = context_.hugepages.wait((mb + HugepagePool::page_mb - 1) / HugepagePool::page_mb, aborted,
                300, std::chrono::seconds(1), 5, [&] {
                    if (context_.pool) context_.pool->control([&] { context_.hugepages.acquire(); });
                    else context_.hugepages.acquire();
                });
        }
    }
    if (aborted()) { finish_stopped(0); return; }
    if (!ready) { stdio("Huge-page reserve is not ready; VM start cancelled.\n"); finish_stopped(-1); return; }
    std::string failure;
    bool launched = false;
    reading_ = true;
    try { launched = launch(config, plan, failure); } catch (const std::exception& error) { failure = error.what(); }
    if (!launched) {
        if (!failure.empty()) stdio(failure + "\n");
        context_.warn("VM " + id_ + " (" + config::string(config, "name") + "): launch failed: " + failure);
        finish_stopped(-1);
        return;
    }
    if (stopped_by_user_) kill_process();
    std::vector<std::thread> readers;
    {
        std::lock_guard lock(state_mutex_);
        readers.emplace_back(&VmRuntime::read_stream, this, process_->stdout_fd(), "stdout", true);
        readers.emplace_back(&VmRuntime::read_stream, this, process_->stderr_fd(), "stderr", true);
        for (const auto& serial : serials_) readers.emplace_back(&VmRuntime::read_stream, this, serial.local_read.get(), serial.stream, false);
    }
    {
        std::lock_guard lock(lock_);
        if (!stopped_by_user_) set_state(State::running);
    }
    const auto started = std::chrono::steady_clock::now();
    pollfd exit_event{process_->pidfd(), POLLIN, 0};
    while (poll(&exit_event, 1, -1) < 0 && errno == EINTR) {}
    int code = -1;
    {
        std::lock_guard lock(state_mutex_);
        if (const auto exit = process_->poll_exit()) code = *exit;
    }
    const auto ran = std::chrono::steady_clock::now() - started;
    reading_ = false;
    for (auto& reader : readers) reader.join();
    // Keep control calls away from teardown and from the next process/socket.
    // The worker must never publish RUNNING/SUSPENDED after a completed stop.
    std::lock_guard lock(lock_);
    reap_and_cleanup();
    exit_code_ = code;
    bool restart = !stopped_by_user_ && (code == crosvm_reset || reboot_requested_);
    if (code == 0 || ran > 60s) pin_retry_used_ = false;
    if (!stopped_by_user_ && !restart && code != 0 && !pin_retry_used_) {
        // The VMM could not pin its memory: worth exactly one retry.
        const auto* log = this->log("stdio");
        const auto text = log ? log->contents() : std::string();
        if (text.find("GH-PIN[") != std::string::npos && text.find("cannot be long-term pinned") != std::string::npos) {
            pin_retry_used_ = true;
            restart = true;
        }
    }
    if (stopped_by_user_ && code != 0) exit_code_ = 0;
    cleanup_taps();
    cleanup_backend();
    if (restart && !stopped_by_user_ && !context_.shutting_down()) {
        reboot_requested_ = false;
        exit_code_ = -1;
        set_state(State::rebooting);
        fire("rebooting");
        { std::lock_guard state(state_mutex_); worker_ = false; }
        idle_.notify_all();
        std::thread([self = shared_from_this()] {
            std::this_thread::sleep_for(500ms);
            std::lock_guard relaunch(self->lock_);
            if (self->state() != State::rebooting) return;
            if (!self->start_locked(true)) self->finish_stopped_locked(-1);
        }).detach();
        return;
    }
    if (access("/sys/kernel/nproc_guard/reset", F_OK) == 0) write_quiet("/sys/kernel/nproc_guard/reset", "1");
    release_disks();
    { std::lock_guard state(state_mutex_); worker_ = false; }
    set_state(State::stopped);
    fire("exited");
}
bool VmRuntime::launch(const Json::Value& config, const BootPlan& plan, std::string& failure) {
    mkdir(context_.run_dir.c_str(), 0700);
    if (config::java_enum(config, "backend", "CROSVM", {"CROSVM", "QEMU"}) == "QEMU") return launch_qemu(config, plan, failure);
    CrosvmRun run;
    { std::lock_guard lock(state_mutex_); run.preserve_disk_paths = static_cast<bool>(disk_lease_); }
    std::vector<Fd> disk_io;
    if (run.preserve_disk_paths) {
        std::shared_ptr<config::DiskFileLeases::Lease> lease;
        RuntimeContext::DiskImages images;
        { std::lock_guard lock(state_mutex_); lease = disk_lease_; images = disk_images_; }
        run.disk_fds.emplace();
        run.disk_backing_fds.emplace();
        std::map<std::string, int> parent_fds;
        const auto& slots = config::member(config, "disks");
        if (slots.isArray()) for (const auto& slot : slots) {
            const auto path = config::string(slot, "path");
            if (path.empty()) continue;
            const auto bus = config::java_enum(slot, "bus", "VIRTIO", {"VIRTIO", "SCSI", "CDROM", "PFLASH", "PMEM"});
            if (bus == "PFLASH") continue;
            const auto& image = images.at(path);
            if ((image.format != "raw" && image.format != "qcow2") ||
                (image.parent && image.format != "qcow2") || (bus == "PMEM" && (image.format != "raw" || image.parent)))
                throw std::runtime_error("Unsupported retained crosvm disk format for this bus");
            if (bus != "PMEM") {
                auto& chain = (*run.disk_backing_fds)[path];
                chain.clear();
                std::set<std::string> seen{path};
                auto parent = image.parent;
                while (parent) {
                    if (chain.size() == 10 || !seen.insert(*parent).second)
                        throw std::runtime_error("Invalid retained crosvm backing depth or cycle");
                    const auto& ancestor = images.at(*parent);
                    if ((ancestor.format != "raw" && ancestor.format != "qcow2") ||
                        (ancestor.parent && ancestor.format != "qcow2"))
                        throw std::runtime_error("Unsupported retained crosvm backing format");
                    if (!parent_fds.contains(*parent)) {
                        auto fd = lease->open_file(*parent, false);
                        parent_fds.emplace(*parent, fd.get());
                        disk_io.push_back(std::move(fd));
                    }
                    chain.push_back(parent_fds.at(*parent));
                    parent = ancestor.parent;
                }
            }
            if (!run.disk_fds->contains(path)) {
                auto fd = lease->open_file(path, !config::boolean(slot, "readonly") && bus != "CDROM");
                run.disk_fds->emplace(path, fd.get());
                disk_io.push_back(std::move(fd));
            }
        }
        if (!run.disk_backing_fds->empty()) {
            // An empty data_dir means the app's own /data/data directory, as for the command.
            HostFacts host; host.data_dir = context_.data_dir;
            const auto data = command::data_dir(host);
            if (!crosvm_disk_capabilities_supported(data + "/usr/bin/crosvm", data + "/usr/lib",
                    [this] { return stopped_by_user_ || context_.shutting_down(); })) {
                // Released crosvm builds cannot take retained backing chains. Launch exactly as
                // the Java daemon did (paths, optimized sdcard paths, backing from headers);
                // the leases stay held so native disk operations cannot touch these files.
                if (context_.warn) context_.warn("crosvm lacks explicit backing chains; launching disks by path as before");
                run.preserve_disk_paths = false;
                run.disk_fds.reset();
                run.disk_backing_fds.reset();
                disk_io.clear();
            }
        }
        lease->verify();
    }
    const auto& ports = config::member(config, "serial_ports");
    auto backend_of = [](const Json::Value& port) { return config::java_enum(port, "backend", "SINK", {"SINK", "APP_CONSOLE", "FILE", "UNIX", "UNIX_STREAM", "PTY", "STDOUT", "SYSLOG", "USB_ACM"}); };
    auto stream_of = [](const Json::Value& port) { // VMSerialConfig.getStreamName
        const auto hardware = config::java_enum(port, "hardware", "SERIAL", {"SERIAL", "SBSA", "VIRTIO_CONSOLE"});
        const auto num = std::to_string(std::bit_cast<int32_t>(static_cast<uint32_t>(config::integer(port, "num", 1))));
        return (hardware == "SBSA" ? "sbsa" : hardware == "VIRTIO_CONSOLE" ? "vcon" : "serial") + num;
    };
    // USB_ACM ports attach their configured pool slot outside the state lock: a
    // pool build waits on the USB stack. A refused slot fails the start; a broken
    // gadget degrades the port to a sink.
    std::vector<std::optional<std::string>> acm;
    if (ports.isArray()) for (const auto& port : ports) {
        acm.emplace_back();
        if (!context_.acm || backend_of(port) != "USB_ACM") continue;
        const auto owner = id_ + "/" + stream_of(port);
        try {
            acm.back() = context_.acm->acquire(std::bit_cast<int32_t>(static_cast<uint32_t>(config::integer(port, "usb_slot", 0))),
                                               owner, context_.app_config());
            std::lock_guard lock(state_mutex_);
            acm_owners_.push_back(owner);
        } catch (const AcmSlotUnavailable& error) {
            failure = std::string("serial setup failed: ") + error.what();
            return false;
        } catch (const std::exception& error) {
            context_.warn("USB ACM for " + stream_of(port) + " unavailable; port degrades to sink: " + error.what());
        }
    }
    {
        std::lock_guard lock(state_mutex_);
        serials_.clear();
        if (ports.isArray()) for (Json::ArrayIndex index = 0; index < ports.size(); ++index) {
            const auto& port = ports[index];
            SerialRun resolved;
            resolved.acm_dev_path = acm[index];
            if (backend_of(port) == "APP_CONSOLE") {
                const auto name = stream_of(port);
                int out[2], in[2];
                if (logs_.contains(name) && pipe2(out, O_CLOEXEC) == 0) {
                    if (pipe2(in, O_CLOEXEC) == 0) {
                        Serial serial{name, Fd(out[0]), Fd(in[1]), Fd(out[1]), Fd(in[0])};
                        resolved.pipe = std::pair{serial.remote_write.get(), serial.remote_read.get()};
                        serials_.push_back(std::move(serial));
                    } else { close(out[0]); close(out[1]); }
                }
            }
            run.serials.push_back(std::move(resolved));
        }
        control_socket_ = context_.run_dir + "/" + config::string(config, "name") + ".sock";
        unlink(control_socket_->c_str());
        run.control_socket_path = control_socket_;
    }
    const auto facts = probe_host({context_.owner, context_.run_dir + "/app-gids", context_.optimize_sdcard(),
                                   plan.uefi ? (plan.vars.empty() ? edk2_vars() : plan.vars) : std::string()});
    auto host = facts;
    host.data_dir = context_.data_dir;
    // crosvm opens <cgroup>/tasks and never creates it; the flag needs this first.
    std::string cgroup_warning;
    run.gpu_cgroup_path = prepare_gpu_cgroup(config, cgroup_warning);
    if (!cgroup_warning.empty()) context_.warn("VM " + id_ + ": " + cgroup_warning);
    const auto command = crosvm_command(config, run, plan, host);
    if (command.input_bridge) {
        // crosvm is the client of these sockets; they must exist before it starts.
        InputBridge::Status status;
        if (context_.input_status)
            status = [this](const std::string& screen, int, std::string records) { context_.input_status(id_, screen, std::move(records)); };
        try { input_.listen(command.input_sockets, std::move(status)); }
        catch (const std::invalid_argument& error) { failure = std::string("display input setup failed: ") + error.what(); return false; }
    }
    if (command.udmabuf_limit_mb) {
        glob_t matches{};
        if (glob("/sys/module/udmabuf*/parameters/size_limit_mb", 0, nullptr, &matches) == 0)
            for (size_t i = 0; i < matches.gl_pathc; ++i) write_quiet(matches.gl_pathv[i], std::to_string(*command.udmabuf_limit_mb));
        globfree(&matches);
    }
    if (!spawn(command.argv, command.env, command.strace_dir, "crosvm", failure, command.preserve_fds)) return false;
    { std::lock_guard lock(state_mutex_); vnc_endpoints_ = command.vnc_endpoints; }
    return true;
}
bool VmRuntime::launch_qemu(const Json::Value& config, const BootPlan& plan, std::string& failure) {
    auto host = probe_host({context_.owner, context_.run_dir + "/app-gids", context_.optimize_sdcard(),
                            plan.uefi ? (plan.vars.empty() ? edk2_vars() : plan.vars) : std::string()});
    host.data_dir = context_.data_dir;
    auto run = qemu_sockets(config, host);
    { std::lock_guard lock(state_mutex_); run.preserve_disk_paths = static_cast<bool>(disk_lease_); }
    run.file_length = [](const std::string& path) -> int64_t { struct stat info{}; return stat(path.c_str(), &info) == 0 && S_ISREG(info.st_mode) ? info.st_size : 0; };
    std::vector<Fd> disk_io; // Own through exec; QEMU then owns its inherited copies.
    if (run.preserve_disk_paths) {
        std::shared_ptr<config::DiskFileLeases::Lease> lease;
        RuntimeContext::DiskImages images;
        { std::lock_guard lock(state_mutex_); lease = disk_lease_; images = disk_images_; }
        std::map<std::string, bool> access;
        std::set<std::string> virtio_paths;
        std::set<std::string> block_paths;
        const auto& slots = config::member(config, "disks");
        if (slots.isArray()) for (const auto& slot : slots) {
            auto path = config::string(slot, "path");
            if (path.empty()) continue;
            const auto bus = config::java_enum(slot, "bus", "VIRTIO", {"VIRTIO", "SCSI", "CDROM", "PFLASH", "PMEM"});
            const bool write = !config::boolean(slot, "readonly") && bus != "CDROM";
            access[path] = access[path] || write;
            if (bus == "VIRTIO") virtio_paths.insert(path);
            if (bus == "PFLASH" || bus == "PMEM") {
                const auto& image = images.at(path);
                if (image.format != "raw" || image.parent) throw std::runtime_error("PFLASH and PMEM require a raw image without backing");
                if (!run.direct_disk_fds.contains(path)) {
                    auto fd = lease->open_file(path, write);
                    run.direct_disk_fds.emplace(path, fd.get());
                    disk_io.push_back(std::move(fd));
                }
                continue;
            }
            while (block_paths.insert(path).second) {
                const auto& image = images.at(path);
                if (!image.parent) break;
                path = *image.parent;
            }
        }
        std::map<std::string, QemuDiskImage> graph;
        for (const auto& path : block_paths) {
            const auto& image = images.at(path);
            const bool write = access[path];
            auto fd = lease->open_file(path, write);
            const bool virtio = virtio_paths.contains(path);
            graph.emplace(path, QemuDiskImage{fd.get(), image.format, image.parent, !write,
                virtio && !config::boolean(config, "agent_mode"), virtio});
            disk_io.push_back(std::move(fd));
        }
        run.disk_graph = qemu_disk_graph(graph);
        run.file_length = [&run](const std::string& path) -> int64_t {
            const auto found = run.direct_disk_fds.find(path);
            struct stat info{};
            if (found == run.direct_disk_fds.end() || fstat(found->second, &info) != 0 || !S_ISREG(info.st_mode))
                throw std::runtime_error("Cannot measure retained raw disk");
            return info.st_size;
        };
        lease->verify();
    }
    QemuLaunch command;
    try { command = qemu_command(config, run, plan, host); }
    catch (const std::exception& error) { failure = error.what(); return false; }
    {
        std::lock_guard lock(state_mutex_);
        serials_.clear(); sockets_.clear();
        for (const auto& path : {run.qmp_socket_path, run.uart_socket_path, run.agent_socket_path})
            if (path) { unlink(path->c_str()); sockets_.push_back(*path); }
        qemu_ = true;
        control_socket_ = run.qmp_socket_path;
        vnc_endpoints_ = command.vnc_endpoints;
    }
    if (!spawn(command.argv, command.env, command.strace_dir, "qemu", failure, command.preserve_fds)) return false;
    // agent0 is declared before the blocking UART chardev: connect it first so
    // no hvc0 boot output races ahead of the reader.
    auto connect_stream = [&](const char* stream, const std::string& path) {
        for (int attempt = 0;; ++attempt) {
            Fd socket_fd(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
            sockaddr_un address{};
            address.sun_family = AF_UNIX;
            if (socket_fd.get() >= 0 && path.size() < sizeof(address.sun_path)) {
                std::copy(path.begin(), path.end(), address.sun_path);
                if (connect(socket_fd.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0) {
                    Fd writer(fcntl(socket_fd.get(), F_DUPFD_CLOEXEC, 0));
                    std::lock_guard lock(state_mutex_);
                    serials_.push_back({stream, std::move(socket_fd), std::move(writer), Fd(), Fd()});
                    return true;
                }
            }
            if (attempt >= 50) return false;
            std::this_thread::sleep_for(100ms);
        }
    };
    if (command.agent && run.agent_socket_path && !connect_stream("agent", *run.agent_socket_path)) {
        failure = "failed to connect agent socket after multiple attempts, giving up"; kill_process(); return false;
    }
    if (run.uart_socket_path && !connect_stream("uart", *run.uart_socket_path)) {
        failure = "failed to connect UART socket after multiple attempts, giving up"; kill_process(); return false;
    }
    return true;
}
bool VmRuntime::spawn(const std::vector<std::string>& argv, const std::vector<std::pair<std::string, std::string>>& env,
                      const std::optional<std::string>& strace_dir, const char* label, std::string& failure,
                      const std::vector<int>& preserve_fds) {
    if (context_.private_console && strace_dir) {
        failure = "Tracing is unavailable for a private VM";
        return false;
    }
    std::shared_ptr<config::DiskFileLeases::Lease> lease;
    { std::lock_guard lock(state_mutex_); lease = disk_lease_; }
    if (lease) lease->verify();
    if (strace_dir) {
        std::error_code error;
        std::filesystem::remove_all(*strace_dir, error);
        std::filesystem::create_directory(*strace_dir, error);
    }
    // VMBackendInstance.cleanUpMemory.
    write_quiet("/sys/kernel/mm/transparent_hugepage/enabled", "madvise");
    write_quiet("/sys/kernel/mm/transparent_hugepage/defrag", "madvise");
    write_quiet("/sys/kernel/mm/transparent_hugepage/shmem_enabled", "advise");
    write_quiet("/proc/sys/vm/drop_caches", "3");
    write_quiet("/proc/sys/vm/compact_memory", "1");
    ChildOptions options;
    options.preserve_fds = preserve_fds;
    options.argv = argv;
    {
        // One line with the exact argv, so a launch can be reproduced from the log.
        std::string line;
        for (const auto& arg : argv) {
            if (!line.empty()) line += ' ';
            line += arg;
        }
        context_.info("Executing: " + line);
    }
    options.environment = merged_environment(env);
    options.limits = {{RLIMIT_NOFILE, 65536, 65536}, {RLIMIT_MEMLOCK, RLIM_INFINITY, RLIM_INFINITY}};
    if (context_.private_console) options.limits.push_back({RLIMIT_CORE, 0, 0});
    {
        std::lock_guard lock(state_mutex_);
        for (const auto& serial : serials_) { options.preserve_fds.push_back(serial.remote_write.get()); options.preserve_fds.push_back(serial.remote_read.get()); }
    }
    std::unique_ptr<HelperIdentity> identity;
    if (context_.identities) {
        context_.identities->allocate(id_, identity_, network::SwitchRuntime::Kind::vm);
        identity = std::make_unique<HelperIdentity>(identity_.directory.get(), context_.identities->owner());
        identity->arm(options);
    }
    if (lease) {
        // Child runs this in the parent while exec is gated. Preserve the helper
        // identity hook, and reject path replacement during boot preparation.
        auto before_exec = std::move(options.before_exec);
        options.before_exec = [lease, before_exec = std::move(before_exec)](pid_t pid) {
            lease->verify();
            if (before_exec) before_exec(pid);
            lease->verify();
        };
    }
    try {
        auto process = std::make_unique<Child>(options);
        std::lock_guard lock(state_mutex_);
        pid_ = process->pid();
        process_ = std::move(process);
        process_started_ = std::chrono::steady_clock::now();
        for (auto& serial : serials_) { serial.remote_write = Fd(); serial.remote_read = Fd(); }
    } catch (const std::exception& error) {
        failure = std::string("Failed to start ") + label + " process: " + error.what();
        return false;
    }
    return true;
}
void VmRuntime::read_stream(int fd, std::string name, bool also_stdio) {
    char buffer[4096];
    auto deliver = [&](const std::string& stream, std::string_view data) {
        if (auto* log = this->log(stream)) log->append(data);
        if (context_.private_console) return;
        Json::Value extra;
        extra["stream"] = stream;
        extra["data"] = url_encode_bytes(data);
        fire("output", extra);
    };
    // Bounded join: grandchildren may keep the pipe open past the VMM's exit.
    std::optional<std::chrono::steady_clock::time_point> deadline;
    for (;;) {
        if (!reading_ && !deadline) deadline = std::chrono::steady_clock::now() + 5s;
        if (deadline && std::chrono::steady_clock::now() > *deadline) break;
        pollfd event{fd, POLLIN, 0};
        const auto ready = poll(&event, 1, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) break;
        if (ready == 0) continue;
        const auto count = read(fd, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        deliver(name, {buffer, static_cast<size_t>(count)});
        if (also_stdio) deliver("stdio", {buffer, static_cast<size_t>(count)});
    }
}
void VmRuntime::reap_and_cleanup() {
    std::unique_ptr<Child> process;
    { std::lock_guard lock(state_mutex_); process = std::move(process_); pid_ = -1; }
    if (process) process->stop(std::chrono::seconds(3));
    std::lock_guard lock(state_mutex_);
    for (auto& [name, log] : logs_) log->close();
}
void VmRuntime::cleanup_backend() {
    input_.release();
    std::vector<std::string> acm;
    { std::lock_guard lock(state_mutex_); acm.swap(acm_owners_); }
    for (const auto& owner : acm) context_.acm->release(owner);
    std::lock_guard lock(state_mutex_);
    if (control_socket_) { unlink(control_socket_->c_str()); control_socket_.reset(); }
    for (const auto& path : sockets_) unlink(path.c_str());
    sockets_.clear(); qemu_ = false;
    vnc_endpoints_.clear();
    serials_.clear();
    if (!identity_.name.empty() && context_.identities) {
        try { context_.identities->cleanup(identity_.name); identity_.directory = Fd(); identity_.name.clear(); } catch (const std::exception&) {}
    }
}
void VmRuntime::finish_stopped(int code) {
    std::lock_guard lock(lock_);
    finish_stopped_locked(code);
}
void VmRuntime::finish_stopped_locked(int code) {
    exit_code_ = code;
    cleanup_taps();
    cleanup_backend();
    release_disks();
    { std::lock_guard state(state_mutex_); worker_ = false; }
    set_state(State::stopped);
    fire("exited");
}
void VmRuntime::release_disks() {
    std::shared_ptr<config::DiskFileLeases::Lease> released;
    { std::lock_guard state(state_mutex_); released.swap(disk_lease_); disk_images_.clear(); }
}
std::shared_ptr<config::DiskFileLeases::Lease> VmRuntime::private_disk_lease() const {
    if (!context_.private_console)
        throw ServiceError(ErrorCode::permission_denied, "Private VM ownership required");
    std::lock_guard state(state_mutex_);
    return disk_lease_;
}
void VmRuntime::kill_process() {
    std::lock_guard lock(state_mutex_);
    if (process_) process_->signal(SIGKILL);
}
// QemuBackendInstance.sendQMP: greeting, qmp_capabilities, one command.
int VmRuntime::send_qmp(const std::string& command) {
    Json::Value request;
    if (command == "stop") request["execute"] = "quit";
    else if (command == "powerbtn") request["execute"] = "system_powerdown";
    else if (command == "sleepbtn") { request["execute"] = "human-monitor-command"; request["arguments"]["command-line"] = "system_sleepbutton"; }
    else if (command == "resume") request["execute"] = "cont";
    else if (command == "suspend") request["execute"] = "stop";
    else return -1;
    std::optional<std::string> path;
    { std::lock_guard lock(state_mutex_); path = control_socket_; }
    if (!path) return -1;
    Fd socket_fd(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (socket_fd.get() < 0 || path->size() >= sizeof(address.sun_path)) return -1;
    std::copy(path->begin(), path->end(), address.sun_path);
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    auto ready = [&](short events) {
        for (;;) {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
            if (remaining <= 0) return false;
            pollfd fd{socket_fd.get(), events, 0};
            const int result = poll(&fd, 1, static_cast<int>(remaining));
            if (result < 0 && errno == EINTR) continue;
            return result > 0 && (fd.revents & (events | POLLERR | POLLHUP));
        }
    };
    if (connect(socket_fd.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        if (errno != EINPROGRESS || !ready(POLLOUT)) return -1;
        int error = 0; socklen_t length = sizeof(error);
        if (getsockopt(socket_fd.get(), SOL_SOCKET, SO_ERROR, &error, &length) != 0 || error) return -1;
    }
    const auto send_all = [&](std::string_view value) {
        while (!value.empty()) {
            if (!ready(POLLOUT)) return false;
            const auto count = ::send(socket_fd.get(), value.data(), value.size(), MSG_NOSIGNAL);
            if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
            if (count <= 0) return false;
            value.remove_prefix(static_cast<size_t>(count));
        }
        return true;
    };
    const auto receive = [&]() -> std::string {
        for (;;) {
            if (!ready(POLLIN)) return {};
            char buffer[4096]; const auto count = recv(socket_fd.get(), buffer, sizeof(buffer), 0);
            if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
            return count > 0 ? std::string(buffer, static_cast<size_t>(count)) : std::string();
        }
    };
    return qmp_control(request, send_all, receive) ? 0 : -1;
}
int VmRuntime::send_control(const std::string& command) {
    bool qemu;
    { std::lock_guard lock(state_mutex_); qemu = qemu_; }
    if (qemu) return send_qmp(command);
    const char* request = command == "stop" ? "Exit" : command == "powerbtn" ? "Powerbtn" : command == "sleepbtn" ? "Sleepbtn" :
        command == "resume" ? "ResumeVcpus" : command == "suspend" ? "SuspendVcpus" : nullptr;
    std::optional<std::string> path;
    { std::lock_guard lock(state_mutex_); path = control_socket_; }
    if (!path || !request) return -1;
    Fd socket_fd(socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0));
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (socket_fd.get() < 0 || path->size() >= sizeof(address.sun_path)) return -1;
    std::copy(path->begin(), path->end(), address.sun_path);
    timeval timeout{5, 0};
    setsockopt(socket_fd.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(socket_fd.get(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (connect(socket_fd.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) return -1;
    const auto text = std::string("\"") + request + "\"";
    if (send(socket_fd.get(), text.data(), text.size(), MSG_NOSIGNAL) != static_cast<ssize_t>(text.size())) return -1;
    char response[4096];
    const auto count = recv(socket_fd.get(), response, sizeof(response), 0);
    if (count <= 0) return -1;
    return std::string_view(response, static_cast<size_t>(count)) == "\"Ok\"" ? 0 : -1;
}
std::optional<State> VmRuntime::claim_action(const std::optional<Observation>& expected, std::initializer_list<State> allowed,
                                           bool allow_uncertain) {
    if (retired_) return {};
    std::lock_guard state(state_mutex_);
    version_.require(expected);
    if (control_uncertain_ && !allow_uncertain) {
        if (expected) throw ServiceError(ErrorCode::commit_uncertain, "VM control state is unconfirmed; stop before another transition");
        return {};
    }
    if (std::find(allowed.begin(), allowed.end(), state_) == allowed.end()) return {};
    version_.admit(expected);
    return state_;
}
bool VmRuntime::stop(std::optional<Observation> expected) {
    std::lock_guard lock(lock_);
    const auto current = claim_action(expected, {State::running, State::starting, State::suspended, State::rebooting}, true);
    if (!current) return false;
    if (*current == State::rebooting) {
        // A relaunch has no live process: cancel it and release its budget.
        stopped_by_user_ = true;
        exit_code_ = 0;
        release_disks();
        set_state(State::stopped);
        fire("exited");
        return true;
    }
    stopped_by_user_ = true;
    set_state(State::stopping);
    { std::lock_guard state(state_mutex_); if (!process_) return true; } // the worker observes stopped_by_user_
    if (send_control("stop") == 0) return true;
    kill_process();
    return true;
}
bool VmRuntime::reboot(std::optional<Observation> expected) {
    std::lock_guard lock(lock_);
    if (reboot_requested_ || !claim_action(expected, {State::running})) return false;
    reboot_requested_ = true;
    if (send_control("stop") == 0) return true;
    kill_process();
    return true;
}
bool VmRuntime::suspend(std::optional<Observation> expected) {
    return control_transition(std::move(expected), State::running, State::suspended, "suspend");
}
bool VmRuntime::resume(std::optional<Observation> expected) {
    return control_transition(std::move(expected), State::suspended, State::running, "resume");
}
bool VmRuntime::control_transition(std::optional<Observation> expected, State from, State to, const std::string& command) {
    std::lock_guard lock(lock_);
    if (reboot_requested_ || !claim_action(expected, {from})) return false;
    if (send_control(command) != 0) {
        { std::lock_guard state(state_mutex_); control_uncertain_ = true; version_.changed(); }
        if (expected) throw ServiceError(ErrorCode::commit_uncertain, "VM control outcome could not be confirmed");
        return false;
    }
    set_state(to);
    return true;
}
bool VmRuntime::control(const std::string& command) {
    if (command == "stop") return stop();
    if (command == "suspend") return suspend();
    if (command == "resume") return resume();
    std::lock_guard lock(lock_);
    if (!claim_action({}, {State::running, State::suspended})) return false;
    return send_control(command) == 0;
}
std::optional<VmRuntime::StreamInfo> VmRuntime::stream_info(const std::string& stream) const {
    std::lock_guard lock(state_mutex_);
    if (!logs_.contains(stream)) return {};
    StreamInfo info;
    const bool running = process_ != nullptr;
    if (stream == "stdout" || stream == "stderr") { info.type = "InputConsoleStream"; info.readable = running; }
    else if (stream == "stdio") { info.type = "SimpleConsoleStream"; info.readable = true; }
    else if (stream == "uart" || stream == "agent") {
        info.type = "LocalSocketConsoleStream";
        for (const auto& serial : serials_) if (serial.stream == stream) info.readable = info.writable = info.ready = true;
    }
    else {
        info.type = "FDPipeConsoleStream"; info.fd_pipe = true;
        for (const auto& serial : serials_) if (serial.stream == stream) {
            info.read_fd = serial.local_read.get(); info.write_fd = serial.local_write.get();
            info.readable = info.read_fd >= 0; info.writable = info.write_fd >= 0;
        }
    }
    return info;
}
bool VmRuntime::write(const std::string& stream, const std::string& data) {
    std::lock_guard lock(state_mutex_);
    for (const auto& serial : serials_) {
        if (serial.stream != stream || serial.local_write.get() < 0) continue;
        std::string_view rest(data);
        while (!rest.empty()) {
            const auto written = ::write(serial.local_write.get(), rest.data(), rest.size());
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) return false;
            rest.remove_prefix(static_cast<size_t>(written));
        }
        return true;
    }
    return false;
}
VmRuntime::ConsoleTarget VmRuntime::console_target() const {
    std::unique_lock lock(state_mutex_, std::try_to_lock);
    if (!lock.owns_lock()) throw ConsoleBusy();
    ConsoleTarget result{version_.observe(), {}};
    if (retired_ || state_ != State::running) return result;
    for (const auto& name : order_) {
        if (name == "agent") continue;
        for (const auto& serial : serials_)
            if (serial.stream == name && serial.local_read.get() >= 0 && serial.local_write.get() >= 0) {
                result.streams.push_back(name); break;
            }
    }
    return result;
}
const VmRuntime::Serial& VmRuntime::console_serial(const std::string& stream, const Observation& expected) const {
    version_.require(expected);
    if (retired_ || state_ != State::running)
        throw ServiceError(ErrorCode::conflict, "VM console requires the observed running instance");
    if (stream != "agent" && logs_.contains(stream))
        for (const auto& serial : serials_)
            if (serial.stream == stream && serial.local_read.get() >= 0 && serial.local_write.get() >= 0) return serial;
    throw ServiceError(ErrorCode::not_found, "Interactive serial console not found");
}
LogSlice VmRuntime::console_read(const std::string& stream, const Observation& expected,
        const std::optional<LogCursor>& cursor, bool tail) const {
    std::unique_lock lock(state_mutex_, std::try_to_lock);
    if (!lock.owns_lock()) throw ConsoleBusy();
    (void)console_serial(stream, expected);
    auto result = logs_.at(stream)->try_read(cursor, tail);
    if (!result) throw ConsoleBusy();
    return std::move(*result);
}
size_t VmRuntime::console_write(const std::string& stream, const Observation& expected, std::string_view data) {
    if (data.empty() || data.size() > console_write_limit)
        throw ServiceError(ErrorCode::invalid_argument, "Console input must contain 1 to 512 bytes");
    std::unique_lock lock(state_mutex_, std::try_to_lock);
    if (!lock.owns_lock()) throw ServiceError(ErrorCode::unavailable, "VM console is busy");
    const auto& serial = console_serial(stream, expected);
    return bounded_console_write(serial.local_write.get(), data);
}
namespace {
std::string display_endpoint_reason(const VncEndpoint& endpoint) {
    if (!endpoint.unavailable_reason.empty()) return endpoint.unavailable_reason;
    if (endpoint.port < 1 || endpoint.port > 65535) return "invalid-endpoint";
    // Backend option lists use commas as separators. A legacy password that
    // changes option parsing cannot be treated as an authoritative endpoint.
    if (endpoint.password.size() > 255 || endpoint.password.find_first_of(",\\\"'") != std::string::npos ||
        std::any_of(endpoint.password.begin(), endpoint.password.end(),
            [](unsigned char byte) { return byte < 0x20 || byte == 0x7f; })) return "unsupported";
    try { (void)local_vnc_address(endpoint.host); }
    catch (const ServiceError&) { return "invalid-endpoint"; }
    return {};
}
}
VmRuntime::DisplayTarget VmRuntime::display_target() const {
    std::unique_lock lock(state_mutex_, std::try_to_lock);
    if (!lock.owns_lock()) throw ConsoleBusy();
    if (context_.private_console) throw ServiceError(ErrorCode::permission_denied, "Private display unavailable");
    DisplayTarget result{version_.observe(), {}};
    for (const auto& screen : command::screens_of(config_)) {
        DisplayScreen item{screen.id, false, {}, false};
        if (!screen.enabled()) item.reason = "disabled";
        else if (retired_ || state_ != State::running || pid_.load() <= 0 || control_uncertain_) item.reason = "not-running";
        else if (screen.exporter() != "VNC") item.reason = "not-vnc";
        else {
            const auto endpoint = std::find_if(vnc_endpoints_.begin(), vnc_endpoints_.end(),
                [&](const auto& value) { return value.screen == screen.id; });
            if (endpoint == vnc_endpoints_.end()) item.reason = "unsupported";
            else {
                item.reason = display_endpoint_reason(*endpoint);
                item.available = item.reason.empty();
                item.input_enabled = item.available && endpoint->input_enabled;
            }
        }
        result.screens.push_back(std::move(item));
    }
    return result;
}
void VmRuntime::require_display(const Observation& expected) const {
    version_.require(expected);
    if (context_.private_console) throw ServiceError(ErrorCode::permission_denied, "Private display unavailable");
    if (retired_ || state_ != State::running || pid_.load() <= 0 || control_uncertain_)
        throw ServiceError(ErrorCode::conflict, "Display requires the observed running instance");
}
VmRuntime::OpenedDisplay VmRuntime::open_display(const std::string& screen, const Observation& expected) {
    std::unique_lock lock(state_mutex_, std::try_to_lock);
    if (!lock.owns_lock()) throw ConsoleBusy();
    require_display(expected);
    const auto endpoint = std::find_if(vnc_endpoints_.begin(), vnc_endpoints_.end(),
        [&](const auto& value) { return value.screen == screen; });
    if (endpoint == vnc_endpoints_.end() || !display_endpoint_reason(*endpoint).empty())
        throw ServiceError(ErrorCode::unavailable, "Display endpoint unavailable");
    auto stream = std::make_shared<VncStream>(endpoint->host, endpoint->port,
        [runtime = shared_from_this(), expected](const std::function<void()>& operation) {
            std::unique_lock state(runtime->state_mutex_, std::try_to_lock);
            if (!state.owns_lock()) throw ConsoleBusy();
            runtime->require_display(expected);
            operation(); // Nonblocking socket call while lifecycle is excluded.
        });
    return {std::move(stream), endpoint->password};
}
void VmRuntime::prepare_private_console_handoff(const Observation& expected) {
    if (!context_.private_console)
        throw ServiceError(ErrorCode::permission_denied, "Private VM ownership required");
    std::unique_lock lock(state_mutex_, std::try_to_lock);
    if (!lock.owns_lock()) throw ConsoleBusy();
    (void)console_serial("uart", expected);
    // The automation's SCRIPT:EXITED and SHELL:READY precede this boundary.
    // No previous console bytes, including password prompts/input echoes, are
    // addressable through old cursors after the history generations rotate.
    for (auto& [stream, history] : logs_) history->clear();
}
void VmRuntime::shutdown(std::chrono::milliseconds timeout) {
    stop();
    std::unique_lock lock(state_mutex_);
    if (idle_.wait_for(lock, timeout, [&] { return state_ == State::stopped && !worker_; })) return;
    if (process_) process_->signal(SIGKILL);
    idle_.wait_for(lock, std::chrono::seconds(10), [&] { return state_ == State::stopped && !worker_; });
}
}
