// SPDX-License-Identifier: GPL-3.0-or-later
// Port of daemon/vm/VMInstance's lifecycle and the crosvm/QEMU backend
// instances' start, cleanup and runControlCommand.
#include "runtime.h"
#include "vm/boot_plan.h"
#include "vm/crosvm_command.h"
#include "vm/qemu_command.h"
#include "vm/host_facts.h"
#include "runtime/helper_identity.h"
#include "services/legacy_events.h"
#include "store/network_config.h"
#include "store/vm_config.h"
#include "common/identity.h"
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
VmRuntime::VmRuntime(std::string id, Json::Value config, const RuntimeContext& context)
    : id_(std::move(id)), context_(context), config_(std::move(config)) { create_streams(); }
VmRuntime::~VmRuntime() = default;
void VmRuntime::create_streams() {
    for (const auto& name : config::vm_streams(config_)) {
        const auto stream = name.asString();
        if (logs_.contains(stream)) continue;
        // Persistent agent logs are disabled in the legacy QEMU backend.
        logs_[stream] = std::make_unique<ConsoleLog>(console_log_path(context_.cache_dir, id_, stream), context_.owner, stream != "agent");
        order_.push_back(stream);
    }
}
State VmRuntime::state() const { std::lock_guard lock(state_mutex_); return state_; }
int64_t VmRuntime::pid() const { return pid_.load(); }
Json::Value VmRuntime::config() const { std::lock_guard lock(state_mutex_); return config_; }
void VmRuntime::replace(Json::Value config) {
    std::lock_guard lock(state_mutex_);
    config_ = std::move(config);
    // The legacy instance is rebuilt on modify: streams follow the new config.
    logs_.clear(); order_.clear(); create_streams();
}
std::vector<std::string> VmRuntime::streams() const { std::lock_guard lock(state_mutex_); return order_; }
ConsoleLog* VmRuntime::log(const std::string& stream) const {
    std::lock_guard lock(state_mutex_);
    const auto at = logs_.find(stream);
    return at == logs_.end() ? nullptr : at->second.get();
}
void VmRuntime::clear_logs() { std::lock_guard lock(state_mutex_); for (auto& [name, log] : logs_) log->clear(); }
void VmRuntime::set_state(State next) {
    // Release before publishing STOPPED so a new start keeps its reservation.
    if (next == State::stopped && context_.pool) context_.pool->release(id_);
    { std::lock_guard lock(state_mutex_); state_ = next; }
    fire("state");
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
        if (auto* stdio = log("stdio")) data["stdio"] = utf8_lossy(stdio->contents());
    }
    if (extra.isObject()) for (const auto& key : extra.getMemberNames()) data[key] = extra[key];
    context_.events->publish(data);
}
bool VmRuntime::start(std::optional<std::string> boot_entry) {
    std::unique_lock lock(lock_);
    {
        std::lock_guard state(state_mutex_);
        if (state_ != State::stopped) return false;
        boot_entry_ = std::move(boot_entry);
    }
    return start_locked(false);
}
bool VmRuntime::start_locked(bool relaunch) {
    if (context_.shutting_down()) return false;
    {
        std::unique_lock state(state_mutex_);
        if (state_ != State::stopped && state_ != State::rebooting) return false;
        relaunch = state_ == State::rebooting;
        idle_.wait_for(state, 1s, [&] { return !worker_; });
        if (worker_) return false;
    }
    if (!setup_taps()) return false;
    { std::lock_guard state(state_mutex_); resolve_vnc(config_); }
    try {
        if (!relaunch) reboot_requested_ = false;
        stopped_by_user_ = false;
        exit_code_ = -1;
        const auto config = this->config();
        HostFacts facts;
        facts.has_kvm = access("/dev/kvm", F_OK) == 0;
        facts.has_gunyah = access("/dev/gunyah", F_OK) == 0;
        if (!relaunch && context_.pool && resolves_to_gunyah(config, facts) && context_.hugepages.resizable()) {
            const auto mb = std::max<int64_t>(config::integer(config, "memory_mb", 512), 64) + boot_guest_prealloc_mb(config);
            if (!context_.pool->reserve(id_, (mb + HugepagePool::page_mb - 1) / HugepagePool::page_mb))
                throw std::runtime_error("Could not set huge-page reserve target");
        }
        set_state(State::starting);
        { std::lock_guard state(state_mutex_); worker_ = true; }
        std::thread([self = shared_from_this()] { self->run(); }).detach();
    } catch (const std::exception& error) {
        context_.warn("Cannot start VM " + config::string(config(), "name") + ": " + error.what());
        cleanup_taps();
        cleanup_backend();
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
        const bool required = context_.pool && context_.pool->contains(id_);
        if (required || context_.hugepages.present()) {
            const auto mb = std::max<int64_t>(config::integer(config, "memory_mb", 512), 64) + boot_guest_prealloc_mb(config);
            ready = context_.hugepages.wait((mb + HugepagePool::page_mb - 1) / HugepagePool::page_mb, aborted);
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
    if (!stopped_by_user_) set_state(State::running);
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
    std::lock_guard lock(lock_);
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
            if (!self->start_locked(true)) self->finish_stopped(-1);
        }).detach();
        return;
    }
    if (access("/sys/kernel/nproc_guard/reset", F_OK) == 0) write_quiet("/sys/kernel/nproc_guard/reset", "1");
    { std::lock_guard state(state_mutex_); worker_ = false; }
    set_state(State::stopped);
    fire("exited");
}
bool VmRuntime::launch(const Json::Value& config, const BootPlan& plan, std::string& failure) {
    mkdir(context_.run_dir.c_str(), 0700);
    if (config::java_enum(config, "backend", "CROSVM", {"CROSVM", "QEMU"}) == "QEMU") return launch_qemu(config, plan, failure);
    CrosvmRun run;
    {
        std::lock_guard lock(state_mutex_);
        serials_.clear();
        const auto& ports = config::member(config, "serial_ports");
        if (ports.isArray()) for (const auto& port : ports) {
            SerialRun resolved;
            if (config::java_enum(port, "backend", "SINK", {"SINK", "APP_CONSOLE", "FILE", "UNIX", "UNIX_STREAM", "PTY", "STDOUT", "SYSLOG", "USB_ACM"}) == "APP_CONSOLE") {
                const auto hardware = config::java_enum(port, "hardware", "SERIAL", {"SERIAL", "SBSA", "VIRTIO_CONSOLE"});
                const auto num = std::to_string(std::bit_cast<int32_t>(static_cast<uint32_t>(config::integer(port, "num", 1))));
                const auto name = (hardware == "SBSA" ? "sbsa" : hardware == "VIRTIO_CONSOLE" ? "vcon" : "serial") + num;
                int out[2], in[2];
                if (logs_.contains(name) && pipe2(out, O_CLOEXEC) == 0) {
                    if (pipe2(in, O_CLOEXEC) == 0) {
                        Serial serial{name, Fd(out[0]), Fd(in[1]), Fd(out[1]), Fd(in[0])};
                        resolved.pipe = std::pair{serial.remote_write.get(), serial.remote_read.get()};
                        serials_.push_back(std::move(serial));
                    } else { close(out[0]); close(out[1]); }
                }
            }
            // USB ACM slots belong to the peripheral pool (P5): degrade to a sink.
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
        try { input_.listen(command.input_sockets); }
        catch (const std::invalid_argument& error) { failure = std::string("display input setup failed: ") + error.what(); return false; }
    }
    if (command.udmabuf_limit_mb) {
        glob_t matches{};
        if (glob("/sys/module/udmabuf*/parameters/size_limit_mb", 0, nullptr, &matches) == 0)
            for (size_t i = 0; i < matches.gl_pathc; ++i) write_quiet(matches.gl_pathv[i], std::to_string(*command.udmabuf_limit_mb));
        globfree(&matches);
    }
    return spawn(command.argv, command.env, command.strace_dir, "crosvm", failure);
}
bool VmRuntime::launch_qemu(const Json::Value& config, const BootPlan& plan, std::string& failure) {
    auto host = probe_host({context_.owner, context_.run_dir + "/app-gids", context_.optimize_sdcard(),
                            plan.uefi ? (plan.vars.empty() ? edk2_vars() : plan.vars) : std::string()});
    host.data_dir = context_.data_dir;
    auto run = qemu_sockets(config, host);
    run.file_length = [](const std::string& path) -> int64_t { struct stat info{}; return stat(path.c_str(), &info) == 0 && S_ISREG(info.st_mode) ? info.st_size : 0; };
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
    }
    if (!spawn(command.argv, command.env, command.strace_dir, "qemu", failure)) return false;
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
                      const std::optional<std::string>& strace_dir, const char* label, std::string& failure) {
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
    options.argv = argv;
    options.environment = merged_environment(env);
    options.limits = {{RLIMIT_NOFILE, 65536, 65536}, {RLIMIT_MEMLOCK, RLIM_INFINITY, RLIM_INFINITY}};
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
    try {
        auto process = std::make_unique<Child>(options);
        std::lock_guard lock(state_mutex_);
        pid_ = process->pid();
        process_ = std::move(process);
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
    std::lock_guard lock(state_mutex_);
    if (control_socket_) { unlink(control_socket_->c_str()); control_socket_.reset(); }
    for (const auto& path : sockets_) unlink(path.c_str());
    sockets_.clear(); qemu_ = false;
    serials_.clear();
    if (!identity_.name.empty() && context_.identities) {
        try { context_.identities->cleanup(identity_.name); identity_.directory = Fd(); identity_.name.clear(); } catch (const std::exception&) {}
    }
}
void VmRuntime::finish_stopped(int code) {
    exit_code_ = code;
    cleanup_taps();
    cleanup_backend();
    { std::lock_guard state(state_mutex_); worker_ = false; }
    set_state(State::stopped);
    fire("exited");
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
    Fd socket_fd(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (socket_fd.get() < 0 || path->size() >= sizeof(address.sun_path)) return -1;
    std::copy(path->begin(), path->end(), address.sun_path);
    timeval timeout{5, 0};
    setsockopt(socket_fd.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(socket_fd.get(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (connect(socket_fd.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) return -1;
    char buffer[4096];
    auto receive = [&]() -> ssize_t { ssize_t count; do count = recv(socket_fd.get(), buffer, sizeof(buffer), 0); while (count < 0 && errno == EINTR); return count; };
    auto send_line = [&](const Json::Value& value) {
        Json::StreamWriterBuilder builder; builder["indentation"] = "";
        const auto text = Json::writeString(builder, value) + "\n";
        return ::send(socket_fd.get(), text.data(), text.size(), MSG_NOSIGNAL) == static_cast<ssize_t>(text.size());
    };
    if (receive() <= 0) return -1;
    Json::Value capabilities;
    capabilities["execute"] = "qmp_capabilities";
    if (!send_line(capabilities)) return -1;
    receive();
    if (!send_line(request)) return -1;
    const auto count = receive();
    if (count <= 0) return -1;
    Json::CharReaderBuilder reader_builder;
    std::unique_ptr<Json::CharReader> reader(reader_builder.newCharReader());
    Json::Value response;
    std::string error;
    if (!reader->parse(buffer, buffer + count, &response, &error) || !response.isObject()) return -1;
    if (response.isMember("return")) return 0;
    return response.isMember("error") ? -1 : 0;
}
int VmRuntime::send_control(const std::string& command) {
    if (qemu_) return send_qmp(command);
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
bool VmRuntime::stop() {
    std::lock_guard lock(lock_);
    const auto current = state();
    if (current == State::rebooting) {
        // A relaunch has no live process: cancel it and release its budget.
        stopped_by_user_ = true;
        exit_code_ = 0;
        set_state(State::stopped);
        fire("exited");
        return true;
    }
    if (current != State::running && current != State::starting && current != State::suspended) return false;
    stopped_by_user_ = true;
    set_state(State::stopping);
    { std::lock_guard state(state_mutex_); if (!process_) return true; } // the worker observes stopped_by_user_
    if (send_control("stop") == 0) return true;
    kill_process();
    return true;
}
bool VmRuntime::reboot() {
    if (state() != State::running) return false;
    reboot_requested_ = true;
    if (send_control("stop") == 0) return true;
    kill_process();
    return true;
}
bool VmRuntime::suspend() {
    if (state() != State::running) return false;
    if (send_control("suspend") != 0) return false;
    set_state(State::suspended);
    return true;
}
bool VmRuntime::resume() {
    if (state() != State::suspended) return false;
    if (send_control("resume") != 0) return false;
    set_state(State::running);
    return true;
}
bool VmRuntime::control(const std::string& command) { return send_control(command) == 0; }
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
void VmRuntime::shutdown(std::chrono::milliseconds timeout) {
    stop();
    std::unique_lock lock(state_mutex_);
    if (idle_.wait_for(lock, timeout, [&] { return state_ == State::stopped && !worker_; })) return;
    if (process_) process_->signal(SIGKILL);
    idle_.wait_for(lock, std::chrono::seconds(10), [&] { return state_ == State::stopped && !worker_; });
}
}
