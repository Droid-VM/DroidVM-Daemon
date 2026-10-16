// SPDX-License-Identifier: GPL-3.0-or-later
// UsbAcmPool: configfs edits share one UDC unbind/bind window, each attempt
// first waits for the vendor USB HAL to look settled.
#include "vm/usb_acm.h"
#include "vm/host_facts.h"
#include "store/network_config.h"
#include "common/fd.h"
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <bit>
#include <cerrno>
#include <cstring>
#include <optional>
#include <thread>
#include <vector>

namespace droidvm::vm {
namespace {
constexpr const char* instance_prefix = "dvmpool";
std::string trim(std::string text) { // String.trim
    size_t first = 0, last = text.size();
    while (first < last && static_cast<unsigned char>(text[first]) <= 0x20) ++first;
    while (last > first && static_cast<unsigned char>(text[last - 1]) <= 0x20) --last;
    return text.substr(first, last - first);
}
std::optional<std::string> read_file(const std::string& path) {
    Fd file(open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (file.get() < 0) return std::nullopt;
    std::string result;
    char buffer[4096];
    for (;;) {
        const auto count = read(file.get(), buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return std::nullopt;
        if (!count) return result;
        result.append(buffer, static_cast<size_t>(count));
    }
}
std::string read_trimmed(const std::string& path) { return trim(read_file(path).value_or("")); }
bool exists(const std::string& path) { struct stat info{}; return stat(path.c_str(), &info) == 0; }
bool is_directory(const std::string& path) { struct stat info{}; return stat(path.c_str(), &info) == 0 && S_ISDIR(info.st_mode); }
// File.list: null when the directory cannot be read; no dot entries.
std::optional<std::vector<std::string>> list(const std::string& path) {
    DIR* dir = opendir(path.c_str());
    if (!dir) return std::nullopt;
    std::vector<std::string> names;
    while (const auto* entry = readdir(dir)) {
        const std::string name = entry->d_name;
        if (name != "." && name != "..") names.push_back(name);
    }
    closedir(dir);
    return names;
}
// Integer.parseInt; nullopt where it throws NumberFormatException.
std::optional<int> java_int(const std::string& text) {
    try {
        const auto value = config::java_long(text);
        if (value < INT32_MIN || value > INT32_MAX) return std::nullopt;
        return static_cast<int>(value);
    } catch (const std::exception&) { return std::nullopt; }
}
std::string failed(const std::string& what, int error) { return what + ": " + std::strerror(error); }
}

int GadgetFs::write(const std::string& path, std::string_view text) {
    Fd file(open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666));
    if (file.get() < 0) return errno;
    while (!text.empty()) {
        const auto count = ::write(file.get(), text.data(), text.size());
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return errno;
        text.remove_prefix(static_cast<size_t>(count));
    }
    return 0;
}
int GadgetFs::make_directory(const std::string& path) { return ::mkdir(path.c_str(), 0777) == 0 ? 0 : errno; }
int GadgetFs::symlink(const std::string& target, const std::string& link) { return ::symlink(target.c_str(), link.c_str()) == 0 ? 0 : errno; }
int GadgetFs::remove(const std::string& path) { return ::remove(path.c_str()) == 0 ? 0 : errno; }

bool acm_enabled(const Json::Value& app_config) { return config::boolean(app_config, acm_enable_key, acm_default_enable); }
int acm_ports(const Json::Value& app_config) {
    const auto n = std::bit_cast<int32_t>(static_cast<uint32_t>(config::integer(app_config, acm_ports_key, acm_default_ports)));
    return std::max(1, std::min(acm_max_ports, n));
}

AcmPool::AcmPool(AcmOptions options) : options_(std::move(options)) {
    if (!options_.fs) options_.fs = std::make_shared<GadgetFs>();
    if (!options_.property) options_.property = [](const char* name) { return system_property(name); };
    if (!options_.now) options_.now = [] { return std::chrono::steady_clock::now(); };
    if (!options_.sleep) options_.sleep = [](std::chrono::milliseconds delay) { std::this_thread::sleep_for(delay); };
    functions_ = options_.gadget + "/functions";
    config_ = options_.gadget + "/configs/b.1";
    udc_ = options_.gadget + "/UDC";
}
void AcmPool::apply_config(const Json::Value& app_config) {
    std::lock_guard lock(mutex_);
    try { reconcile(acm_enabled(app_config) ? acm_ports(app_config) : 0); }
    catch (const std::exception& error) { log("WARN", std::string("USB ACM pool reconcile failed: ") + error.what()); }
}
std::string AcmPool::acquire(int slot, const std::string& owner, const Json::Value& app_config) {
    std::lock_guard lock(mutex_);
    if (!acm_enabled(app_config))
        throw AcmSlotUnavailable("USB serial (ACM) is disabled; enable it in the app settings first");
    const auto pool_size = acm_ports(app_config);
    if (slot < 0 || slot >= pool_size)
        throw AcmSlotUnavailable("USB serial slot " + std::to_string(slot) + " is outside the pool (size " + std::to_string(pool_size) +
                                 "); raise the USB serial ports setting or pick a lower slot");
    const auto instance = instance_prefix + std::to_string(slot);
    if (const auto holder = owners_.find(instance); holder != owners_.end())
        throw AcmSlotUnavailable("USB serial slot " + std::to_string(slot) + " is busy (held by " + holder->second + ")");
    reconcile(pool_size);
    const auto path = dev_path_of(instance);
    wait_for_node(path);
    owners_[instance] = owner;
    log("INFO", "acm slot " + std::to_string(slot) + " (" + path + ") -> " + owner);
    return path;
}
void AcmPool::release(const std::string& owner) {
    std::lock_guard lock(mutex_);
    std::erase_if(owners_, [&](const auto& entry) { return entry.second == owner; });
}
std::map<std::string, std::string> AcmPool::owners() const {
    std::lock_guard lock(mutex_);
    return owners_;
}
// Only acm.dvmpool* is ever touched; members a VM holds are never removed.
void AcmPool::reconcile(int pool_size) {
    std::vector<std::string> to_remove;
    const auto name_prefix = std::string("acm.") + instance_prefix;
    if (const auto names = list(functions_)) for (const auto& name : *names) {
        if (!name.starts_with(name_prefix)) continue;
        const auto instance = name.substr(4);
        const auto index = java_int(instance.substr(std::strlen(instance_prefix)));
        if (!index) continue;
        if (*index >= pool_size && !owners_.contains(instance)) to_remove.push_back(functions_ + "/" + name);
    }
    bool missing_link = false;
    for (int i = 0; i < pool_size; ++i) {
        const auto name = name_prefix + std::to_string(i);
        const auto func = functions_ + "/" + name;
        // mkdir works while bound; only the config links need the unbound window.
        if (!is_directory(func) && options_.fs->make_directory(func) != 0) throw std::runtime_error("cannot create " + func);
        if (!exists(config_ + "/" + name)) missing_link = true;
    }
    if (!missing_link && to_remove.empty()) return;
    std::optional<std::string> last_failure;
    for (int attempt = 1; attempt <= options_.timing.udc_retries; ++attempt) {
        await_usb_settled();
        try {
            with_udc_unbound([&] {
                for (int i = 0; i < pool_size; ++i) {
                    const auto name = name_prefix + std::to_string(i);
                    const auto link = config_ + "/" + name;
                    if (exists(link)) continue;
                    if (const int error = options_.fs->symlink(functions_ + "/" + name, link)) throw std::runtime_error(failed("symlink failed", error));
                }
                for (const auto& func : to_remove) {
                    options_.fs->remove(config_ + func.substr(functions_.size()));
                    if (is_directory(func) && options_.fs->remove(func) != 0) log("WARN", "cannot remove " + func);
                }
            });
            last_failure.reset();
            break;
        } catch (const std::exception& error) {
            last_failure = error.what();
            log("WARN", "gadget reconcile attempt " + std::to_string(attempt) + "/" + std::to_string(options_.timing.udc_retries) +
                " lost the UDC race: " + error.what());
        }
    }
    if (last_failure) throw std::runtime_error(*last_failure);
    log("INFO", "USB ACM pool reconciled to " + std::to_string(pool_size) + " members");
}
// The kernel assigns the ttyGS index at function creation and reports it in port_num.
std::string AcmPool::dev_path_of(const std::string& instance) {
    const auto file = functions_ + "/acm." + instance + "/port_num";
    const auto text = read_file(file);
    if (!text) throw std::runtime_error(file + " (" + std::strerror(errno) + ")"); // FileNotFoundException
    const auto port = java_int(trim(*text));
    if (!port) throw std::runtime_error("cannot parse acm port_num");
    return options_.dev + "/ttyGS" + std::to_string(*port);
}
// The node only appears after the gadget binds.
void AcmPool::wait_for_node(const std::string& path) {
    for (std::chrono::milliseconds waited{0}; !exists(path); waited += options_.timing.node_poll) {
        if (waited >= options_.timing.node_wait) throw std::runtime_error(path + " did not appear after bind");
        options_.sleep(options_.timing.node_poll);
    }
}
// Boot is done and the UDC holds one steady non-empty value across a probe.
bool AcmPool::usb_settled() {
    if (trim(options_.property("sys.boot_completed")) != "1") return false;
    const auto first = read_file(udc_);
    if (!first || trim(*first).empty()) return false;
    options_.sleep(options_.timing.settle_probe);
    const auto again = read_file(udc_);
    return again && trim(*first) == trim(*again);
}
void AcmPool::await_usb_settled() {
    const auto deadline = options_.now() + options_.timing.settle_timeout;
    while (options_.now() < deadline) {
        if (usb_settled()) return;
        options_.sleep(options_.timing.settle_poll);
    }
    log("WARN", "USB stack did not settle in time; attempting the gadget edit anyway");
}
// Unbind, edit, bind back-to-back; the bind always runs so a failed edit
// never strands the gadget unbound.
void AcmPool::with_udc_unbound(const std::function<void()>& op) {
    auto udc = read_trimmed(udc_);
    if (udc.empty()) {
        const auto names = list(options_.udc_class);
        if (!names || names->empty()) throw std::runtime_error("no UDC available");
        udc = names->front();
    }
    // A newline, not "": zero bytes never reach the UDC store, so the gadget stays bound.
    options_.fs->write(udc_, "\n");
    if (const auto check = read_trimmed(udc_); !check.empty())
        throw std::runtime_error("gadget did not unbind (UDC still " + check + ")");
    std::exception_ptr failure;
    try { op(); } catch (...) { failure = std::current_exception(); }
    // EBUSY means the racing HAL bound first; only a UDC left unbound fails.
    if (const int error = options_.fs->write(udc_, udc); error != 0 && read_trimmed(udc_).empty())
        throw std::runtime_error(failed(udc_, error));
    if (failure) std::rethrow_exception(failure);
}
}
