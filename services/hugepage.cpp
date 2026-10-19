// SPDX-License-Identifier: GPL-3.0-or-later
#include "hugepage.h"
#include "common/identity.h"
#ifndef _WIN32
#include "runtime/child.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <sstream>
#include <thread>

namespace droidvm {
namespace {
constexpr size_t max_file = 65536;
constexpr int64_t max_pages = 1073741824;
const char* const controls[] = {"pool_want", "pool_target", "pool_want_with_cma",
    "moveable_to_cma_vender_already_allowed", "moveable_to_cma_restrict_cma_redirect_disabled",
    "moveable_to_cma_gfp_cma_hook", "system_reserve_mb", "system_reserve_mb_default",
    "cma_reservoir_floor_mb", "boot_acquire", "boot_acquire_runs", "boot_acquire_wait"};
const std::map<std::string, std::pair<int64_t, int64_t>> advanced = {
    {"system_reserve_mb", {64, 1048576}}, {"cma_reservoir_floor_mb", {0, 1048576}},
    {"boot_acquire", {0, 3}}, {"boot_acquire_runs", {1, 99}}, {"boot_acquire_wait", {0, 3600}}};
void require(bool good, ErrorCode code, const char* message) { if (!good) throw ServiceError(code, message); }
void access(const CallContext& caller) {
    require(caller.authenticated, ErrorCode::unauthenticated, "Authentication required");
    require(caller.administrator && !caller.principal.empty(), ErrorCode::permission_denied, "Administrator permission required");
}
std::string trim(std::string value) {
    auto first = value.find_first_not_of(" \t\r\n"), last = value.find_last_not_of(" \t\r\n");
    return first == std::string::npos ? std::string() : value.substr(first, last - first + 1);
}
std::optional<int64_t> number(const std::string& value) {
    const auto clean = trim(value); int64_t result = 0;
    auto parsed = std::from_chars(clean.data(), clean.data() + clean.size(), result);
    if (clean.empty() || parsed.ec != std::errc{} || parsed.ptr != clean.data() + clean.size()) return {};
    return result;
}
std::string encode(const Json::Value& value) { Json::StreamWriterBuilder writer; writer["indentation"] = ""; return Json::writeString(writer, value); }
TaskView with_cancellation_receipt(TaskView task) {
    // TaskService cancels queued work without invoking execute(). Such a task
    // has a definite no-effect outcome, unlike a missing or expired record.
    if (task.state == TaskState::cancelled && task.result.isNull()) {
        for (const auto* flag : {"saved", "applied", "degraded", "uncertain"}) task.result[flag] = false;
        task.result["implementation"] = "cancelled-before-start";
        task.result["snapshot"] = Json::Value();
        task.result_available = true;
    }
    return task;
}
Json::Value props(const std::string& bytes, bool stats) {
    Json::Value out(Json::objectValue);
    std::istringstream lines(bytes); std::string line;
    while (std::getline(lines, line)) {
        if (stats) {
            std::istringstream words(line); std::string word;
            while (words >> word) {
                auto equal = word.find('=');
                if (equal == std::string::npos || equal == 0) continue;
                const auto key = word.substr(0, equal), value = word.substr(equal + 1);
                if (auto n = number(value)) out[key] = Json::Int64(*n); else out[key] = value;
            }
        } else {
            line = trim(line); if (line.empty() || line[0] == '#') continue;
            const auto equal = line.find('=');
            require(equal != std::string::npos, ErrorCode::io_error, "Malformed module settings");
            const auto key = trim(line.substr(0, equal)), value = trim(line.substr(equal + 1));
            require(!key.empty() && key.size() <= 128 && key.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") == std::string::npos,
                ErrorCode::io_error, "Malformed module setting key");
            require(value.size() <= 4096 && value.find('\0') == std::string::npos, ErrorCode::io_error, "Malformed module setting value");
            out[key] = value;
        }
    }
    return out;
}
bool file_exists(const std::string& path) {
    std::error_code error; auto state = std::filesystem::status(path, error);
    if (error == std::errc::no_such_file_or_directory) return false;
    require(!error, ErrorCode::io_error, "Cannot inspect module file");
    return std::filesystem::exists(state);
}
bool file_writable(const std::string& path) {
    std::error_code error;
    const auto state = std::filesystem::status(path, error);
    if (error || !std::filesystem::exists(state)) return false;
    const auto permissions = state.permissions();
    return permissions != std::filesystem::perms::unknown &&
        (permissions & std::filesystem::perms::owner_write) != std::filesystem::perms::none;
}
std::string file_identity(const std::string& path) {
#ifdef _WIN32
    auto file = CreateFileW(std::filesystem::path(path).c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (file == INVALID_HANDLE_VALUE) return "unavailable";
    BY_HANDLE_FILE_INFORMATION info{}; bool ok = GetFileInformationByHandle(file, &info) != 0; CloseHandle(file);
    if (!ok) return "unavailable";
    return std::to_string(info.dwVolumeSerialNumber) + ":" + std::to_string(info.nFileIndexHigh) + ":" + std::to_string(info.nFileIndexLow) + ":" + std::to_string(info.ftCreationTime.dwHighDateTime) + ":" + std::to_string(info.ftCreationTime.dwLowDateTime);
#else
    struct stat info{}; if (::stat(path.c_str(), &info) != 0) return "unavailable";
    return std::to_string(info.st_dev) + ":" + std::to_string(info.st_ino) + ":" + std::to_string(info.st_ctim.tv_sec) + ":" + std::to_string(info.st_ctim.tv_nsec);
#endif
}
std::optional<std::string> file_read(const std::string& path, size_t limit) {
#ifdef _WIN32
    if (!file_exists(path)) return {};
    std::ifstream file(path, std::ios::binary);
    require(file.good(), ErrorCode::io_error, "Cannot read module file");
    std::string bytes; char buffer[4096];
    while (file.read(buffer, sizeof(buffer)) || file.gcount()) {
        bytes.append(buffer, static_cast<size_t>(file.gcount()));
        require(bytes.size() <= limit, ErrorCode::resource_exhausted, "Module file exceeds limit");
    }
    require(file.eof(), ErrorCode::io_error, "Cannot read module file");
    return bytes;
#else
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 && errno == ENOENT) return {};
    require(fd >= 0, ErrorCode::io_error, "Cannot open module file");
    std::string bytes; char buffer[4096];
    for (;;) {
        auto count = ::read(fd, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 || (count > 0 && bytes.size() + static_cast<size_t>(count) > limit)) {
            ::close(fd); throw ServiceError(ErrorCode::io_error, "Cannot read bounded module file");
        }
        if (!count) break;
        bytes.append(buffer, static_cast<size_t>(count));
    }
    ::close(fd); return bytes;
#endif
}
bool file_write(const std::string& path, const std::string& value) {
#ifdef _WIN32
    std::ofstream file(path, std::ios::binary | std::ios::trunc); file << value << '\n'; file.close(); return !file.fail();
#else
    int fd = ::open(path.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    const auto bytes = value + "\n";
    const auto count = ::write(fd, bytes.data(), bytes.size());
    const bool closed = ::close(fd) == 0;
    return count >= 0 && static_cast<size_t>(count) == bytes.size() && closed;
#endif
}
void atomic_publish(const std::string& path, const std::string& bytes) {
    const std::filesystem::path target(path);
    const auto temporary = "." + target.filename().string() + "." + random_id(false) + ".tmp";
#ifdef _WIN32
    const auto staging = target.parent_path() / temporary;
    HANDLE file = CreateFileW(staging.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    require(file != INVALID_HANDLE_VALUE, ErrorCode::io_error, "Cannot create module settings");
    DWORD count = 0;
    bool written = WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) && count == bytes.size() && FlushFileBuffers(file);
    CloseHandle(file);
    if (!written || !MoveFileExW(staging.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(staging.c_str()); throw ServiceError(ErrorCode::commit_uncertain, "Module settings publication failed");
    }
#else
    int dir = ::open(target.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    require(dir >= 0, ErrorCode::io_error, "Cannot open module settings directory");
    struct stat info{};
    if (fstat(dir, &info) != 0 || (info.st_uid != 0 && info.st_uid != geteuid()) || (info.st_mode & 0022)) {
        ::close(dir); throw ServiceError(ErrorCode::permission_denied, "Untrusted module settings directory");
    }
    int fd = openat(dir, temporary.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) { ::close(dir); throw ServiceError(ErrorCode::io_error, "Cannot create module settings"); }
    size_t offset = 0; bool good = true;
    while (offset < bytes.size()) {
        auto count = ::write(fd, bytes.data() + offset, bytes.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { good = false; break; }
        offset += static_cast<size_t>(count);
    }
    good = good && fsync(fd) == 0;
    if (::close(fd) != 0) good = false;
    bool renamed = false;
    if (good) renamed = renameat(dir, temporary.c_str(), dir, target.filename().c_str()) == 0;
    bool synced = renamed && fsync(dir) == 0;
    if (!renamed) unlinkat(dir, temporary.c_str(), 0);
    ::close(dir);
    require(synced, renamed ? ErrorCode::commit_uncertain : ErrorCode::io_error, "Module settings publication failed");
#endif
}
void marker_write(const std::string& path, bool present) {
    if (present) { atomic_publish(path, ""); return; }
#ifdef _WIN32
    std::error_code error; std::filesystem::remove(path, error);
    require(!error, ErrorCode::io_error, "Cannot remove module boot marker");
#else
    const std::filesystem::path target(path);
    int dir = ::open(target.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    require(dir >= 0, ErrorCode::io_error, "Cannot open module boot directory");
    const bool removed = unlinkat(dir, target.filename().c_str(), 0) == 0 || errno == ENOENT;
    const bool synced = removed && fsync(dir) == 0; ::close(dir);
    require(synced, ErrorCode::commit_uncertain, "Module boot marker update failed");
#endif
}
HugepageCommandResult command_run(const std::vector<std::string>& argv) {
#ifdef _WIN32
    (void)argv; throw ServiceError(ErrorCode::unavailable, "Kernel module operations unavailable on this host");
#else
    ChildOptions options; options.argv = argv; Child child(options);
    auto result = child.communicate({}, std::chrono::seconds(30), max_file);
    return {result.exit_code, result.timed_out || result.cancelled || result.truncated, std::move(result.output), std::move(result.error)};
#endif
}
int64_t integer(const Json::Value& object, const char* key, int64_t low, int64_t high) {
    require(object.isMember(key), ErrorCode::invalid_argument, "Expected bounded integer");
    std::optional<int64_t> value;
    if (object[key].isInt64()) value = object[key].asInt64();
    else if (object[key].isString()) {
        const auto text = object[key].asString();
        require(!text.empty() && text.size() <= 19 && text.find_first_not_of("0123456789") == std::string::npos && (text.size() == 1 || text[0] != '0'), ErrorCode::invalid_argument, "Expected canonical decimal integer");
        value = number(text);
    }
    require(value && *value >= low && *value <= high, ErrorCode::invalid_argument, "Integer outside allowed range"); return *value;
}
bool boolean(const Json::Value& object, const char* key) {
    require(object.isMember(key) && object[key].isBool(), ErrorCode::invalid_argument, "Expected boolean"); return object[key].asBool();
}
void keys(const Json::Value& value, std::initializer_list<const char*> allowed) {
    require(value.isObject(), ErrorCode::invalid_argument, "Expected object");
    for (const auto& key : value.getMemberNames()) {
        const bool found = std::any_of(allowed.begin(), allowed.end(), [&](const char* entry) { return key == entry; });
        require(found, ErrorCode::invalid_argument, "Unexpected operation field");
    }
}
std::string lever(const Json::Value& value) {
    require(value.isNull() || (value.isString() && (value.asString() == "flag" || value.asString() == "hook")), ErrorCode::invalid_argument, "Invalid CMA lever");
    return value.isNull() ? std::string() : value.asString();
}
void validate_operation(const Json::Value& op) {
    require(op.isObject() && op["kind"].isString(), ErrorCode::invalid_argument, "Expected hugepage operation");
    const auto kind = op["kind"].asString();
    if (kind == "runtime" || kind == "boot" || kind == "restrict" || kind == "gfp-hook") {
        keys(op, {"kind", "enabled"}); boolean(op, "enabled");
    } else if (kind == "unload" || kind == "stop-acquire" || kind == "reconcile" || kind == "migrate-settings" || kind == "dismiss-crash") keys(op, {"kind"});
    else if (kind == "acquire") { keys(op, {"kind", "mode"}); integer(op, "mode", 1, 3); }
    else if (kind == "targets") {
        keys(op, {"kind", "poolPages", "cmaPages", "persist", "acquireMode"});
        auto pool = integer(op, "poolPages", 0, max_pages);
        require(op.isMember("cmaPages"), ErrorCode::invalid_argument, "Missing CMA target");
        if (!op["cmaPages"].isNull()) {
            auto cma = integer(op, "cmaPages", 0, max_pages);
            require(cma == 0 || cma >= pool, ErrorCode::invalid_argument, "CMA target must cover pool target");
        }
        boolean(op, "persist");
        if (op.isMember("acquireMode")) integer(op, "acquireMode", 0, 3);
    } else if (kind == "cma-target") { keys(op, {"kind", "pages", "persist"}); integer(op, "pages", 0, max_pages); boolean(op, "persist"); }
    else if (kind == "cma-lever") { keys(op, {"kind", "value"}); require(op.isMember("value"), ErrorCode::invalid_argument, "Missing lever"); lever(op["value"]); }
    else if (kind == "advanced") {
        keys(op, {"kind", "key", "value"}); require(op["key"].isString() && op.isMember("value"), ErrorCode::invalid_argument, "Missing advanced setting");
        const auto found = advanced.find(op["key"].asString()); require(found != advanced.end(), ErrorCode::invalid_argument, "Unsupported advanced setting");
        if (!op["value"].isNull()) integer(op, "value", found->second.first, found->second.second);
    } else if (kind == "cma") {
        keys(op, {"kind", "enabled", "pages", "persist", "lever"});
        if (boolean(op, "enabled")) { integer(op, "pages", 1, max_pages); require(op.isMember("lever"), ErrorCode::invalid_argument, "Missing CMA lever"); lever(op["lever"]); }
        else if (op.isMember("pages")) integer(op, "pages", 0, 0);
        if (op.isMember("lever")) lever(op["lever"]);
        if (op.isMember("persist")) boolean(op, "persist");
    } else if (kind == "cma-save") {
        keys(op, {"kind", "pages", "lever"}); integer(op, "pages", 0, max_pages);
        require(op.isMember("lever"), ErrorCode::invalid_argument, "Missing CMA lever"); lever(op["lever"]);
    } else throw ServiceError(ErrorCode::invalid_argument, "Unsupported hugepage operation");
}
}
struct HugepageService::Impl {
    TaskService& tasks;
    vm::PoolReservations& pool;
    HugepageOptions io;
    Impl(TaskService& tasks, vm::PoolReservations& pool, HugepageOptions options) : tasks(tasks), pool(pool), io(std::move(options)) {
        if (!io.exists) io.exists = file_exists;
        if (!io.writable) io.writable = file_writable;
        if (!io.identity) io.identity = file_identity;
        if (!io.read) io.read = file_read;
        if (!io.write) io.write = file_write;
        if (!io.publish) io.publish = atomic_publish;
        if (!io.marker) io.marker = marker_write;
        if (!io.run) io.run = command_run;
    }
    std::string param(const std::string& key) const { return io.parameters + "/" + key; }
    std::string module(const std::string& key) const { return io.module_directory + "/" + key; }
    bool has(const std::string& key) const { return io.exists(param(key)); }
    bool loaded() const { return io.exists(io.parameters); }
    bool advanced_live_writable(const std::string& key) const {
        return key == "cma_reservoir_floor_mb" && has(key) && io.writable(param(key));
    }
    std::optional<int64_t> read(const std::string& key) const {
        const auto bytes = io.read(param(key), 128); return bytes ? number(*bytes) : std::nullopt;
    }
    Json::Value settings() const {
        const auto bytes = io.read(module("settings.prop"), max_file);
        require(bytes || !io.exists(module("settings.prop")), ErrorCode::io_error, "Existing module settings could not be read");
        return props(bytes.value_or(""), false);
    }
    Json::Value stat() const { return props(io.read(param("refill_stat"), max_file).value_or(""), true); }
    Json::Value snapshot() const {
        const auto state = pool.snapshot();
        Json::Value out(Json::objectValue); out["capability"] = HugepageService::capability;
        out["revision"] = Json::UInt64(state.revision); out["busy"] = state.busy;
        out["consumerPages"] = Json::Int64(state.pages); out["consumerCount"] = Json::UInt64(state.consumers);
        out["manualPoolPages"] = state.manual_known ? Json::Value(Json::Int64(state.manual_pages)) : Json::Value();
        out["installed"] = io.exists(module("module.prop")); out["loaded"] = loaded();
        out["moduleIdentity"] = out["loaded"].asBool() ? io.identity(io.parameters) : "absent";
        out["hasCrash"] = io.exists(module("crash"));
        out["bootEnabled"] = out["installed"].asBool() && !io.exists(module("disable"));
        out["hasPoolWant"] = has("pool_want"); out["hasCma"] = has("pool_want_with_cma");
        out["stats"] = stat(); out["settings"] = settings();
        out["hasLegacySettings"] = out["settings"].isMember("cma_probe_result");
        auto& features = out["features"];
        features["acquire"] = has("acquire") || has("manual_refill");
        features["stopAcquire"] = has("acquire");
        features["reconcile"] = has("reconcile");
        features["restrict"] = has("moveable_to_cma_restrict_cma_redirect_disabled");
        features["gfpHook"] = has("moveable_to_cma_gfp_cma_hook");
        out["advancedLiveWritable"] = Json::Value(Json::objectValue);
        for (const auto& [key, range] : advanced) {
            (void)range;
            out["advancedLiveWritable"][key] = advanced_live_writable(key);
        }
        out["controls"] = Json::Value(Json::objectValue);
        for (const auto* key : controls) { const auto n = read(key); out["controls"][key] = n ? Json::Value(Json::Int64(*n)) : Json::Value(); }
        Json::Value stable;
        for (const auto* key : {"revision", "installed", "loaded", "moduleIdentity", "bootEnabled", "hasCrash", "hasLegacySettings", "features", "advancedLiveWritable", "controls", "settings", "consumerPages", "consumerCount", "manualPoolPages"}) stable[key] = out[key];
        const auto bytes = encode(stable); uint64_t hash = 14695981039346656037ULL;
        for (unsigned char c : bytes) { hash ^= c; hash *= 1099511628211ULL; }
        std::ostringstream fingerprint; fingerprint << tasks.epoch() << ':' << std::hex << hash;
        out["fingerprint"] = fingerprint.str(); return out;
    }
    void save(Json::Value values, Json::Value& receipt) {
        std::string bytes;
        for (const auto& key : values.getMemberNames()) bytes += key + "=" + values[key].asString() + "\n";
        require(bytes.size() <= max_file, ErrorCode::resource_exhausted, "Module settings exceed limit");
        io.publish(module("settings.prop"), bytes); receipt["saved"] = true;
    }
    void write(const std::string& key, int64_t value, Json::Value& receipt, bool verify = true, bool rounded = false) {
        require(has(key), ErrorCode::unavailable, "Module control is not supported");
        receipt["uncertain"] = true;
        require(io.write(param(key), std::to_string(value)), ErrorCode::commit_uncertain, "Module control write failed; observe state before another operation");
        receipt["applied"] = true;
        if (verify) {
            const auto actual = read(key);
            require(actual && (*actual == value || (rounded && value > 0 && *actual >= value)), ErrorCode::commit_uncertain, "Module control readback is unknown or differs");
        }
        receipt["uncertain"] = false;
    }
    void acquire(int mode, Json::Value& receipt) {
        require(loaded(), ErrorCode::unavailable, "Hugepage module is not loaded");
        const bool modern = has("acquire"), legacy = !modern && has("manual_refill");
        require(modern || legacy, ErrorCode::unavailable, "Acquire is unavailable");
        // Match the App's best-effort reclaim without making an unrelated
        // cache flush failure trigger acquire fallback or replay.
        try { io.write("/proc/sys/vm/drop_caches", "3"); } catch (...) {}
        if (modern) { write("acquire", mode, receipt, false); receipt["implementation"] = "acquire" + std::to_string(mode); }
        else { write("manual_refill", 1, receipt, false); receipt["implementation"] = "manual_refill"; receipt["degraded"] = mode != 1; }
    }
    void stop(Json::Value& receipt, bool wait) {
        require(loaded(), ErrorCode::unavailable, "Hugepage module is not loaded");
        if (!has("acquire")) {
            const auto observed = stat();
            require(observed["acquire_active"].isInt64() && observed["acquire_active"].asInt64() == 0,
                ErrorCode::unavailable, "Legacy acquire stop cannot be observed");
            return;
        }
        write("acquire", 0, receipt, false);
        if (!wait) return;
        for (unsigned i = 0; i < 60; ++i) {
            const auto observed = stat();
            require(observed["acquire_active"].isInt64(), ErrorCode::commit_uncertain, "Acquire stop cannot be observed");
            if (observed["acquire_active"].asInt64() == 0) return;
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        receipt["uncertain"] = true;
        throw ServiceError(ErrorCode::commit_uncertain, "Acquire worker has not stopped");
    }
    void quiesce(Json::Value& receipt) {
        if (!loaded()) return;
        const auto observed = stat();
        if (observed["acquire_active"].isInt64() && observed["acquire_active"].asInt64() == 0) return;
        if (!has("acquire")) {
            require(!observed.isMember("acquire_active"), ErrorCode::unavailable, "Legacy acquire worker cannot be stopped");
            // Older modules expose no worker-stop protocol. Their own target
            // setter/unload must arbitrate refill; do not claim observed idle.
            receipt["degraded"] = true;
            return;
        }
        stop(receipt, true);
    }
    void change_manual(const vm::PoolReservations::ControlLease& lease, int64_t pages, Json::Value& receipt) {
        require(pool.set_manual(lease, pages), ErrorCode::conflict, "Pool target is below active consumer demand");
        if (io.manual_changed) {
            receipt["uncertain"] = true;
            io.manual_changed(pages);
            receipt["uncertain"] = false;
        }
    }
    void cma_target(int64_t pages, Json::Value& receipt) {
        if (pages != 0) {
            const auto base = read("pool_want"); require(base && pages >= *base, ErrorCode::invalid_argument, "CMA target is below pool target");
        }
        write("pool_want_with_cma", pages, receipt, true, true);
    }
    int64_t actual(const char* key) const {
        const auto value = read(key);
        require(value.has_value(), ErrorCode::commit_uncertain, "Module target readback is unavailable"); return *value;
    }
    void target_settings(Json::Value& values, int64_t base, std::optional<int64_t> cma) {
        values["pool_want"] = std::to_string(base); values["pool_target"] = std::to_string(base);
        if (cma) {
            values["pool_want_with_cma"] = std::to_string(*cma);
            if (*cma > 0) values["pool_want_with_cma_last"] = std::to_string(*cma);
        }
    }
    void require_saved_cma(const Json::Value& values, int64_t pages) const {
        const auto saved_base = number(values.get("pool_want", values.get("pool_target", "1024")).asString());
        require(pages == 0 || (saved_base && pages >= *saved_base), ErrorCode::invalid_argument, "Saved CMA target is below saved pool target");
    }
    void run_checked(const std::vector<std::string>& argv, Json::Value& receipt) {
        receipt["uncertain"] = true;
        const auto result = io.run(argv);
        require(!result.uncertain && result.exit_code == 0, ErrorCode::commit_uncertain, "Kernel module command failed; observe state before another operation");
        receipt["applied"] = true; receipt["uncertain"] = false;
    }
    void load(int64_t pages, Json::Value& receipt) {
#ifdef __ANDROID__
        const std::string shell = "/system/bin/sh", insmod = "/system/bin/insmod";
#else
        const std::string shell = "/bin/sh", insmod = "/sbin/insmod";
#endif
        if (io.exists(module("load.sh"))) {
            run_checked({shell, module("load.sh")}, receipt);
            require(loaded(), ErrorCode::commit_uncertain, "Module load has no observable result");
            receipt["implementation"] = "load.sh"; return;
        }
        std::string guard;
        if (io.exists(module("kapi_check"))) {
            const auto result = io.run({module("kapi_check"), "/sys/kernel/btf/vmlinux"});
            require(!result.uncertain && result.exit_code == 0, ErrorCode::unavailable, "Module ABI preflight failed");
            std::istringstream lines(result.output); std::string line;
            while (std::getline(lines, line)) {
                line = trim(line); if (!line.starts_with("disable=")) continue;
                auto value = trim(line.substr(8));
                require(value.size() < 4096 && value.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_,") == std::string::npos,
                    ErrorCode::unavailable, "Invalid module ABI preflight result");
                if (!value.empty()) guard = "disable_kapi=" + value;
            }
        }
        const std::vector<std::vector<std::string>> rungs = {
            {"pool_want=" + std::to_string(pages), "pool_target=" + std::to_string(pages)},
            {"pool_want=" + std::to_string(pages)}, {"pool_target=" + std::to_string(pages)}, {}};
        for (size_t i = 0; i < rungs.size(); ++i) {
            std::vector<std::string> argv{insmod, module("gh_hugepage_reserve.ko")};
            if (!guard.empty()) argv.push_back(guard);
            argv.insert(argv.end(), rungs[i].begin(), rungs[i].end());
            receipt["uncertain"] = true; auto result = io.run(argv);
            if (!result.uncertain && result.exit_code == 0 && loaded()) {
                receipt["applied"] = true; receipt["uncertain"] = false; receipt["degraded"] = i != 0;
                receipt["implementation"] = i == 0 ? "insmod-both" : i == 1 ? "insmod-want" : i == 2 ? "insmod-target" : "insmod-default"; return;
            }
            // Never strip the ABI guard. Only explicit unknown-parameter
            // rejection permits another sizing rung; unknown failures stop.
            const auto error = result.error + result.output;
            require(!result.uncertain && !loaded() && (error.find("Unknown parameter") != std::string::npos || error.find("unknown parameter") != std::string::npos),
                ErrorCode::commit_uncertain, "Legacy module load failed; no unsafe fallback attempted");
        }
        throw ServiceError(ErrorCode::unavailable, "Legacy module sizing is unsupported");
    }
    void unload(Json::Value& receipt) {
        require(pool.snapshot().consumers == 0, ErrorCode::conflict, "Gunyah consumers still own hugepages");
        if (!loaded()) return;
        if (has("acquire")) quiesce(receipt);
#ifdef __ANDROID__
        run_checked({"/system/bin/rmmod", "gh_hugepage_reserve"}, receipt);
#else
        run_checked({"/sbin/rmmod", "gh_hugepage_reserve"}, receipt);
#endif
        require(!loaded(), ErrorCode::commit_uncertain, "Module unload has no observable result");
    }
    void apply(const Json::Value& op, const vm::PoolReservations::ControlLease& lease, Json::Value& receipt);
    TaskCompletion execute(const Json::Value& request, TaskControl& task);
};
void HugepageService::Impl::apply(const Json::Value& op, const vm::PoolReservations::ControlLease& lease, Json::Value& receipt) {
    const auto kind = op["kind"].asString(); receipt["implementation"] = kind;
    auto values = settings();
    if (kind == "acquire") { acquire(op["mode"].asInt(), receipt); return; }
    if (kind == "stop-acquire") { stop(receipt, false); return; }
    if (kind == "boot") {
        require(io.exists(module("module.prop")), ErrorCode::unavailable, "Hugepage module is not installed");
        receipt["uncertain"] = true; io.marker(module("disable"), !op["enabled"].asBool()); receipt["saved"] = true;
        require(io.exists(module("disable")) != op["enabled"].asBool(), ErrorCode::commit_uncertain, "Boot marker readback differs");
        receipt["uncertain"] = false; return;
    }
    if (kind == "dismiss-crash") {
        if (!io.exists(module("crash"))) return;
        receipt["uncertain"] = true; io.marker(module("crash"), false);
        require(!io.exists(module("crash")), ErrorCode::commit_uncertain, "Crash acknowledgement readback differs");
        receipt["saved"] = true; receipt["uncertain"] = false; return;
    }
    if (kind == "unload") { unload(receipt); change_manual(lease, 0, receipt); return; }
    if (kind == "runtime") {
        if (!op["enabled"].asBool()) {
            require(pool.snapshot().consumers == 0, ErrorCode::conflict, "Gunyah consumers still own hugepages");
            if (loaded()) {
                if (has("pool_want")) { quiesce(receipt); write("pool_want", 0, receipt); }
                else unload(receipt);
            }
            change_manual(lease, 0, receipt); return;
        }
        auto saved = values.isMember("pool_want") ? number(values["pool_want"].asString()) : values.isMember("pool_target") ? number(values["pool_target"].asString()) : std::optional<int64_t>(1024);
        require(saved && *saved >= pool.snapshot().pages && *saved > 0 && *saved <= max_pages, ErrorCode::conflict, "Saved target cannot cover Gunyah consumers");
        if (!loaded()) load(*saved, receipt);
        else if (has("pool_want")) { quiesce(receipt); write("pool_want", *saved, receipt, true, true); }
        const auto effective = read("pool_want");
        if (effective) change_manual(lease, *effective, receipt);
        acquire(1, receipt); return;
    }
    if (kind == "targets") {
        int64_t base = op["poolPages"].asInt64();
        std::optional<int64_t> cma;
        if (!op["cmaPages"].isNull()) cma = op["cmaPages"].asInt64();
        require(base >= pool.snapshot().pages, ErrorCode::conflict, "Pool target is below Gunyah consumer demand");
        if (op["persist"].asBool() && !cma && values.isMember("pool_want_with_cma")) {
            const auto previous = number(values["pool_want_with_cma"].asString());
            require(previous && (*previous == 0 || *previous >= base), ErrorCode::conflict, "Preserved saved CMA target cannot cover the new pool target");
        }
        const bool live_target = loaded() && has("pool_want");
        if (live_target) {
            require(!cma || *cma == 0 || has("pool_want_with_cma"), ErrorCode::unavailable, "CMA targets are unsupported");
            if (!cma && has("pool_want_with_cma")) {
                const auto prior = read("pool_want_with_cma");
                require(prior && (*prior == 0 || *prior >= base), ErrorCode::conflict, "Preserved CMA target cannot cover the new pool target");
            }
            quiesce(receipt);
            write("pool_want", base, receipt, true, true); base = actual("pool_want");
            change_manual(lease, base, receipt);
            if (cma && has("pool_want_with_cma")) { *cma = *cma ? std::max(*cma, base) : 0; cma_target(*cma, receipt); cma = actual("pool_want_with_cma"); }
            if (!cma && has("pool_want_with_cma")) {
                const auto preserved = actual("pool_want_with_cma");
                require(preserved == 0 || preserved >= base, ErrorCode::commit_uncertain, "Rounded pool target exceeds preserved CMA target");
            }
        } else {
            require(op["persist"].asBool(), ErrorCode::unavailable, "Live pool resizing is unavailable");
            receipt["implementation"] = "next-load";
        }
        if (op["persist"].asBool()) { target_settings(values, base, cma); save(values, receipt); }
        if (live_target && op.get("acquireMode", 0).asInt() != 0) {
            const auto observed = stat();
            auto deficit = [&](int64_t target, std::initializer_list<const char*> counters) -> std::optional<bool> {
                for (const auto* key : counters) {
                    const auto& value = observed[key];
                    if (!value.isInt64() || value.asInt64() < 0) return {};
                    target -= std::min(target, value.asInt64());
                }
                return target > 0;
            };
            const auto pool_needed = deficit(base, {"pool_avail", "served"});
            const auto cma_base = cma ? cma : read("pool_want_with_cma");
            const auto cma_needed = cma_base && *cma_base > 0
                ? deficit(*cma_base, {"pool_avail", "served", "pool_cma"}) : std::optional<bool>(false);
            if (pool_needed.value_or(false) || cma_needed.value_or(false)) acquire(op["acquireMode"].asInt(), receipt);
            else if (!pool_needed || !cma_needed) receipt["degraded"] = true;
        }
        return;
    }
    if (kind == "cma-target") {
        int64_t pages = op["pages"].asInt64();
        if (op["persist"].asBool()) require_saved_cma(values, pages);
        if (loaded() && has("pool_want_with_cma")) { quiesce(receipt); cma_target(pages, receipt); pages = actual("pool_want_with_cma"); }
        else { require(op["persist"].asBool(), ErrorCode::unavailable, "Live CMA resizing is unavailable"); receipt["implementation"] = "next-load"; }
        if (op["persist"].asBool()) {
            values["pool_want_with_cma"] = std::to_string(pages);
            if (pages) values["pool_want_with_cma_last"] = std::to_string(pages);
            save(values, receipt);
        }
        return;
    }
    if (kind == "restrict" || kind == "gfp-hook") {
        const auto knob = kind == "restrict" ? "moveable_to_cma_restrict_cma_redirect_disabled" : "moveable_to_cma_gfp_cma_hook";
        require(has(knob), ErrorCode::unavailable, "Requested CMA lever is unsupported");
        quiesce(receipt);
        write(knob, op["enabled"].asBool() ? 1 : 0, receipt); return;
    }
    if (kind == "cma-lever") {
        const auto selected = lever(op["value"]);
        if (selected.empty()) values.removeMember("cma_movable_lever"); else values["cma_movable_lever"] = selected;
        save(values, receipt); return;
    }
    if (kind == "advanced") {
        const auto key = op["key"].asString();
        if (op["value"].isNull()) values.removeMember(key); else values[key] = std::to_string(op["value"].asInt64());
        save(values, receipt);
        // Boot knobs and system_reserve only take effect at next load.
        if (!op["value"].isNull() && advanced_live_writable(key)) {
            quiesce(receipt);
            write(key, op["value"].asInt64(), receipt);
        }
        else receipt["implementation"] = "next-load";
        return;
    }
    if (kind == "reconcile") { write("reconcile", 1, receipt, false); return; }
    if (kind == "migrate-settings") { if (values.isMember("cma_probe_result")) { values.removeMember("cma_probe_result"); save(values, receipt); } return; }
    if (kind == "cma" || kind == "cma-save") {
        const bool saving = kind == "cma-save";
        const bool enabled = saving ? op["pages"].asInt64() != 0 : op["enabled"].asBool();
        int64_t pages = enabled ? op["pages"].asInt64() : 0;
        const auto selected = lever(op["lever"]);
        require(has("pool_want_with_cma"), ErrorCode::unavailable, "CMA is unsupported");
        if (saving || op.get("persist", false).asBool()) require_saved_cma(values, pages);
        if (saving) {
            const auto current = read("pool_want_with_cma");
            require(current && *current == pages, ErrorCode::conflict, "CMA target changed before saving");
            if (!selected.empty() && pages) {
                const auto knob = selected == "flag" ? "moveable_to_cma_restrict_cma_redirect_disabled" : "moveable_to_cma_gfp_cma_hook";
                require(read(knob) == std::optional<int64_t>(1) || read("moveable_to_cma_vender_already_allowed") == std::optional<int64_t>(1), ErrorCode::conflict, "CMA lever changed before saving");
            }
        } else if (enabled) {
            const auto base = read("pool_want"); require(base && pages >= *base, ErrorCode::invalid_argument, "CMA target is below pool target");
            const bool needs_lever = !selected.empty() && read("moveable_to_cma_vender_already_allowed") != std::optional<int64_t>(1);
            const auto knob = selected == "flag" ? "moveable_to_cma_restrict_cma_redirect_disabled" : "moveable_to_cma_gfp_cma_hook";
            require(!needs_lever || has(knob), ErrorCode::unavailable, "Requested CMA lever is unsupported");
            require(has("acquire") || has("manual_refill"), ErrorCode::unavailable, "CMA acquire is unsupported");
            quiesce(receipt);
            if (needs_lever) write(knob, 1, receipt);
            cma_target(pages, receipt); pages = actual("pool_want_with_cma"); acquire(3, receipt);
        } else {
            quiesce(receipt);
            if (has("moveable_to_cma_gfp_cma_hook")) write("moveable_to_cma_gfp_cma_hook", 0, receipt);
            if (has("moveable_to_cma_restrict_cma_redirect_disabled")) write("moveable_to_cma_restrict_cma_redirect_disabled", 0, receipt);
            cma_target(0, receipt);
        }
        if (saving || op.get("persist", false).asBool()) {
            values["pool_want_with_cma"] = std::to_string(pages);
            if (pages) values["pool_want_with_cma_last"] = std::to_string(pages);
            if (selected.empty() || !enabled) values.removeMember("cma_movable_lever"); else values["cma_movable_lever"] = selected;
            values.removeMember("cma_probe_result"); save(values, receipt);
        }
    }
}
TaskCompletion HugepageService::Impl::execute(const Json::Value& request, TaskControl& task) {
    Json::Value receipt(Json::objectValue);
    for (const auto* flag : {"saved", "applied", "degraded", "uncertain"}) receipt[flag] = false;
    receipt["implementation"] = request["operation"]["kind"];
    auto lease = pool.begin_control();
    if (!lease) return TaskCompletion::failure(ErrorCode::conflict, "Hugepage control is busy", receipt);
    try {
        require(snapshot()["fingerprint"] == request["expected"]["fingerprint"], ErrorCode::conflict, "Hugepage controls changed; refresh before submitting a new operation");
        if (!task.enter_commit()) return TaskCompletion::cancelled(receipt);
        apply(request["operation"], *lease, receipt);
        lease.reset(); receipt["snapshot"] = snapshot();
        return TaskCompletion::success(receipt);
    } catch (const ServiceError& error) {
        if (error.code() == ErrorCode::commit_uncertain || receipt["saved"].asBool() || receipt["applied"].asBool()) receipt["uncertain"] = true;
        if (receipt["uncertain"].asBool() && lease) lease->suppress_release_adjustment();
        lease.reset(); try { receipt["snapshot"] = snapshot(); } catch (...) { receipt["snapshot"] = Json::Value(); }
        return TaskCompletion::failure(error.code(), error.what(), receipt);
    } catch (...) {
        receipt["uncertain"] = true; if (lease) lease->suppress_release_adjustment(); lease.reset();
        try { receipt["snapshot"] = snapshot(); } catch (...) { receipt["snapshot"] = Json::Value(); }
        return TaskCompletion::failure(ErrorCode::commit_uncertain, "Hugepage operation could not be confirmed; inspect current state", receipt);
    }
}
HugepageService::HugepageService(TaskService& tasks, vm::PoolReservations& pool, HugepageOptions options)
    : impl_(std::make_unique<Impl>(tasks, pool, std::move(options))) {}
HugepageService::~HugepageService() = default;
Json::Value HugepageService::snapshot(const CallContext& caller) { access(caller); return impl_->snapshot(); }
TaskView HugepageService::start(const CallContext& caller, const Json::Value& request) {
    access(caller); keys(request, {"requestId", "expected", "operation"});
    require(request["requestId"].isString() && !request["requestId"].asString().empty() && request["requestId"].asString().size() <= 128,
        ErrorCode::invalid_argument, "Invalid operation request ID");
    keys(request["expected"], {"fingerprint"});
    require(request["expected"]["fingerprint"].isString() && request["expected"]["fingerprint"].asString().size() <= 256 && !request["expected"]["fingerprint"].asString().empty(), ErrorCode::invalid_argument, "Missing control expectation");
    validate_operation(request["operation"]);
    auto canonical = request;
    auto& operation = canonical["operation"];
    for (const auto* key : {"poolPages", "cmaPages", "pages", "mode", "acquireMode"})
        if (operation.isMember(key) && !operation[key].isNull()) operation[key] = Json::Int64(integer(operation, key, 0, max_pages));
    if (operation["kind"] == "advanced" && !operation["value"].isNull()) operation["value"] = Json::Int64(integer(operation, "value", 0, max_pages));
    TaskSpec spec; spec.kind = "hugepage_operation"; spec.resource = "hugepages";
    spec.background = true;
    spec.request_id = canonical["requestId"].asString(); spec.request_signature = encode(canonical); spec.result_bytes = 256u << 10;
    auto ref = impl_->tasks.submit(caller, std::move(spec), [impl = impl_.get(), canonical](TaskControl& control) { return impl->execute(canonical, control); });
    return with_cancellation_receipt(impl_->tasks.get(caller, ref));
}
TaskView HugepageService::status(const CallContext& caller, const std::string& request_id) {
    access(caller); require(!request_id.empty() && request_id.size() <= 128, ErrorCode::invalid_argument, "Invalid operation request ID");
    auto task = impl_->tasks.find_request(caller, request_id);
    require(task && task->kind == "hugepage_operation" && task->resource == "hugepages", ErrorCode::task_not_found, "Hugepage operation is not retained");
    return with_cancellation_receipt(impl_->tasks.get(caller, task->ref));
}
}
