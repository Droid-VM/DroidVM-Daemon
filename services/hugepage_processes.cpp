// SPDX-License-Identifier: GPL-3.0-or-later
#include "hugepage_processes.h"
#include <algorithm>
#include <charconv>
#include <chrono>
#include <climits>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string_view>
#ifdef _WIN32
#include <process.h>
#else
#include "common/fd.h"
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace droidvm {
namespace {
constexpr uint64_t page_bytes = 2u * 1024u * 1024u;
constexpr size_t ko_limit = 65536, stat_limit = 4096, smaps_limit = 16384, stack_limit = 16384;
void require(bool good, ErrorCode code, const char* message) { if (!good) throw ServiceError(code, message); }
void access(const CallContext& caller, bool task = false) {
    require(caller.authenticated, ErrorCode::unauthenticated, "Authentication required");
    require(caller.administrator && !caller.principal.empty() && (!task || caller.manage_tasks), ErrorCode::permission_denied, "Hugepage process permission required");
}
std::optional<uint64_t> integer(std::string_view text) {
    uint64_t result = 0;
    if (text.empty() || text.size() > 20 || text.find_first_not_of("0123456789") != std::string_view::npos) return {};
    auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) return {};
    return result;
}
bool decimal(const std::string& value) { auto parsed = integer(value); return parsed && std::to_string(*parsed) == value; }
std::string clean(const std::string& text, size_t limit, bool multiline = false) {
    std::string out;
    for (size_t i = 0; i < text.size() && out.size() < limit;) {
        auto first = static_cast<unsigned char>(text[i]);
        if (first < 0x80) {
            out += (first >= 0x20 && first != 0x7f) || (multiline && (first == '\n' || first == '\r' || first == '\t')) ? text[i] : '?';
            ++i; continue;
        }
        size_t count = first >= 0xc2 && first <= 0xdf ? 2 : first >= 0xe0 && first <= 0xef ? 3 : first >= 0xf0 && first <= 0xf4 ? 4 : 0;
        bool valid = count && i + count <= text.size();
        for (size_t j = 1; valid && j < count; ++j) valid = (static_cast<unsigned char>(text[i + j]) & 0xc0) == 0x80;
        if (valid && count >= 3) {
            auto second = static_cast<unsigned char>(text[i + 1]);
            valid = !(first == 0xe0 && second < 0xa0) && !(first == 0xed && second >= 0xa0) &&
                !(first == 0xf0 && second < 0x90) && !(first == 0xf4 && second >= 0x90);
        }
        if (!valid) { out += '?'; ++i; continue; }
        if (out.size() + count > limit) break;
        out.append(text, i, count); i += count;
    }
    return out;
}
HugepageProcessRead read_file(const std::string& path, size_t limit) {
#ifdef _WIN32
    std::ifstream input(path, std::ios::binary);
    if (!input) return {HugepageProcessReadState::failed, {}, false};
    std::string bytes(limit + 1, '\0'); input.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    bytes.resize(static_cast<size_t>(input.gcount()));
    bool truncated = bytes.size() > limit; if (truncated) bytes.resize(limit);
    return {input.bad() ? HugepageProcessReadState::failed : HugepageProcessReadState::present, std::move(bytes), truncated};
#else
    Fd file(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (file.get() < 0) return {errno == ENOENT || errno == ESRCH ? HugepageProcessReadState::missing :
        errno == EACCES || errno == EPERM ? HugepageProcessReadState::denied : HugepageProcessReadState::failed, {}, false};
    std::string bytes;
    char buffer[4096];
    while (bytes.size() <= limit) {
        auto count = ::read(file.get(), buffer, std::min(sizeof(buffer), limit + 1 - bytes.size()));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return {errno == EACCES || errno == EPERM ? HugepageProcessReadState::denied : HugepageProcessReadState::failed, {}, false};
        if (!count) break;
        bytes.append(buffer, static_cast<size_t>(count));
    }
    bool truncated = bytes.size() > limit; if (truncated) bytes.resize(limit);
    return {HugepageProcessReadState::present, std::move(bytes), truncated};
#endif
}
struct ProcessStat { std::string start, state; };
std::optional<ProcessStat> parse_stat(const HugepageProcessRead& input, int pid) {
    if (input.state != HugepageProcessReadState::present || input.truncated) return {};
    auto first = input.text.find('('), last = input.text.rfind(')');
    if (first == std::string::npos || last == std::string::npos || last <= first) return {};
    std::istringstream prefix(input.text.substr(0, first)); int observed_pid = -1; prefix >> observed_pid;
    if (observed_pid != pid) return {};
    std::istringstream fields(input.text.substr(last + 1)); std::string value, state;
    for (unsigned field = 3; field <= 22; ++field) {
        if (!(fields >> value)) return {};
        if (field == 3) state = value;
    }
    if (!integer(value) || state.size() != 1 || std::string("RSDZTtXxKWPI").find(state[0]) == std::string::npos) return {};
    return ProcessStat{std::to_string(*integer(value)), state};
}
std::optional<uint64_t> thp_bytes(const HugepageProcessRead& input) {
    if (input.state != HugepageProcessReadState::present || input.truncated) return {};
    std::istringstream lines(input.text); std::string line;
    std::optional<uint64_t> anon, shmem;
    while (std::getline(lines, line)) {
        std::istringstream parts(line); std::string key, value, unit, extra;
        if (!(parts >> key) || (key != "AnonHugePages:" && key != "ShmemPmdMapped:")) continue;
        if (!(parts >> value >> unit) || unit != "kB" || (parts >> extra)) return {};
        auto n = integer(value); if (!n) return {};
        auto& destination = key == "AnonHugePages:" ? anon : shmem;
        if (destination) return {};
        destination = *n;
    }
    if (!anon || !shmem || *anon > UINT64_MAX - *shmem || *anon + *shmem > UINT64_MAX / 1024u) return {};
    return (*anon + *shmem) * 1024u;
}
#ifndef _WIN32
class PidHandle final : public HugepageProcessHandle {
    Fd fd_;
public:
    explicit PidHandle(int fd) : fd_(fd) {}
    bool alive() override {
        pollfd value{fd_.get(), POLLIN, 0}; int status;
        do { status = ::poll(&value, 1, 0); } while (status < 0 && errno == EINTR);
        require(status >= 0 && !(value.revents & (POLLNVAL | POLLERR)), ErrorCode::unavailable, "Process identity cannot be observed");
        return !(value.revents & (POLLIN | POLLHUP));
    }
    bool signal(int number) override {
        if (::syscall(SYS_pidfd_send_signal, fd_.get(), number, nullptr, 0) == 0) return true;
        if (errno == ESRCH) return false;
        throw ServiceError(ErrorCode::commit_uncertain, "Process signal could not be confirmed");
    }
};
#endif
std::unique_ptr<HugepageProcessHandle> open_process(int pid) {
#ifdef _WIN32
    (void)pid; throw ServiceError(ErrorCode::unavailable, "Process identity handles unavailable");
#else
    int fd = static_cast<int>(::syscall(SYS_pidfd_open, pid, 0));
    if (fd < 0 && errno == ESRCH) return {};
    require(fd >= 0, ErrorCode::unavailable, "Process identity handles unavailable");
    return std::make_unique<PidHandle>(fd);
#endif
}
void keys(const Json::Value& value, std::initializer_list<const char*> allowed) {
    require(value.isObject(), ErrorCode::invalid_argument, "Expected object");
    for (const auto& key : value.getMemberNames()) require(std::any_of(allowed.begin(), allowed.end(), [&](const char* item) { return key == item; }), ErrorCode::invalid_argument, "Unexpected process field");
}
void validate_expected(const Json::Value& expected) {
    keys(expected, {"pid", "startTicks", "source", "membership"});
    require(expected.size() == 4 && expected["pid"].isInt() && expected["pid"].asInt() > 1 && expected["startTicks"].isString() && decimal(expected["startTicks"].asString()) && expected["startTicks"] != "0" &&
        (expected["source"] == "ko" || expected["source"] == "scan") && expected["membership"].isString(), ErrorCode::invalid_argument, "Invalid process identity");
    const auto token = expected["membership"].asString();
    require(!token.empty() && token.size() <= 256 && token.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-") == std::string::npos, ErrorCode::invalid_argument, "Invalid process membership");
}
Json::Value receipt(const Json::Value& request) {
    Json::Value value; value["signal"] = request["signal"]; value["expected"] = request["expected"];
    value["sent"] = false; value["uncertain"] = false; value["exited"] = false; return value;
}
TaskView cancelled_receipt(TaskView task) {
    if (task.state == TaskState::cancelled && !task.result.isObject()) {
        task.result["sent"] = false; task.result["uncertain"] = false; task.result["exited"] = false;
        task.result["signal"] = Json::Value(); task.result["expected"] = Json::Value();
    }
    return task;
}
}
std::optional<std::string> hugepage_process_start_ticks(int pid) {
    if (pid <= 1) return {};
    const auto value = parse_stat(read_file("/proc/" + std::to_string(pid) + "/stat", stat_limit), pid);
    return value && value->start != "0" ? std::optional<std::string>(value->start) : std::nullopt;
}
struct HugepageProcessService::Impl {
    TaskService& tasks;
    HugepageProcessOptions io;
    struct Owner { std::string name; std::optional<uint64_t> pages; bool member = false; };
    struct VmSet { std::map<int, HugepageVmProcess> entries; bool available = true, partial = false; };
    struct KoSet { std::map<int, Owner> entries; bool available = false, partial = false; };
    Impl(TaskService& tasks, HugepageProcessOptions options) : tasks(tasks), io(std::move(options)) {
        require(io.max_entries > 0 && io.max_entries <= 512, ErrorCode::invalid_argument, "Invalid process observation limit");
        if (!io.read) io.read = read_file;
        if (!io.open_process) io.open_process = open_process;
        if (!io.wall_ms) io.wall_ms = [] { return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()); };
        if (!io.daemon_pid) {
#ifdef _WIN32
            io.daemon_pid = _getpid();
#else
            io.daemon_pid = getpid();
#endif
        }
    }
    std::string proc(int pid, const char* name) const { return io.proc_directory + "/" + std::to_string(pid) + "/" + name; }
    HugepageProcessRead read(const std::string& path, size_t limit) const {
        try {
            auto value = io.read(path, limit);
            if (value.text.size() > limit) { value.text.resize(limit); value.truncated = true; }
            return value;
        } catch (...) { return {HugepageProcessReadState::failed, {}, false}; }
    }
    VmSet vms() const {
        VmSet result;
        if (!io.running_vms) { result.available = false; return result; }
        try {
            auto rows = io.running_vms();
            for (const auto& row : rows) {
                if (row.pid <= 1 || row.pid == io.daemon_pid) continue;
                if (result.entries.size() >= io.max_entries) { result.partial = true; break; }
                if (row.id.empty() || row.id.size() > 128 || row.runtime_instance.empty() || row.runtime_instance.size() > 128) { result.partial = true; continue; }
                if (result.entries.contains(row.pid)) { result.entries[row.pid].start_ticks.clear(); result.partial = true; continue; }
                result.entries.emplace(row.pid, row);
            }
        } catch (...) { result.available = false; result.partial = true; result.entries.clear(); }
        return result;
    }
    KoSet ko() const {
        KoSet result;
        auto owners = read(io.parameters + "/vm_owners", ko_limit), summary = read(io.parameters + "/served_summary", ko_limit);
        if (owners.state != HugepageProcessReadState::present || summary.state != HugepageProcessReadState::present) return result;
        result.available = true; result.partial = owners.truncated || summary.truncated;
        auto lines = [](HugepageProcessRead value) {
            if (value.truncated) { auto end = value.text.rfind('\n'); value.text = end == std::string::npos ? std::string() : value.text.substr(0, end + 1); }
            return std::istringstream(value.text);
        };
        auto input = lines(owners); std::string line;
        while (std::getline(input, line)) {
            if (line.find("pid=") == std::string::npos) continue;
            auto comm = line.find("comm=");
            std::istringstream fields(line.substr(0, comm)); std::string field; std::optional<uint64_t> pid;
            bool duplicate = false;
            while (fields >> field) if (field.starts_with("pid=")) { if (pid) duplicate = true; pid = integer(field.substr(4)); }
            if (duplicate || !pid || *pid == 0 || *pid > INT_MAX) { result.partial = true; continue; }
            if (result.entries.size() >= io.max_entries && !result.entries.contains(static_cast<int>(*pid))) { result.partial = true; continue; }
            auto& entry = result.entries[static_cast<int>(*pid)];
            if (entry.member) { result.partial = true; continue; }
            entry.member = true;
            entry.name = comm == std::string::npos ? "PID " + std::to_string(*pid) : clean(line.substr(comm + 5), 256);
        }
        auto totals = lines(summary); std::set<int> seen;
        while (std::getline(totals, line)) {
            if (!line.starts_with("owner ")) continue;
            std::istringstream fields(line); std::string field; std::optional<uint64_t> pid, pages;
            bool duplicate = false;
            while (fields >> field) {
                if (field.starts_with("pid=")) { if (pid) duplicate = true; pid = integer(field.substr(4)); }
                if (field.starts_with("pages=")) { if (pages) duplicate = true; pages = integer(field.substr(6)); }
            }
            if (!pid || *pid == 0 || *pid > INT_MAX) { result.partial = true; continue; }
            if (result.entries.size() >= io.max_entries && !result.entries.contains(static_cast<int>(*pid))) { result.partial = true; continue; }
            auto& entry = result.entries[static_cast<int>(*pid)];
            if (entry.name.empty()) entry.name = "PID " + std::to_string(*pid);
            if (!seen.insert(static_cast<int>(*pid)).second) duplicate = true;
            if (duplicate || !pages || *pages > UINT64_MAX / page_bytes) { result.partial = true; entry.pages.reset(); continue; }
            entry.pages = *pages;
            if (!entry.member) result.partial = true;
        }
        for (const auto& [pid, entry] : result.entries) { (void)pid; if (!entry.pages) result.partial = true; }
        return result;
    }
    std::optional<std::string> owner_birth(int pid) const {
        if (!io.owner_start_ticks) return {};
        try { auto value = io.owner_start_ticks(pid); return value && decimal(*value) && *value != "0" ? value : std::nullopt; } catch (...) { return {}; }
    }
    Json::Value expected(int pid, const std::string& birth, const std::string& source, const HugepageVmProcess* vm) const {
        std::string identity = tasks.epoch() + ":" + source + ":" + std::to_string(pid) + ":" + birth;
        if (vm) identity += ":" + vm->id + ":" + vm->runtime_instance + ":" + std::to_string(vm->runtime_revision);
        uint64_t hash = 14695981039346656037ULL;
        for (unsigned char byte : identity) { hash ^= byte; hash *= 1099511628211ULL; }
        std::ostringstream token; token << tasks.epoch() << ':' << std::hex << hash;
        Json::Value out; out["pid"] = pid; out["startTicks"] = birth; out["source"] = source; out["membership"] = token.str(); return out;
    }
    Json::Value row(int pid, const std::string& source, const Owner* owner, const HugepageVmProcess* vm) const {
        Json::Value out;
        out["pid"] = pid; out["source"] = source;
        out["name"] = owner ? owner->name : vm ? clean(vm->name, 256) : "PID " + std::to_string(pid);
        out["pages"] = Json::Value(); out["bytes"] = Json::Value(); out["state"] = Json::Value(); out["alive"] = Json::Value();
        out["startTicks"] = Json::Value(); out["expected"] = Json::Value(); out["vm"] = Json::Value();
        out["canSignal"] = false; out["canStack"] = false; out["reason"] = Json::Value();
        out["identityStatus"] = "unverified"; out["attributionVerified"] = false;
        if (vm) {
            auto& association = out["vm"];
            association["id"] = vm->id; association["name"] = clean(vm->name, 256);
            association["runtimeInstance"] = vm->runtime_instance; association["runtimeRevision"] = std::to_string(vm->runtime_revision);
        }
        if (owner && owner->pages) { out["pages"] = std::to_string(*owner->pages); out["bytes"] = std::to_string(*owner->pages * page_bytes); }
        if (pid <= 1 || pid == io.daemon_pid) { out["reason"] = "protected-process"; return out; }
        auto birth = vm && decimal(vm->start_ticks) && vm->start_ticks != "0" ? std::optional<std::string>(vm->start_ticks) : owner && owner->member && !vm ? owner_birth(pid) : std::nullopt;
        auto observed = read(proc(pid, "stat"), stat_limit);
        auto info = parse_stat(observed, pid);
        if (!info) {
            const bool gone = observed.state == HugepageProcessReadState::missing;
            out["identityStatus"] = gone ? "exited" : "unreadable";
            out["alive"] = gone ? Json::Value(false) : Json::Value(); out["reason"] = gone ? "process-exited" : "process-unreadable"; return out;
        }
        if (!birth) { out["reason"] = "identity-unverified"; return out; }
        if (info->start != *birth) { out["identityStatus"] = "changed"; out["reason"] = "process-changed"; return out; }
        std::unique_ptr<HugepageProcessHandle> handle;
        try { handle = io.open_process(pid); }
        catch (...) { out["reason"] = "pidfd-unavailable"; return out; }
        try {
            if (!handle || !handle->alive()) { out["alive"] = false; out["identityStatus"] = "exited"; out["reason"] = "process-exited"; return out; }
            // Identity is checked again AFTER opening the identity handle.
            info = parse_stat(read(proc(pid, "stat"), stat_limit), pid);
            if (!info || info->start != *birth) { out["identityStatus"] = "changed"; out["reason"] = "process-changed"; return out; }
            std::optional<uint64_t> bytes;
            if (source == "scan") bytes = thp_bytes(read(proc(pid, "smaps_rollup"), smaps_limit));
            auto after = parse_stat(read(proc(pid, "stat"), stat_limit), pid);
            if (!handle->alive()) { out["alive"] = false; out["identityStatus"] = "exited"; out["reason"] = "process-exited"; return out; }
            if (!after || after->start != *birth) { out["identityStatus"] = "changed"; out["reason"] = "process-changed"; return out; }
            out["identityStatus"] = "verified"; out["startTicks"] = *birth; out["alive"] = true; out["state"] = after->state;
            if (source == "scan") {
                out["attributionVerified"] = bytes.has_value();
                if (bytes) { out["bytes"] = std::to_string(*bytes); if (*bytes % page_bytes == 0) out["pages"] = std::to_string(*bytes / page_bytes); }
                else out["reason"] = "process-unreadable";
            } else {
                const auto original = owner && owner->member ? owner_birth(pid) : std::nullopt;
                out["attributionVerified"] = original && *original == *birth;
                if (!out["attributionVerified"].asBool()) out["reason"] = "ko-owner-unverified";
            }
            // A legacy KO PID is not proof of its historical owner's birth.
            // Current VM controls use the independent, trusted VM membership.
            if (vm || out["attributionVerified"].asBool()) {
                out["expected"] = expected(pid, *birth, vm ? "scan" : "ko", vm);
                out["canSignal"] = !vm || static_cast<bool>(io.signal_vm);
                out["canStack"] = after->state == "D";
            }
            return out;
        } catch (...) { out["identityStatus"] = "unreadable"; out["reason"] = "process-unreadable"; return out; }
    }
    Json::Value snapshot(const std::string& requested) const {
        require(requested == "auto" || requested == "ko" || requested == "scan", ErrorCode::invalid_argument, "Invalid hugepage process source");
        auto running = vms(); KoSet owners; if (requested != "scan") owners = ko();
        const auto source = requested == "scan" || (requested == "auto" && !owners.available) ? std::string("scan") : std::string("ko");
        Json::Value out;
        out["capability"] = HugepageProcessService::capability; out["requestedSource"] = requested; out["source"] = source;
        out["observedAtMs"] = std::to_string(io.wall_ms()); out["pageBytes"] = std::to_string(page_bytes);
        out["coverage"] = source == "ko" ? "module-owners" : "running-vms";
        out["available"] = source == "ko" ? owners.available : running.available;
        out["partial"] = source == "ko" ? owners.partial || !running.available || running.partial : running.partial;
        out["fallbackReason"] = requested == "auto" && source == "scan" ? Json::Value("ko-unavailable") : Json::Value();
        out["entries"] = Json::Value(Json::arrayValue); out["issues"] = Json::Value(Json::arrayValue);
        if (source == "ko" && !owners.available) out["issues"].append("ko-unavailable");
        if (owners.partial) out["issues"].append("ko-partial");
        if (!running.available) out["issues"].append("vm-provider-unavailable");
        if (running.partial) out["issues"].append("limit-reached");
        if (source == "ko") {
            for (const auto& [pid, owner] : owners.entries) {
                auto vm = running.entries.find(pid);
                out["entries"].append(row(pid, source, &owner, vm == running.entries.end() ? nullptr : &vm->second));
            }
        } else if (running.available) {
            for (const auto& [pid, vm] : running.entries) out["entries"].append(row(pid, source, nullptr, &vm));
        }
        uint64_t pages = 0, bytes = 0; bool all_pages = out["available"].asBool() && !out["partial"].asBool(), all_bytes = all_pages;
        for (const auto& entry : out["entries"]) {
            auto p = entry["pages"].isString() ? integer(entry["pages"].asString()) : std::nullopt;
            auto b = entry["bytes"].isString() ? integer(entry["bytes"].asString()) : std::nullopt;
            if (!p || *p > UINT64_MAX - pages) { all_pages = false; out["partial"] = true; } else pages += *p;
            if (!b || *b > UINT64_MAX - bytes) { all_bytes = false; out["partial"] = true; } else bytes += *b;
            if (!b || entry["identityStatus"] != "verified" || !entry["attributionVerified"].asBool()) out["partial"] = true;
        }
        auto& totals = out["totals"];
        totals["pages"] = all_pages ? Json::Value(std::to_string(pages)) : Json::Value();
        totals["bytes"] = all_bytes ? Json::Value(std::to_string(bytes)) : Json::Value();
        totals["knownPages"] = std::to_string(pages); totals["knownBytes"] = std::to_string(bytes);
        return out;
    }
    struct Verified { std::unique_ptr<HugepageProcessHandle> handle; Json::Value row; };
    Verified verify(const Json::Value& expected) const {
        validate_expected(expected);
        const auto pid = expected["pid"].asInt();
        require(pid != io.daemon_pid, ErrorCode::permission_denied, "Protected process cannot be controlled");
        auto handle = io.open_process(pid);
        require(handle && handle->alive(), ErrorCode::not_found, "Process has exited");
        auto born = parse_stat(read(proc(pid, "stat"), stat_limit), pid);
        require(born && born->start == expected["startTicks"].asString(), ErrorCode::conflict, "Process birth changed or cannot be verified");
        auto observed = snapshot(expected["source"].asString());
        require(observed["available"].asBool(), ErrorCode::unavailable, "Process membership source is unavailable");
        Json::Value found;
        for (const auto& row : observed["entries"]) if (row["pid"] == expected["pid"] && row["expected"] == expected) { found = row; break; }
        require(found.isObject(), ErrorCode::conflict, "Process is no longer a member of the observed hugepage source");
        born = parse_stat(read(proc(pid, "stat"), stat_limit), pid);
        require(handle->alive() && born && born->start == expected["startTicks"].asString(), ErrorCode::conflict, "Process identity changed during membership verification");
        return {std::move(handle), std::move(found)};
    }
    TaskCompletion signal(const Json::Value& request, TaskControl& control);
};
TaskCompletion HugepageProcessService::Impl::signal(const Json::Value& request, TaskControl& control) {
    auto result = receipt(request);
    try {
        auto target = verify(request["expected"]);
        require(target.row["canSignal"].asBool(), ErrorCode::unavailable, "Process signal is unavailable for this owner");
        if (!control.enter_commit()) return TaskCompletion::cancelled(result);
        if (!target.handle->alive()) { result["exited"] = true; return TaskCompletion::success(result); }
        const int number = request["signal"] == "term" ? 15 : 9;
        result["uncertain"] = true;
        bool sent;
        if (target.row["vm"].isObject()) {
            const auto& association = target.row["vm"];
            HugepageVmProcess vm;
            vm.id = association["id"].asString(); vm.name = association["name"].asString(); vm.pid = request["expected"]["pid"].asInt();
            vm.start_ticks = request["expected"]["startTicks"].asString(); vm.runtime_instance = association["runtimeInstance"].asString();
            vm.runtime_revision = *integer(association["runtimeRevision"].asString());
            sent = io.signal_vm(vm, number);
        } else sent = target.handle->signal(number);
        result["sent"] = sent; result["uncertain"] = false;
        result["exited"] = !target.handle->alive();
        if (!sent && !result["exited"].asBool()) return TaskCompletion::failure(ErrorCode::conflict, "Owned VM process changed before signal delivery", result);
        return TaskCompletion::success(result);
    } catch (const ServiceError& error) {
        // Runtime expectation rejection happens before Child::signal. Preserve
        // its definite no-effect outcome instead of inventing uncertainty.
        if (error.code() == ErrorCode::conflict || error.code() == ErrorCode::not_found || error.code() == ErrorCode::permission_denied || error.code() == ErrorCode::unavailable)
            if (!result["sent"].asBool()) result["uncertain"] = false;
        return TaskCompletion::failure(error.code(), error.what(), result);
    } catch (...) {
        return TaskCompletion::failure(result["uncertain"].asBool() ? ErrorCode::commit_uncertain : ErrorCode::unavailable, "Process signal could not be confirmed", result);
    }
}
HugepageProcessService::HugepageProcessService(TaskService& tasks, HugepageProcessOptions options)
    : impl_(std::make_unique<Impl>(tasks, std::move(options))) {}
HugepageProcessService::~HugepageProcessService() = default;
Json::Value HugepageProcessService::snapshot(const CallContext& caller, const std::string& source) { access(caller); return impl_->snapshot(source); }
Json::Value HugepageProcessService::stack(const CallContext& caller, const Json::Value& expected) {
    access(caller);
    auto target = impl_->verify(expected);
    require(target.row["state"] == "D" && target.row["canStack"].asBool(), ErrorCode::conflict, "Kernel stack is available only for the observed blocked process");
    const auto pid = expected["pid"].asInt();
    const auto read = impl_->read(impl_->proc(pid, "stack"), stack_limit);
    const auto after = parse_stat(impl_->read(impl_->proc(pid, "stat"), stat_limit), pid);
    require(target.handle->alive() && after && after->start == expected["startTicks"].asString() && after->state == "D", ErrorCode::conflict, "Process changed while reading kernel stack");
    Json::Value out; out["expected"] = expected;
    out["available"] = read.state == HugepageProcessReadState::present;
    out["text"] = out["available"].asBool() ? Json::Value(clean(read.text, stack_limit, true)) : Json::Value();
    out["truncated"] = read.truncated; out["reason"] = out["available"].asBool() ? Json::Value() : Json::Value("stack-unreadable");
    return out;
}
TaskView HugepageProcessService::start(const CallContext& caller, const Json::Value& request) {
    access(caller, true); keys(request, {"requestId", "expected", "signal"});
    require(request.size() == 3 && request["requestId"].isString(), ErrorCode::invalid_argument, "Invalid process signal request");
    const auto id = request["requestId"].asString();
    require(!id.empty() && id.size() <= 128 && id.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-") == std::string::npos, ErrorCode::invalid_argument, "Invalid process request ID");
    validate_expected(request["expected"]);
    require(request["signal"] == "term" || request["signal"] == "kill", ErrorCode::invalid_argument, "Unsupported process signal");
    Json::StreamWriterBuilder writer; writer["indentation"] = "";
    TaskSpec spec; spec.kind = "hugepage_process_signal"; spec.resource = "hugepage-processes";
    spec.request_id = id; spec.request_signature = Json::writeString(writer, request); spec.result_bytes = 16384; spec.background = true;
    const auto ref = impl_->tasks.submit(caller, std::move(spec), [impl = impl_.get(), request](TaskControl& control) { return impl->signal(request, control); });
    return cancelled_receipt(impl_->tasks.get(caller, ref));
}
TaskView HugepageProcessService::status(const CallContext& caller, const std::string& request_id) {
    access(caller, true);
    require(!request_id.empty() && request_id.size() <= 128, ErrorCode::invalid_argument, "Invalid process request ID");
    const auto found = impl_->tasks.find_request(caller, request_id);
    require(found && found->kind == "hugepage_process_signal" && found->resource == "hugepage-processes", ErrorCode::task_not_found, "Process operation is not retained");
    return cancelled_receipt(impl_->tasks.get(caller, found->ref));
}
}
