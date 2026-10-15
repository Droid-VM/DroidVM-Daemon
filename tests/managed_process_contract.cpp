// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "runtime/managed_process.h"
#include <dirent.h>
#include <fstream>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>

using namespace droidvm;
using namespace droidvm::test;
namespace {
volatile sig_atomic_t terminate_requested = 0;
void on_term(int) { terminate_requested = 1; }
void on_hup(int) { const char line[] = "reload\n"; static_cast<void>(write(1, line, sizeof(line) - 1)); }
void write_all(int fd, std::string_view text) {
    while (!text.empty()) {
        const auto count = write(fd, text.data(), text.size());
        if (count < 0 && errno == EINTR) continue;
        check(count > 0, "helper output write");
        text.remove_prefix(static_cast<size_t>(count));
    }
}
ChildOptions helper(const char* mode) { ChildOptions options; options.argv = {"/proc/self/exe", "--helper", mode}; return options; }
size_t descriptors() {
    DIR* dir = opendir("/proc/self/fd"); check(dir, "open FD count");
    size_t size = 0;
    while (const auto* entry = readdir(dir)) if (entry->d_name[0] != '.') ++size;
    closedir(dir); return size;
}
template<class Predicate> ProcessStatus await(ManagedProcess& process, Predicate predicate, std::chrono::milliseconds limit = 5s) {
    const auto deadline = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return process.status();
        pollfd fd{process.event_fd(), POLLIN, 0};
        poll(&fd, 1, 10);
        // Tests that wait on status intentionally leave the bounded mailbox
        // untouched to exercise overflow. Sleep also prevents readiness spin.
        std::this_thread::sleep_for(1ms);
    }
    throw std::runtime_error("managed process observation deadline");
}
bool logged(ManagedProcess& process, std::string_view text) {
    for (const auto& line : process.log()) if (line.text == text) return true;
    return false;
}
void line_boundaries_and_exit() {
    ManagedProcess process;
    process.start(helper("lines"));
    const auto state = await(process, [&] { return !process.status().running; });
    check(state.unexpected_exit && state.exit_code == 7 && state.error.empty(), "real early exit and successful output drain");
    auto batch = process.take_output();
    check(!batch.resync_required && batch.dropped == 0, "small output delivered completely");
    std::vector<std::string> output, error;
    uint64_t sequence = 0;
    for (const auto& line : batch.lines) {
        check(line.sequence > sequence && line.generation == state.generation && !line.truncated, "ordered generation-scoped lines");
        sequence = line.sequence;
        (line.stream == ProcessStream::output ? output : error).push_back(line.text);
    }
    check(output == std::vector<std::string>{"first", "second", "", "网络🌏", "tail"}, "CR/LF, fragmented UTF8 and unterminated tail");
    check(error == std::vector<std::string>{"diagnostic", "error-tail"}, "stderr separate from protocol stdout");
    check(!process.signal(SIGHUP), "stale process signal refused");
    pollfd fd{process.event_fd(), POLLIN, 0};
    check(poll(&fd, 1, 0) == 0, "mailbox drain clears readiness");
}
void output_budget_and_invalid_utf8() {
    ManagedProcess process;
    process.start(helper("flood"));
    await(process, [&] { return !process.status().running; }, 10s);
    auto batch = process.take_output();
    check(batch.status.exit_code == 0 && batch.resync_required && batch.dropped > 0, "overflow explicitly requires consumer resync");
    size_t bytes = 0;
    bool truncated = false, replaced = false;
    for (const auto& line : batch.lines) {
        bytes += line.text.size();
        check(line.text.size() <= ManagedProcess::line_limit, "event line bound");
        truncated |= line.truncated;
        replaced |= line.text == "invalid:\xef\xbf\xbd";
    }
    check(bytes <= ManagedProcess::queue_bytes && batch.lines.size() <= ManagedProcess::queue_lines && truncated && replaced, "bounded complete/oversized/malformed event lines");
    auto log = process.log(); bytes = 0;
    for (const auto& line : log) { bytes += line.text.size(); check(line.text.size() <= ManagedProcess::log_line_limit, "log line bound"); }
    check(bytes <= ManagedProcess::log_bytes && log.size() <= ManagedProcess::log_lines, "merged log byte and line bounds");
    check(!process.take_output().resync_required, "overflow acknowledged on mailbox drain");
}
void signals_stop_and_restart() {
    ManagedProcess process;
    process.start(helper("graceful"));
    await(process, [&] { return logged(process, "ready"); });
    check(process.signal(SIGHUP), "held pidfd receives reload");
    await(process, [&] { return logged(process, "reload"); });
    const auto old_generation = process.status().generation;
    process.stop(2s);
    check(process.status().exit_code == 0 && !process.status().unexpected_exit && logged(process, "shutdown-done"), "large final output drains during graceful stop");
    process.start(helper("stubborn"));
    await(process, [&] {
        for (const auto& line : process.log()) if (line.generation > old_generation && line.text == "ready") return true;
        return false;
    });
    auto batch = process.take_output();
    for (const auto& line : batch.lines) check(line.generation == process.status().generation, "restart drops prior unread mailbox lines");
    const auto start = std::chrono::steady_clock::now();
    process.stop(80ms);
    check(process.status().exit_code == -SIGKILL && !process.status().unexpected_exit &&
        std::chrono::steady_clock::now() - start < 1s, "ignored TERM escalates with bounded grace");
}
void orphan_group_and_repeated_lifecycle() {
    const auto before = descriptors();
    {
        ManagedProcess process;
        process.start(helper("orphan"));
        await(process, [&] { return !process.status().running; });
        check(process.status().exit_code == 42 && process.status().error.empty(), "leader exit cleans inherited group pipe holders");
        pid_t descendant = -1;
        for (const auto& line : process.log()) if (line.stream == ProcessStream::output) descendant = std::stoi(line.text);
        check(descendant > 0, "descendant reported");
        std::ifstream stat("/proc/" + std::to_string(descendant) + "/stat");
        std::string text; std::getline(stat, text);
        check(text.empty() || text.substr(text.rfind(')') + 2, 1) == "Z", "owned descendant no longer running");
        for (int i = 0; i < 20; ++i) {
            process.start(helper("lines"));
            await(process, [&] { return !process.status().running; });
            process.stop(0ms);
        }
    }
    check(descriptors() == before, "repeated spawn/stop/destruction leaves no FDs");
    siginfo_t status{};
    check(waitid(P_ALL, 0, &status, WEXITED | WNOHANG | WNOWAIT) < 0 && errno == ECHILD, "no unreaped direct children");
}
void capacity_and_spawn_failure() {
    const auto before = descriptors();
    {
        std::vector<std::unique_ptr<ManagedProcess>> processes;
        for (size_t i = 0; i < ManagedProcess::max_instances; ++i) processes.push_back(std::make_unique<ManagedProcess>());
        error(ErrorCode::resource_exhausted, [] { ManagedProcess excess; });
        ChildOptions missing; missing.argv = {"/does/not/exist"};
        try { processes.front()->start(missing); throw std::runtime_error("expected exec failure"); }
        catch (const std::system_error&) {}
        check(!processes.front()->status().running && !processes.front()->status().error.empty(), "spawn error visible without fake running state");
        auto bad = helper("lines"); bad.new_process_group = false;
        error(ErrorCode::invalid_argument, [&] { processes.front()->start(bad); });
        processes.pop_back();
        ManagedProcess recovered;
        recovered.start(helper("lines"));
        await(recovered, [&] { return !recovered.status().running; });
    }
    check(descriptors() == before, "capacity and exec failures release all FDs");
}
int child(const std::string& mode) {
    if (mode == "lines") {
        write_all(1, "first\r"); write_all(1, "second\r\n\n\xe7\xbd");
        write_all(1, "\x91\xe7\xbb\x9c\xf0\x9f\x8c\x8f\ntail");
        write_all(2, "diagnostic\nerror-tail"); return 7;
    }
    if (mode == "flood") {
        std::string line(1024, 'x'); line += '\n';
        for (int i = 0; i < 10000; ++i) write_all(i % 2 ? 1 : 2, line);
        write_all(1, std::string(256u << 10, 'y') + "\ninvalid:\xff\n"); return 0;
    }
    if (mode == "orphan") {
        auto pid = fork(); check(pid >= 0, "fork group descendant");
        if (!pid) { for (;;) pause(); }
        write_all(1, std::to_string(pid) + "\n"); return 42;
    }
    if (mode == "graceful" || mode == "stubborn") {
        signal(SIGTERM, mode == "stubborn" ? SIG_IGN : on_term);
        signal(SIGHUP, on_hup);
        write_all(1, "ready\n");
        while (!terminate_requested) usleep(1000);
        for (int i = 0; i < 1024; ++i) write_all(1, std::string(1024, 'z') + "\n");
        write_all(1, "shutdown-done\n"); return 0;
    }
    return 99;
}
}
int main(int argc, char** argv) {
    if (argc == 3 && std::string_view(argv[1]) == "--helper") return child(argv[2]);
    return run({{"separate_streams_crlf_utf8_and_eof", line_boundaries_and_exit}, {"bounded_mailbox_logs_and_resync", output_budget_and_invalid_utf8},
        {"reload_graceful_stop_escalation_restart", signals_stop_and_restart}, {"orphan_cleanup_and_twenty_restarts", orphan_group_and_repeated_lifecycle},
        {"global_capacity_and_exec_failure", capacity_and_spawn_failure}});
}
