// SPDX-License-Identifier: GPL-3.0-or-later
#include "child.h"
#include "common/pipe_write.h"
#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdexcept>
#include <system_error>
#include <sys/syscall.h>
#include <sys/wait.h>

namespace droidvm {
namespace {
void fail(const char* operation) { throw std::system_error(errno, std::generic_category(), operation); }
void nonblocking(int fd) {
    if (fd >= 0) {
        int flags = fcntl(fd, F_GETFL);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) fail("nonblocking child pipe");
    }
}
std::vector<char*> strings(const std::vector<std::string>& values) {
    std::vector<char*> result;
    for (const auto& value : values) {
        if (value.find('\0') != std::string::npos) throw std::invalid_argument("embedded NUL in process argument");
        result.push_back(const_cast<char*>(value.c_str()));
    }
    result.push_back(nullptr);
    return result;
}
}
Child::Child(const ChildOptions& options) : group_(options.new_process_group) {
    if (options.argv.empty() || options.argv.size() > 4096 || options.directory.find('\0') != std::string::npos)
        throw std::invalid_argument("invalid child options");
    struct sigaction reaper{};
    if (sigaction(SIGCHLD, nullptr, &reaper)) fail("query SIGCHLD");
    if (reaper.sa_handler != SIG_DFL || (reaper.sa_flags & SA_NOCLDWAIT))
        throw std::runtime_error("Child requires exclusive child reaping");
    auto argv = strings(options.argv);
    auto environment = options.environment ? strings(*options.environment) : std::vector<char*>{};
    droidvm_process_options spawn{argv.data(), options.environment ? environment.data() : nullptr,
        options.directory.empty() ? nullptr : options.directory.c_str(), options.preserve_fds.data(), options.preserve_fds.size(),
        options.limits.data(), options.limits.size(), {options.stdio[0], options.stdio[1], options.stdio[2]}, group_};
    droidvm_process_result result{};
    struct Gate { const ChildOptions& options; std::exception_ptr error; } gate{options, {}};
    auto before_exec = [](pid_t pid, void* context) -> int {
        auto& gate = *static_cast<Gate*>(context);
        try { gate.options.before_exec(pid); return 0; }
        catch (...) { gate.error = std::current_exception(); errno = EIO; return -1; }
    };
    if (droidvm_process_spawn_gated(&spawn, &result, options.before_exec ? +before_exec : nullptr, &gate)) {
        if (gate.error) std::rethrow_exception(gate.error);
        fail("spawn child");
    }
    pid_ = result.pid;
    input_ = Fd(result.pipes[0]); output_ = Fd(result.pipes[1]); error_ = Fd(result.pipes[2]);
    try {
        process_ = Fd(static_cast<int>(syscall(SYS_pidfd_open, pid_, 0)));
        if (process_.get() < 0) fail("open child pidfd");
        if (result.exec_stage != DROIDVM_EXEC_OK)
            throw std::system_error(result.exec_errno, std::generic_category(), "child setup/exec stage " + std::to_string(result.exec_stage));
        nonblocking(input_.get()); nonblocking(output_.get()); nonblocking(error_.get());
    } catch (...) {
        // The just-forked child has not been reaped, so its PID/group cannot be reused.
        if (group_) kill(-pid_, SIGKILL);
        kill(pid_, SIGKILL);
        while (waitpid(pid_, nullptr, 0) < 0 && errno == EINTR) {}
        throw;
    }
}
Child::~Child() {
    if (!reaped_ && pid_ > 0) {
        signal_owned(SIGKILL);
        try { reap(); } catch (...) {}
    }
}
std::optional<int> Child::poll_exit() {
    if (exit_) return exit_;
    siginfo_t info{};
    if (waitid(P_PID, static_cast<id_t>(pid_), &info, WEXITED | WNOHANG | WNOWAIT) < 0) {
        if (errno == EINTR) return {};
        fail("observe child exit");
    }
    if (info.si_pid == pid_) exit_ = info.si_code == CLD_EXITED ? info.si_status : -info.si_status;
    return exit_;
}
bool Child::signal(int number) {
    if (reaped_ || poll_exit()) return false;
    if (syscall(SYS_pidfd_send_signal, process_.get(), number, nullptr, 0) == 0) return true;
    if (errno == ESRCH) return false;
    fail("signal child pidfd");
    return false;
}
void Child::close_stdin() { input_ = Fd(); }
void Child::request_stop() { signal_owned(SIGTERM); }
void Child::signal_owned(int number) {
    if (reaped_) return;
    if (group_) kill(-pid_, number); // leader remains unreaped until group cleanup
    if (process_.get() >= 0) syscall(SYS_pidfd_send_signal, process_.get(), number, nullptr, 0);
}
void Child::reap() {
    if (reaped_) return;
    int code;
    if (droidvm_process_wait(pid_, 1, &code) != 1) fail("reap owned child");
    exit_ = code;
    reaped_ = true;
    process_ = Fd();
}
int Child::stop(std::chrono::milliseconds grace) {
    if (reaped_) return *exit_;
    signal_owned(SIGTERM);
    if (!poll_exit() && grace.count() > 0) {
        pollfd descriptor{process_.get(), POLLIN, 0};
        auto deadline = std::chrono::steady_clock::now() + grace;
        while (!poll_exit() && std::chrono::steady_clock::now() < deadline) {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
            poll(&descriptor, 1, static_cast<int>(std::clamp<int64_t>(remaining, 0, 100)));
        }
    }
    signal_owned(SIGKILL); // also clean same-group descendants of an exited leader
    reap();
    input_ = Fd();
    return *exit_;
}
ChildOutput Child::communicate(std::string_view input, std::chrono::milliseconds timeout, size_t capture_bytes,
                               std::function<bool()> cancelled, std::function<void(std::string_view)> on_output) {
    if (timeout.count() < 0 || capture_bytes > (16u << 20) || (input_.get() < 0 && !input.empty()))
        throw std::invalid_argument("invalid child IO budget");
    ChildOutput result;
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    size_t written = 0;
    auto drain = [&](Fd& fd, std::string& destination) {
        char bytes[8192];
        size_t budget = 64u << 10;
        while (fd.get() >= 0 && budget) {
            const auto count = read(fd.get(), bytes, std::min(sizeof(bytes), budget));
            if (count < 0 && errno == EINTR) continue;
            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (count < 0) fail("read child pipe");
            if (count == 0) { fd = Fd(); break; }
            if (on_output && &fd == &output_) on_output(std::string_view(bytes, static_cast<size_t>(count)));
            const size_t keep = std::min<size_t>(count, capture_bytes - result.output.size() - result.error.size());
            destination.append(bytes, keep);
            result.truncated |= keep < static_cast<size_t>(count);
            budget -= static_cast<size_t>(count);
        }
    };
    while (true) {
        if (input_.get() >= 0 && written == input.size()) input_ = Fd();
        drain(output_, result.output); drain(error_, result.error);
        if (poll_exit()) {
            stop(std::chrono::milliseconds(0));
            if (output_.get() < 0 && error_.get() < 0) break;
        }
        result.cancelled = cancelled && cancelled();
        result.timed_out = !result.cancelled && std::chrono::steady_clock::now() >= deadline;
        if (result.cancelled || result.timed_out) {
            stop(std::chrono::milliseconds(100));
            drain(output_, result.output); drain(error_, result.error);
            output_ = Fd(); error_ = Fd();
            break;
        }
        pollfd fds[] = {{input_.get(), POLLOUT, 0}, {output_.get(), POLLIN, 0}, {error_.get(), POLLIN, 0}, {process_.get(), POLLIN, 0}};
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (poll(fds, 4, static_cast<int>(std::clamp<int64_t>(remaining, 0, 25))) < 0 && errno != EINTR) fail("poll child IO");
        if (input_.get() >= 0 && fds[0].revents) {
            const auto count = pipe_write(input_.get(), input.data() + written, std::min<size_t>(input.size() - written, 8192));
            if (count > 0) written += static_cast<size_t>(count);
            else if (count < 0 && errno == EPIPE) input_ = Fd();
            else if (count < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) fail("write child pipe");
        }
    }
    result.exit_code = *exit_;
    return result;
}
}
