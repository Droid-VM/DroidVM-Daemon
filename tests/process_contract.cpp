// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "runtime/child.h"
#include <atomic>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <signal.h>
#include <sys/wait.h>
#include <system_error>

using namespace droidvm;
using namespace droidvm::test;
using namespace std::chrono_literals;
namespace {
void write_all(int fd, std::string_view value) {
    while (!value.empty()) {
        auto count = write(fd, value.data(), value.size());
        if (count < 0 && errno == EINTR) continue;
        check(count > 0, "helper write failed");
        value.remove_prefix(static_cast<size_t>(count));
    }
}
std::vector<int> descriptors() {
    DIR* directory = opendir("/proc/self/fd");
    check(directory, "open FD list");
    std::vector<int> values;
    while (auto* entry = readdir(directory)) {
        char* end;
        long value = strtol(entry->d_name, &end, 10);
        if (!*end && value >= 0 && value != dirfd(directory)) values.push_back(static_cast<int>(value));
    }
    closedir(directory);
    return values;
}
ChildOptions helper(const std::string& mode) {
    ChildOptions options;
    options.argv = {"/proc/self/exe", "--child", mode};
    return options;
}
int child_main(int argc, char** argv) {
    const std::string mode = argv[2];
    if (mode == "exit") return argc > 3 ? atoi(argv[3]) : 17;
    if (mode == "inspect") {
        Json::Value value;
        auto& args = value["args"] = Json::Value(Json::arrayValue);
        for (int i = 3; i < argc; ++i) args.append(argv[i]);
        value["environment"] = getenv("DROIDVM_TEST_VALUE") ? getenv("DROIDVM_TEST_VALUE") : "missing";
        char directory[4096];
        check(getcwd(directory, sizeof(directory)), "getcwd");
        value["directory"] = directory;
        struct rlimit limit{};
        getrlimit(RLIMIT_NOFILE, &limit);
        value["nofile"] = Json::UInt64(limit.rlim_cur);
        sigset_t mask;
        sigprocmask(SIG_SETMASK, nullptr, &mask);
        value["term_blocked"] = sigismember(&mask, SIGTERM) != 0;
        auto& fds = value["fds"] = Json::Value(Json::arrayValue);
        for (int fd : descriptors()) if (fd > 2) fds.append(fd);
        write_all(1, wire::stringify(value));
        return 0;
    }
    if (mode == "echo") {
        char bytes[8192];
        ssize_t count;
        while ((count = read(0, bytes, sizeof(bytes))) > 0) {
            write_all(1, std::string_view(bytes, count));
            write_all(2, std::string_view(bytes, count));
        }
        return 0;
    }
    if (mode == "close_input") {
        close(0);
        write_all(1, "ready");
        std::this_thread::sleep_for(100ms);
        return 0;
    }
    if (mode == "closed_stdio") {
        close(0); close(1); close(2);
        return Child(helper("exit")).communicate().exit_code == 17 ? 0 : 1;
    }
    if (mode == "orphan") {
        pid_t child = fork();
        check(child >= 0, "fork descendant");
        if (!child) { for (;;) pause(); }
        write_all(1, std::to_string(child));
        return 42;
    }
    if (mode == "ignore_term") signal(SIGTERM, SIG_IGN);
    if (mode == "sleep" || mode == "ignore_term") {
        write_all(1, "ready");
        for (;;) pause();
    }
    return 99;
}
void ready(Child& child) {
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    std::string bytes;
    while (bytes != "ready" && std::chrono::steady_clock::now() < deadline) {
        char buffer[5];
        auto count = read(child.stdout_fd(), buffer, sizeof(buffer));
        if (count > 0) bytes.append(buffer, count);
        else std::this_thread::sleep_for(1ms);
    }
    check(bytes == "ready", "child readiness");
}
void arguments_limits_and_fds() {
    Fd file(open("/dev/null", O_RDONLY | O_CLOEXEC));
    Fd keep(fcntl(file.get(), F_DUPFD_CLOEXEC, 200));
    Fd unwanted(fcntl(file.get(), F_DUPFD, 210));
    check(keep.get() >= 200 && unwanted.get() >= 210, "FD fixtures");
    auto options = helper("inspect");
    options.argv.insert(options.argv.end(), {"a b", "$(not-a-shell)", "引用", "", "semi;colon"});
    options.environment = std::vector<std::string>{"DROIDVM_TEST_VALUE=literal $value ; quoted"};
    options.directory = "/data/local/tmp";
    options.preserve_fds = {keep.get()};
    options.limits = {{RLIMIT_NOFILE, 256, 256}};
    auto result = Child(options).communicate();
    check(result.exit_code == 0, "inspect exit");
    auto value = wire::parse(result.output);
    check(value["args"].size() == 5 && value["args"][1] == "$(not-a-shell)" && value["args"][2] == "引用" && value["args"][3] == "", "literal argv");
    check(value["environment"] == "literal $value ; quoted" && value["directory"] == "/data/local/tmp", "environment/cwd");
    check(value["nofile"] == 256 && value["fds"].size() == 1 && value["fds"][0] == keep.get(), "rlimit and explicit FD inheritance");
    check(fcntl(keep.get(), F_GETFD) & FD_CLOEXEC, "preserve must not change parent descriptor flags");
    check(Child(helper("closed_stdio")).communicate().exit_code == 0, "closed parent stdio does not collide with pipes");
}
void setup_failures_and_leaks() {
    const auto before = descriptors().size();
    for (int i = 0; i < 10; ++i) {
        for (int variant = 0; variant < 3; ++variant) {
            auto options = helper("exit");
            if (variant == 0) options.argv[0] = "/droidvm-nonexistent-executable";
            if (variant == 1) options.directory = "/droidvm-nonexistent-directory";
            if (variant == 2) options.limits = {{RLIMIT_NOFILE, 32, 16}};
            bool failed = false;
            try { Child child(options); } catch (const std::system_error& error) {
                failed = error.code().value() == (variant == 2 ? EINVAL : ENOENT);
            }
            check(failed, "setup failure stage is reported by spawn");
        }
        auto options = helper("exit"); options.argv.push_back("127");
        check(Child(options).communicate().exit_code == 127, "real exit 127 is not exec failure");
    }
    check(descriptors().size() == before, "spawn failure/exit must not leak FDs");
    siginfo_t info{};
    check(waitid(P_ALL, 0, &info, WEXITED | WNOHANG | WNOWAIT) < 0 && errno == ECHILD, "no unreaped children");
}
void signals_timeout_and_cancellation() {
    sigset_t block, previous;
    sigemptyset(&block); sigaddset(&block, SIGTERM);
    check(pthread_sigmask(SIG_BLOCK, &block, &previous) == 0, "block parent signal");
    auto value = wire::parse(Child(helper("inspect")).communicate().output);
    pthread_sigmask(SIG_SETMASK, &previous, nullptr);
    check(value["term_blocked"] == false, "child resets daemon signal mask");
    Child normal(helper("sleep")); ready(normal);
    check(normal.signal(SIGTERM), "pidfd signal");
    auto result = normal.communicate({}, 2s);
    check(result.exit_code == -SIGTERM && !result.timed_out && !normal.signal(SIGTERM), "signal exit cached and stale signal refused");
    Child stubborn(helper("ignore_term")); ready(stubborn);
    auto start = std::chrono::steady_clock::now();
    result = stubborn.communicate({}, 80ms);
    check(result.timed_out && result.exit_code == -SIGKILL && std::chrono::steady_clock::now() - start < 2s, "timeout escalates ignored TERM");
    Child cancelled(helper("sleep")); ready(cancelled);
    result = cancelled.communicate({}, 2s, 1024, [] { return true; });
    check(result.cancelled && !result.timed_out && result.exit_code == -SIGTERM, "explicit cancellation waits for cleanup");
}
void bounded_io_and_sigpipe() {
    std::string input(1u << 20, 'x');
    auto result = Child(helper("echo")).communicate(input, 5s, 8192);
    check(result.exit_code == 0 && !result.timed_out && result.truncated, "large concurrent stdout/stderr drains without deadlock");
    check(result.output.size() + result.error.size() == 8192, "combined retained output budget");
    result = Child(helper("close_input")).communicate(input, 2s);
    check(result.exit_code == 0 && result.output == "ready", "closed child stdin cannot SIGPIPE parent");
}
void owned_group_and_raii() {
    pid_t original;
    {
        Child child(helper("sleep")); ready(child); original = child.pid();
    }
    int status;
    check(waitpid(original, &status, WNOHANG) < 0 && errno == ECHILD, "destructor reaps direct child");
    auto result = Child(helper("orphan")).communicate({}, 3s);
    check(result.exit_code == 42 && !result.timed_out, "exited leader cannot leave inherited pipes hanging");
    const auto descendant = std::stoi(result.output);
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    bool stopped = false;
    do {
        std::ifstream stat("/proc/" + std::to_string(descendant) + "/stat");
        std::string record;
        std::getline(stat, record);
        const auto end = record.rfind(')');
        stopped = record.empty() || (end != std::string::npos && record.substr(end + 2, 1) == "Z");
        if (!stopped) std::this_thread::sleep_for(1ms);
    } while (!stopped && std::chrono::steady_clock::now() < deadline);
    check(stopped, "same-group descendant stopped before ownership released");
}
void threaded_spawns() {
    const auto before = descriptors().size();
    std::atomic<bool> passed{true};
    std::vector<std::thread> threads;
    for (int i = 0; i < 6; ++i) threads.emplace_back([&] {
        try {
            for (int j = 0; j < 10; ++j)
                if (Child(helper("exit")).communicate({}, 3s).exit_code != 17) passed = false;
        } catch (...) { passed = false; }
    });
    for (auto& thread : threads) thread.join();
    check(passed && descriptors().size() == before, "parallel spawn, IO and cleanup isolation");
}
}
int main(int argc, char** argv) {
    if (argc >= 3 && std::string(argv[1]) == "--child") return child_main(argc, argv);
    return run({{"argv_environment_cwd_rlimit_fd_isolation", arguments_limits_and_fds},
        {"exec_failures_exit127_no_leaks", setup_failures_and_leaks},
        {"signals_deadlines_cancellation", signals_timeout_and_cancellation},
        {"bounded_concurrent_io_sigpipe", bounded_io_and_sigpipe},
        {"owned_group_orphan_raii", owned_group_and_raii},
        {"six_threads_sixty_spawns", threaded_spawns}});
}
