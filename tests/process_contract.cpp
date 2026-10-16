// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "runtime/child.h"
#include "runtime/helper_identity.h"
#include "common/identity.h"
#include <atomic>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <signal.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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
void ready(Child& child);
int child_main(int argc, char** argv) {
    const std::string mode = argv[2];
    if (mode == "marker") {
        { Fd marker(open(argv[3], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
          check(marker.get() >= 0, "create execution evidence"); }
        signal(SIGTERM, SIG_IGN);
        write_all(1, "ready");
        for (;;) pause();
    }
    if (mode == "journal_owner") {
        const std::string path = argv[3], phase = argv[4];
        Fd dir(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        auto options = helper("marker"); options.argv.push_back(path + "/executed");
        HelperIdentity identity(dir.get(), getuid()); identity.arm(options);
        auto persist = options.before_exec;
        options.before_exec = [&](pid_t pid) {
            { Fd evidence(open((path + "/child.pid").c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
              check(evidence.get() >= 0, "record fixture child"); write_all(evidence.get(), std::to_string(pid)); }
            if (phase == "before_save") kill(getpid(), SIGKILL);
            persist(pid);
            if (phase == "after_save") kill(getpid(), SIGKILL);
        };
        Child child(options); ready(child);
        kill(getpid(), SIGKILL);
        return 99;
    }
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
struct IdentityCase {
    std::string path = "/data/local/tmp/droidvm-identity-" + random_id(false);
    Fd dir;
    IdentityCase() {
        check(mkdir(path.c_str(), 0700) == 0, "create identity fixture");
        dir = Fd(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    }
    ~IdentityCase() {
        try { HelperIdentity::recover(dir.get(), getuid(), 10ms); } catch (...) { return; }
        for (const char* name : {"helper.identity", "helper.json", "helper.json.bak", "child.pid", "executed", "original.identity"})
            unlinkat(dir.get(), name, 0);
        rmdir(path.c_str());
    }
};
void gated_spawn_failure() {
    IdentityCase test;
    const auto before = descriptors().size();
    for (int mode = 0; mode < 2; ++mode) {
        auto options = helper("marker"); options.argv.push_back(test.path + "/executed");
        options.before_exec = [&](pid_t pid) {
            check(access((test.path + "/executed").c_str(), F_OK) < 0 && errno == ENOENT, "exec waits for parent transaction");
            if (mode == 0) throw std::runtime_error("injected persistence failure");
            check(kill(pid, SIGKILL) == 0, "kill still-owned gated child");
            // Hold its zombie so the shared spawn code remains the sole reaper.
            siginfo_t exited{};
            check(waitid(P_PID, pid, &exited, WEXITED | WNOWAIT) == 0, "observe gated child death");
        };
        bool failed = false;
        try { Child child(options); }
        catch (const std::runtime_error& error) {
            failed = mode == 1 || std::string(error.what()) == "injected persistence failure";
        }
        check(failed && access((test.path + "/executed").c_str(), F_OK) < 0, "failed gate never executes and preserves original exception");
    }
    check(descriptors().size() == before, "gated failure closes all pipes and sockets");
    siginfo_t info{};
    check(waitid(P_ALL, 0, &info, WEXITED | WNOHANG | WNOWAIT) < 0 && errno == ECHILD, "gated failures reaped");
}
void persistent_helper_crashes() {
    for (const char* phase : {"before_save", "after_save", "after_exec"}) {
        IdentityCase test;
        auto options = helper("journal_owner"); options.argv.insert(options.argv.end(), {test.path, phase});
        const auto result = Child(options).communicate({}, 5s);
        if (result.exit_code != -SIGKILL) {
            std::cerr << "owner phase=" << phase << " exit=" << result.exit_code << " stderr=" << result.error << std::endl;
            throw std::runtime_error("owner killed at launch boundary");
        }
        std::ifstream evidence(test.path + "/child.pid"); pid_t pid = -1; evidence >> pid;
        check(pid > 1, "fixture child identity recorded");
        Fd process(static_cast<int>(syscall(SYS_pidfd_open, pid, 0)));
        if (std::string_view(phase) == "after_exec") {
            pollfd fd{process.get(), POLLIN, 0};
            check(process.get() >= 0 && poll(&fd, 1, 0) == 0 && access((test.path + "/executed").c_str(), F_OK) == 0,
                "helper is alive after owner death");
        }
        HelperIdentity::recover(test.dir.get(), getuid(), 20ms);
        if (process.get() >= 0) {
            pollfd fd{process.get(), POLLIN, 0};
            check(poll(&fd, 1, 2000) > 0 && (fd.revents & POLLIN), "gate EOF or identity recovery stops orphan");
        }
        if (std::string_view(phase) != "after_exec")
            check(access((test.path + "/executed").c_str(), F_OK) < 0, "owner death before release prevents exec");
        HelperIdentity::recover(test.dir.get(), getuid(), 20ms); // idempotent after death/reap
    }
}
void persistent_identity_mismatch() {
    IdentityCase test;
    auto options = helper("sleep");
    HelperIdentity identity(test.dir.get(), getuid()); identity.arm(options);
    Child child(options); ready(child);
    config::JsonFile journal(test.dir.get(), "helper.json", getuid());
    const auto original = journal.load()->value;
    auto changed = original; changed["birth"] = Json::UInt64(original["birth"].asUInt64() + 1);
    journal.save(changed);
    HelperIdentity::recover(test.dir.get(), getuid(), 10ms);
    check(!child.poll_exit(), "stale birth record cannot signal live process");
    changed = original; changed["boot"] = "previous-boot"; journal.save(changed);
    HelperIdentity::recover(test.dir.get(), getuid(), 10ms);
    check(!child.poll_exit(), "previous boot record cannot signal live process");
    journal.save(original);
    check(renameat(test.dir.get(), "helper.identity", test.dir.get(), "original.identity") == 0, "retain real marker fixture");
    { Fd replacement(openat(test.dir.get(), "helper.identity", O_CREAT | O_EXCL | O_RDONLY | O_CLOEXEC, 0400));
      check(replacement.get() >= 0, "create same-name replacement marker"); }
    bool refused = false;
    try { HelperIdentity::recover(test.dir.get(), getuid(), 10ms); } catch (const std::runtime_error&) { refused = true; }
    check(refused && !child.poll_exit(), "same-name marker replacement never authorizes signal");
    check(unlinkat(test.dir.get(), "helper.identity", 0) == 0 &&
        renameat(test.dir.get(), "original.identity", test.dir.get(), "helper.identity") == 0, "restore marker fixture");
    // Point at a separate live process with its actual birth but no marker FD.
    Child unrelated(helper("sleep")); ready(unrelated);
    auto unrelated_options = helper("sleep"); // use its gated birth record from a second isolated identity
    IdentityCase other_case;
    HelperIdentity other_identity(other_case.dir.get(), getuid()); other_identity.arm(unrelated_options);
    Child other_child(unrelated_options); ready(other_child);
    const auto other_record = config::JsonFile(other_case.dir.get(), "helper.json", getuid()).load()->value;
    changed = original; changed["pid"] = other_record["pid"]; changed["birth"] = other_record["birth"];
    journal.save(changed); refused = false;
    try { HelperIdentity::recover(test.dir.get(), getuid(), 10ms); } catch (const std::runtime_error&) { refused = true; }
    check(refused && !other_child.poll_exit() && !unrelated.poll_exit(), "journal PID text cannot target unrelated live processes");
    journal.save(original);
    HelperIdentity::recover(test.dir.get(), getuid(), 10ms);
    check(child.communicate({}, 1s).exit_code == -SIGTERM, "restored marker permits exact process recovery");
}
}
int main(int argc, char** argv) {
    if (argc >= 3 && std::string(argv[1]) == "--child") return child_main(argc, argv);
    return run({{"argv_environment_cwd_rlimit_fd_isolation", arguments_limits_and_fds},
        {"exec_failures_exit127_no_leaks", setup_failures_and_leaks},
        {"signals_deadlines_cancellation", signals_timeout_and_cancellation},
        {"bounded_concurrent_io_sigpipe", bounded_io_and_sigpipe},
        {"owned_group_orphan_raii", owned_group_and_raii},
        {"six_threads_sixty_spawns", threaded_spawns},
        {"gated_failures_never_exec", gated_spawn_failure},
        {"persistent_helper_owner_sigkill", persistent_helper_crashes},
        {"persistent_identity_mismatch", persistent_identity_mismatch}});
}
