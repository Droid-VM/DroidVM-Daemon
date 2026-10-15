// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "common/identity.h"
#include "runtime/log.h"
#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <algorithm>

using namespace droidvm;
using namespace droidvm::test;
namespace {
struct Temporary {
    std::string path = "/data/local/tmp/droidvm-log-" + random_id(false);
    Fd directory;
    Temporary() {
        check(mkdir(path.c_str(), 0700) == 0, "create test directory");
        directory = Fd(open(path.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC));
        check(directory.get() >= 0, "open test directory");
    }
    ~Temporary() {
        unlinkat(directory.get(), "daemon.log", 0);
        rmdir(path.c_str());
    }
};
std::string contents(int fd) {
    struct stat info{};
    check(fstat(fd, &info) == 0, "stat reader");
    check(info.st_size >= 0 && static_cast<uint64_t>(info.st_size) <= RuntimeLog::max_bytes, "bounded log");
    std::string result(static_cast<size_t>(info.st_size), '\0');
    check(pread(fd, result.data(), result.size(), 0) == static_cast<ssize_t>(result.size()), "read log");
    return result;
}
void bounds_and_reader() {
    Temporary temp;
    RuntimeLog log(temp.directory.get(), getuid());
    Fd reader(openat(temp.directory.get(), "daemon.log", O_RDONLY | O_CLOEXEC));
    struct stat original{};
    check(fstat(reader.get(), &original) == 0, "open reader");
    std::string message(RuntimeLog::max_message * 3, 'x');
    log.write("INFO", message);
    check(contents(reader.get()).find("[truncated]") != std::string::npos, "oversized message truncated");
    for (int i = 0; i < 300; ++i) log.write("INFO", message);
    log.write("INFO", "tail\nrecord\rinjection");
    const auto text = contents(reader.get());
    check(text.find("older records discarded") != std::string::npos, "bound resets old records");
    check(text.find("tail record injection\n") != std::string::npos, "line injection removed");
    struct stat current{};
    check(fstatat(temp.directory.get(), "daemon.log", &current, 0) == 0 && original.st_ino == current.st_ino,
          "open viewer keeps current inode");
    check((current.st_mode & 0777) == 0600, "private log");
}
void parallel_and_restart() {
    Temporary temp;
    {
        RuntimeLog log(temp.directory.get(), getuid());
        std::vector<std::thread> writers;
        for (int worker = 0; worker < 4; ++worker) writers.emplace_back([&, worker] {
            for (int i = 0; i < 100; ++i)
                log.write("INFO", "worker=" + std::to_string(worker) + " record=" + std::to_string(i));
        });
        for (auto& thread : writers) thread.join();
    }
    RuntimeLog restarted(temp.directory.get(), getuid());
    restarted.write("INFO", "restart");
    Fd reader(openat(temp.directory.get(), "daemon.log", O_RDONLY | O_CLOEXEC));
    const auto text = contents(reader.get());
    check(std::count(text.begin(), text.end(), '\n') == 401, "concurrent lines and restart retained");
    for (int worker = 0; worker < 4; ++worker)
        for (int i = 0; i < 100; ++i)
            check(text.find("worker=" + std::to_string(worker) + " record=" + std::to_string(i) + '\n') != std::string::npos,
                  "complete concurrent record");
}
void write_failure() {
    Temporary temp;
    RuntimeLog log(temp.directory.get(), getuid());
    struct rlimit original{};
    check(getrlimit(RLIMIT_FSIZE, &original) == 0, "get file limit");
    auto old_signal = signal(SIGXFSZ, SIG_IGN);
    auto limited = original;
    limited.rlim_cur = 0;
    check(setrlimit(RLIMIT_FSIZE, &limited) == 0, "inject write failure");
    log.write("ERROR", "cannot write");
    check(setrlimit(RLIMIT_FSIZE, &original) == 0, "restore file limit");
    signal(SIGXFSZ, old_signal);
    log.write("INFO", "sink remains disabled");
    Fd reader(openat(temp.directory.get(), "daemon.log", O_RDONLY | O_CLOEXEC));
    check(contents(reader.get()).empty(), "failed sink disabled without terminating process");
}
}
int main() {
    return run({{"bounded_records_same_reader_inode", bounds_and_reader},
                {"concurrent_lines_and_restart", parallel_and_restart},
                {"write_failure_disables_sink", write_failure}});
}
