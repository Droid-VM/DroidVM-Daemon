// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "common/fd.h"
#include "common/process.h"
#include <array>
#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace droidvm {
struct ChildOptions {
    std::vector<std::string> argv;
    std::optional<std::vector<std::string>> environment;
    std::string directory;
    std::vector<int> preserve_fds;
    std::vector<droidvm_process_limit> limits;
    std::array<int, 3> stdio{-1, -1, -1};
    bool new_process_group = true;
};
struct ChildOutput {
    int exit_code = -1; // same negative-signal convention as the existing JNI
    std::string output, error;
    bool truncated = false, timed_out = false, cancelled = false;
};
// Exclusive owner/reaper of one direct child and (optionally) its process group.
// Methods are serialized by the owning worker, never by an arbitrary SIGCHLD
// reaper. Exit observation holds the zombie until group cleanup, preventing PID
// reuse from changing a later signal target. Destruction kills and reaps.
class Child {
public:
    explicit Child(const ChildOptions& options);
    ~Child();
    Child(const Child&) = delete;
    Child& operator=(const Child&) = delete;
    pid_t pid() const { return pid_; }
    int pidfd() const { return process_.get(); }
    int stdin_fd() const { return input_.get(); }
    int stdout_fd() const { return output_.get(); }
    int stderr_fd() const { return error_.get(); }
    std::optional<int> poll_exit();
    bool signal(int number);
    int stop(std::chrono::milliseconds grace = std::chrono::seconds(3));
    ChildOutput communicate(std::string_view input = {}, std::chrono::milliseconds timeout = std::chrono::seconds(30),
        size_t capture_bytes = 256u << 10, std::function<bool()> cancelled = {});
private:
    pid_t pid_ = -1;
    Fd process_, input_, output_, error_;
    bool group_ = false, reaped_ = false;
    std::optional<int> exit_;
    void signal_owned(int number);
    void reap();
};
}
