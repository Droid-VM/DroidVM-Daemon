// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "child.h"
#include <deque>
#include <future>
#include <mutex>
#include <thread>
#include <atomic>

namespace droidvm {
enum class ProcessStream { output, error };
struct ProcessLine {
    uint64_t sequence = 0, generation = 0;
    ProcessStream stream = ProcessStream::output;
    std::string text;
    bool truncated = false;
};
struct ProcessStatus {
    uint64_t generation = 0;
    pid_t pid = -1; // diagnostic only; control always uses the held Child/pidfd
    bool running = false, stopping = false, unexpected_exit = false;
    std::optional<int> exit_code;
    std::string error;
};
struct ProcessOutput {
    ProcessStatus status;
    std::deque<ProcessLine> lines;
    uint64_t dropped = 0;
    // A consumer of JSON event lines must refresh state after overflow or
    // malformed/oversized input, never treat a partial event as authoritative.
    bool resync_required = false;
};
// One bounded IO thread per helper, with at most 32 retained instances across
// the daemon (running or retaining a finished helper's history). No callbacks
// run on the IO thread. A service consumes its eventfd/mailbox on its own worker.
// Restart policy belongs to the network/VM service, not an unconditional loop.
class ManagedProcess {
public:
    static constexpr size_t max_instances = 32;
    static constexpr size_t line_limit = 64u << 10, log_line_limit = 4096;
    static constexpr size_t queue_bytes = 256u << 10, queue_lines = 256;
    static constexpr size_t log_bytes = 256u << 10, log_lines = 1000;
    ManagedProcess();
    ~ManagedProcess();
    ManagedProcess(const ManagedProcess&) = delete;
    ManagedProcess& operator=(const ManagedProcess&) = delete;
    void start(const ChildOptions& options);
    void stop(std::chrono::milliseconds grace = std::chrono::seconds(3));
    bool signal(int number);
    ProcessStatus status() const;
    std::deque<ProcessLine> log() const;
    int event_fd() const { return ready_.get(); }
    ProcessOutput take_output(); // one consumer; drains ready_ with the mailbox lock
private:
    struct Signal { int number; std::promise<bool> result; };
    struct Slot;
    Fd control_, ready_;
    std::unique_ptr<Slot> slot_;
    std::thread monitor_;
    std::mutex lifecycle_;
    mutable std::mutex mutex_;
    std::unique_ptr<Signal> signal_;
    ProcessStatus status_;
    std::deque<ProcessLine> output_, log_;
    size_t output_bytes_ = 0, log_bytes_ = 0;
    uint64_t sequence_ = 0, dropped_ = 0;
    bool resync_ = false;
    std::atomic<bool> stopping_{false};
    std::atomic<int64_t> grace_ms_{3000};
    void run(std::unique_ptr<Child> child) noexcept;
    void line(ProcessStream stream, std::string text, bool truncated);
    void stop_locked(std::chrono::milliseconds grace);
};
}
