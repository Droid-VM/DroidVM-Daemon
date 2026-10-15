// SPDX-License-Identifier: GPL-3.0-or-later
#include "managed_process.h"
#include "services/context.h"
#include <algorithm>
#include <cerrno>
#include <poll.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <system_error>

namespace droidvm {
namespace {
std::atomic<size_t> instances{0};
void notify(int fd) {
    const uint64_t one = 1;
    while (write(fd, &one, sizeof(one)) < 0 && errno == EINTR) {}
}
void drain_event(int fd) {
    uint64_t value;
    while (read(fd, &value, sizeof(value)) < 0 && errno == EINTR) {}
}
// Like Java's UTF-8 InputStreamReader, replace invalid sequences. Keep complete
// codepoints at the byte cap so logs remain safe to encode in JSON responses.
std::string text_utf8(std::string_view input, size_t limit, bool& changed) {
    std::string output;
    for (size_t i = 0; i < input.size();) {
        const auto first = static_cast<unsigned char>(input[i]);
        size_t count = first < 0x80 ? 1 : first >= 0xc2 && first <= 0xdf ? 2 : first >= 0xe0 && first <= 0xef ? 3 : first >= 0xf0 && first <= 0xf4 ? 4 : 0;
        bool valid = count && count <= input.size() - i;
        for (size_t j = 1; valid && j < count; ++j) {
            auto byte = static_cast<unsigned char>(input[i + j]);
            valid = byte >= 0x80 && byte <= 0xbf;
        }
        if (valid && count >= 3) {
            const auto second = static_cast<unsigned char>(input[i + 1]);
            valid = !(first == 0xe0 && second < 0xa0) && !(first == 0xed && second > 0x9f) &&
                    !(first == 0xf0 && second < 0x90) && !(first == 0xf4 && second > 0x8f);
        }
        const auto piece = valid ? input.substr(i, count) : std::string_view("\xef\xbf\xbd");
        changed |= !valid;
        if (piece.size() > limit - output.size()) { changed = true; break; }
        output.append(piece); i += valid ? count : 1;
    }
    return output;
}
}
struct ManagedProcess::Slot {
    Slot() {
        const auto previous = instances.fetch_add(1);
        if (previous >= max_instances) { --instances; throw ServiceError(ErrorCode::resource_exhausted, "Managed process capacity exhausted"); }
    }
    ~Slot() { --instances; }
};
ManagedProcess::ManagedProcess()
    : control_(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)), ready_(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)) {
    if (control_.get() < 0 || ready_.get() < 0) throw std::system_error(errno, std::generic_category(), "create process events");
    slot_ = std::make_unique<Slot>();
}
ManagedProcess::~ManagedProcess() { try { stop(); } catch (...) {} }
void ManagedProcess::start(const ChildOptions& options) {
    std::lock_guard lifecycle(lifecycle_);
    stop_locked(std::chrono::seconds(3));
    if (!options.new_process_group || options.stdio != std::array<int, 3>{-1, -1, -1})
        throw ServiceError(ErrorCode::invalid_argument, "Managed processes require owned group and captured stdio");
    std::unique_ptr<Child> child;
    try { child = std::make_unique<Child>(options); }
    catch (const std::exception& error) {
        std::lock_guard lock(mutex_);
        status_.error = std::string(error.what()).substr(0, 4096); notify(ready_.get());
        throw;
    }
    child->close_stdin();
    {
        std::lock_guard lock(mutex_);
        ++status_.generation;
        status_.pid = child->pid(); status_.running = true; status_.stopping = false;
        status_.unexpected_exit = false; status_.exit_code.reset(); status_.error.clear();
        output_.clear(); output_bytes_ = 0; dropped_ = 0; resync_ = false;
        stopping_ = false; drain_event(control_.get()); drain_event(ready_.get());
    }
    try { monitor_ = std::thread([this, child = std::move(child)]() mutable { run(std::move(child)); }); }
    catch (...) {
        std::lock_guard lock(mutex_);
        status_.running = false; status_.error = "Failed to start process monitor"; notify(ready_.get());
        throw;
    }
    notify(ready_.get());
}
void ManagedProcess::stop_locked(std::chrono::milliseconds grace) {
    if (!monitor_.joinable()) return;
    grace_ms_ = grace.count(); stopping_ = true; notify(control_.get());
    monitor_.join();
}
void ManagedProcess::stop(std::chrono::milliseconds grace) {
    if (grace.count() < 0 || grace > std::chrono::seconds(10)) throw ServiceError(ErrorCode::invalid_argument, "Invalid process stop grace");
    std::lock_guard lifecycle(lifecycle_);
    stop_locked(grace);
}
bool ManagedProcess::signal(int number) {
    if (number <= 0 || number >= NSIG) throw ServiceError(ErrorCode::invalid_argument, "Invalid process signal");
    std::lock_guard lifecycle(lifecycle_);
    std::future<bool> result;
    {
        std::lock_guard lock(mutex_);
        if (!status_.running || stopping_) return false;
        signal_ = std::make_unique<Signal>(); signal_->number = number;
        result = signal_->result.get_future(); notify(control_.get());
    }
    return result.get();
}
ProcessStatus ManagedProcess::status() const { std::lock_guard lock(mutex_); return status_; }
std::deque<ProcessLine> ManagedProcess::log() const { std::lock_guard lock(mutex_); return log_; }
ProcessOutput ManagedProcess::take_output() {
    std::lock_guard lock(mutex_);
    ProcessOutput result{status_, std::move(output_), dropped_, resync_};
    output_.clear(); output_bytes_ = 0; dropped_ = 0; resync_ = false;
    drain_event(ready_.get());
    return result;
}
void ManagedProcess::line(ProcessStream stream, std::string text, bool truncated) {
    text = text_utf8(text, line_limit, truncated);
    std::lock_guard lock(mutex_);
    ProcessLine line{++sequence_, status_.generation, stream, std::move(text), truncated};
    resync_ |= truncated;
    while (!output_.empty() && (output_.size() >= queue_lines || output_bytes_ + line.text.size() > queue_bytes)) {
        output_bytes_ -= output_.front().text.size(); output_.pop_front(); ++dropped_; resync_ = true;
    }
    output_bytes_ += line.text.size(); output_.push_back(line);
    line.text = text_utf8(line.text, log_line_limit, line.truncated);
    while (!log_.empty() && (log_.size() >= log_lines || log_bytes_ + line.text.size() > log_bytes)) {
        log_bytes_ -= log_.front().text.size(); log_.pop_front();
    }
    log_bytes_ += line.text.size(); log_.push_back(std::move(line));
    notify(ready_.get());
}
void ManagedProcess::run(std::unique_ptr<Child> child) noexcept {
    struct Stream { int fd; ProcessStream type; std::string partial; bool truncated = false, skip_lf = false; };
    Stream streams[] = {{child->stdout_fd(), ProcessStream::output, {}}, {child->stderr_fd(), ProcessStream::error, {}}};
    auto consume = [&](Stream& stream) {
        char bytes[8192];
        size_t budget = 64u << 10;
        while (stream.fd >= 0 && budget) {
            auto count = read(stream.fd, bytes, std::min(sizeof(bytes), budget));
            if (count < 0 && errno == EINTR) continue;
            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (count < 0) throw std::system_error(errno, std::generic_category(), "read process output");
            if (!count) {
                stream.fd = -1;
                if (!stream.partial.empty() || stream.truncated) line(stream.type, std::move(stream.partial), stream.truncated);
                stream.partial.clear(); stream.truncated = false;
                break;
            }
            budget -= static_cast<size_t>(count);
            for (ssize_t i = 0; i < count; ++i) {
                if (stream.skip_lf && bytes[i] == '\n') { stream.skip_lf = false; continue; }
                stream.skip_lf = bytes[i] == '\r';
                if (bytes[i] == '\n' || bytes[i] == '\r') {
                    line(stream.type, std::move(stream.partial), stream.truncated);
                    stream.partial.clear(); stream.truncated = false;
                } else if (stream.partial.size() < line_limit) stream.partial += bytes[i];
                else stream.truncated = true;
            }
        }
    };
    bool requested = false;
    auto deadline = std::chrono::steady_clock::time_point::max();
    std::optional<int> exit;
    auto tail_deadline = std::chrono::steady_clock::time_point::max();
    std::string failure;
    try {
        for (;;) {
            drain_event(control_.get());
            std::unique_ptr<Signal> signal;
            { std::lock_guard lock(mutex_); signal = std::move(signal_); }
            if (signal) {
                try { signal->result.set_value(child->signal(signal->number)); }
                catch (...) { signal->result.set_exception(std::current_exception()); }
            }
            if (stopping_ && !requested) {
                requested = true; child->request_stop();
                deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(grace_ms_.load());
                std::lock_guard lock(mutex_); status_.stopping = true; notify(ready_.get());
            }
            for (auto& stream : streams) consume(stream);
            if (!exit && (child->poll_exit() || (requested && std::chrono::steady_clock::now() >= deadline))) {
                exit = child->stop(std::chrono::milliseconds(0));
                tail_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(250);
            }
            if (exit && streams[0].fd < 0 && streams[1].fd < 0) break;
            if (exit && std::chrono::steady_clock::now() >= tail_deadline) {
                failure = "Output remained open after owned process group exited";
                for (auto& stream : streams) if (!stream.partial.empty() || stream.truncated)
                    line(stream.type, std::move(stream.partial), true);
                break;
            }
            pollfd fds[] = {{control_.get(), POLLIN, 0}, {streams[0].fd, POLLIN, 0}, {streams[1].fd, POLLIN, 0}, {child->pidfd(), POLLIN, 0}};
            int wait = -1;
            if (requested) wait = static_cast<int>(std::clamp<int64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count(), 0, 100));
            if (exit) wait = 25;
            if (poll(fds, 4, wait) < 0 && errno != EINTR) throw std::system_error(errno, std::generic_category(), "poll process output");
        }
    } catch (const std::exception& error) { failure = error.what(); }
    catch (...) { failure = "Process output monitor failed"; }
    if (!exit) { try { exit = child->stop(std::chrono::milliseconds(0)); } catch (...) {} }
    child.reset();
    std::lock_guard lock(mutex_);
    status_.running = false; status_.stopping = false;
    status_.unexpected_exit = !requested && !stopping_;
    status_.exit_code = exit; status_.error = failure.substr(0, 4096);
    resync_ |= !failure.empty();
    if (signal_) { signal_->result.set_value(false); signal_.reset(); }
    notify(ready_.get());
}
}
