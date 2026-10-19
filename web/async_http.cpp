// SPDX-License-Identifier: GPL-3.0-or-later
#include "async_http.h"
#include <limits>
#include <map>

namespace droidvm::web {
namespace http_detail {
struct Budget {
    std::mutex mutex;
    size_t pending = 0, bytes = 0;
};
struct Reservation {
    std::shared_ptr<Budget> budget;
    size_t bytes = 0;
    ~Reservation() {
        if (!bytes) return;
        std::lock_guard lock(budget->mutex);
        --budget->pending;
        budget->bytes -= bytes;
    }
};
struct Job {
    HttpTicket ticket;
    std::shared_ptr<Reservation> reservation;
    HttpRequest request;
    AsyncHttp::Handle handle;
    std::optional<HttpResponse> response;
    bool cancelled = false, started = false;
};
struct Queue {
    std::mutex mutex;
    std::shared_ptr<Budget> budget = std::make_shared<Budget>();
    HttpQueueLimits limits;
    AsyncHttp::Handle handle;
    std::map<uint64_t, std::shared_ptr<Job>> jobs;
    std::map<uint64_t, uint64_t> live;
    uint64_t sequence = 0;
    bool stopped = false;
};
}
namespace {
[[noreturn]] void capacity() { throw ServiceError(ErrorCode::resource_exhausted, "HTTP queue capacity exhausted"); }
HttpResponse failure(int status, const char* code) {
    return {status, {{"Content-Type", "application/json"}, {"Cache-Control", "no-store"}},
        std::string("{\"error\":{\"code\":\"") + code + "\"}}"};
}
size_t input_bytes(const HttpRequest& request) {
    if (request.method.size() > 16 || request.path.size() > 2048 || request.body.size() > HttpApi::request_limit(request.path) || request.headers.size() > 64)
        capacity();
    size_t headers = 0;
    for (const auto& [name, value] : request.headers) {
        if (name.size() > 8192 - headers) capacity();
        headers += name.size();
        if (value.size() > 8192 - headers) capacity();
        headers += value.size();
    }
    return request.method.size() + request.path.size() + request.body.size() + headers;
}
bool bounded(const HttpResponse& response, size_t limit) {
    if (response.status < 200 || response.status > 599 || response.headers.size() > 64 || response.body.size() > limit) return false;
    if (response.stream && (response.status != 200 || !response.body.empty() || !response.stream->read
        || !response.stream->chunk_bytes || response.stream->chunk_bytes > (256u << 10)
        || response.stream->length > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))) return false;
    size_t bytes = response.body.size();
    for (const auto& [name, value] : response.headers) {
        if (name.size() > limit - bytes) return false;
        bytes += name.size();
        if (value.size() > limit - bytes) return false;
        bytes += value.size();
        if (name.empty() || name.find_first_of("\r\n:") != std::string::npos || value.find_first_of("\r\n") != std::string::npos) return false;
    }
    return true;
}
// queue.mutex held; only unlink a matching generation, never a reused connection.
void unlink(http_detail::Queue& queue, HttpTicket ticket) {
    const auto live = queue.live.find(ticket.connection);
    if (live != queue.live.end() && live->second == ticket.generation) queue.live.erase(live);
    queue.jobs.erase(ticket.generation);
}
void execute(const std::shared_ptr<http_detail::Queue>& queue, const std::shared_ptr<http_detail::Job>& job, bool discarded) {
    {
        std::lock_guard lock(queue->mutex);
        if (job->started) return;
        job->started = true;
        if (queue->stopped || job->cancelled) { unlink(*queue, job->ticket); return; }
    }
    HttpResponse response;
    try {
        response = discarded ? failure(503, "unavailable") : (job->handle ? job->handle : queue->handle)(job->request);
        if (!bounded(response, queue->limits.response_bytes)) response = failure(503, "unavailable");
    } catch (...) { response = failure(500, "internal"); }
    std::lock_guard lock(queue->mutex);
    if (queue->stopped || job->cancelled) unlink(*queue, job->ticket);
    else job->response.emplace(std::move(response));
}
}
HttpCompletion::HttpCompletion(HttpTicket ticket, HttpResponse response, std::shared_ptr<http_detail::Reservation> reservation)
    : ticket_(ticket), reservation_(std::move(reservation)), response_(std::move(response)) {}
HttpCompletion& HttpCompletion::operator=(HttpCompletion&& other) noexcept {
    if (this != &other) {
        HttpCompletion previous(std::move(other));
        std::swap(ticket_, previous.ticket_);
        std::swap(response_, previous.response_);
        reservation_.swap(previous.reservation_);
    }
    return *this;
}
AsyncHttp::AsyncHttp(Post post, Handle handle, HttpQueueLimits limits)
    : post_(std::move(post)), queue_(std::make_shared<http_detail::Queue>()) {
    if (!post_ || !handle || !limits.pending || limits.pending > 64 || limits.response_bytes < 512 ||
        limits.response_bytes > (4u << 20) || limits.retained_bytes < limits.response_bytes || limits.retained_bytes > (64u << 20))
        throw std::invalid_argument("Invalid HTTP queue configuration");
    queue_->limits = limits;
    queue_->handle = std::move(handle);
}
AsyncHttp::~AsyncHttp() { stop(); }
HttpTicket AsyncHttp::submit(uint64_t connection, HttpRequest request, Handle handle) {
    if (!connection) throw ServiceError(ErrorCode::invalid_argument, "Missing connection identity");
    const auto bytes = input_bytes(request) + queue_->limits.response_bytes;
    auto reservation = std::make_shared<http_detail::Reservation>();
    reservation->budget = queue_->budget;
    auto job = std::make_shared<http_detail::Job>();
    job->request = std::move(request);
    job->handle = std::move(handle);
    job->reservation = reservation;
    {
        std::lock_guard lock(queue_->mutex);
        if (queue_->stopped || queue_->sequence == std::numeric_limits<uint64_t>::max())
            throw ServiceError(ErrorCode::unavailable, "HTTP queue is stopped");
        if (queue_->live.contains(connection)) capacity();
        {
            std::lock_guard budget_lock(queue_->budget->mutex);
            if (queue_->budget->pending >= queue_->limits.pending || bytes > queue_->limits.retained_bytes - queue_->budget->bytes) capacity();
            ++queue_->budget->pending;
            queue_->budget->bytes += bytes;
            reservation->bytes = bytes;
        }
        job->ticket = {connection, ++queue_->sequence};
        queue_->jobs.emplace(job->ticket.generation, job);
        try { queue_->live.emplace(connection, job->ticket.generation); }
        catch (...) { queue_->jobs.erase(job->ticket.generation); throw; }
    }
    try {
        // No this/wsi/context capture. Accepted work can outlive this mailbox.
        post_([queue = queue_, job](bool discarded) { execute(queue, job, discarded); });
    } catch (...) {
        std::lock_guard lock(queue_->mutex);
        unlink(*queue_, job->ticket);
        throw;
    }
    return job->ticket;
}
void AsyncHttp::cancel(HttpTicket ticket) {
    std::lock_guard lock(queue_->mutex);
    const auto found = queue_->jobs.find(ticket.generation);
    if (found == queue_->jobs.end() || found->second->ticket != ticket) return;
    const auto job = found->second;
    job->cancelled = true;
    const auto live = queue_->live.find(ticket.connection);
    if (live != queue_->live.end() && live->second == ticket.generation) queue_->live.erase(live);
    if (job->response) queue_->jobs.erase(found);
    // Queued/running work still owns its input and reservation until completed.
}
std::vector<HttpCompletion> AsyncHttp::drain() {
    std::lock_guard lock(queue_->mutex);
    std::vector<HttpCompletion> result;
    result.reserve(queue_->jobs.size());
    for (auto it = queue_->jobs.begin(); it != queue_->jobs.end();) {
        auto& job = *it->second;
        if (!job.response) { ++it; continue; }
        result.push_back(HttpCompletion(job.ticket, std::move(*job.response), job.reservation));
        const auto live = queue_->live.find(job.ticket.connection);
        if (live != queue_->live.end() && live->second == job.ticket.generation) queue_->live.erase(live);
        it = queue_->jobs.erase(it);
    }
    return result;
}
void AsyncHttp::stop() {
    std::lock_guard lock(queue_->mutex);
    queue_->stopped = true;
    queue_->live.clear();
    for (auto it = queue_->jobs.begin(); it != queue_->jobs.end();) {
        it->second->cancelled = true;
        if (it->second->response) it = queue_->jobs.erase(it);
        else ++it;
    }
}
}
