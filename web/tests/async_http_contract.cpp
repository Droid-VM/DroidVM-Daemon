// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/async_http.h"
#include <atomic>
#include <deque>
#include <future>
#include <iostream>

using namespace droidvm;
using namespace droidvm::web;
namespace {
void require(bool condition) { if (!condition) throw std::runtime_error("HTTP queue assertion failed"); }
template<class Function> void rejected(Function function, ErrorCode expected = ErrorCode::resource_exhausted) {
    try { function(); } catch (const ServiceError& error) { require(error.code() == expected); return; }
    throw std::runtime_error("Expected queue rejection");
}
struct Scheduler {
    std::deque<AsyncHttp::Work> work;
    AsyncHttp::Post post() { return [this](AsyncHttp::Work next) { work.push_back(std::move(next)); }; }
    AsyncHttp::Work take() { auto next = std::move(work.front()); work.pop_front(); return next; }
    void run(bool discarded = false) { take()(discarded); }
};
HttpRequest request() { return {"GET", "/api/v1/vms", {}, {}}; }
HttpResponse response(const HttpRequest&) { return {200, {{"Content-Type", "application/json"}}, "{\"items\":[]}"}; }
size_t passed = 0;
template<class Function> void test(const char* name, Function function) {
    function(); ++passed; std::cout << "PASS " << name << '\n';
}
}
int main() {
    try {
        test("dispatch is deferred and the completion identifies the exact request generation", [] {
            Scheduler scheduler; size_t calls = 0;
            AsyncHttp queue(scheduler.post(), [&](const auto& input) { ++calls; return response(input); });
            const auto ticket = queue.submit(7, request());
            require(calls == 0 && queue.drain().empty());
            scheduler.run();
            auto done = queue.drain();
            require(calls == 1 && done.size() == 1 && done[0].ticket() == ticket && done[0].response().status == 200);
            require(queue.drain().empty());
        });
        test("one active request per connection and drained responses retain quota until destroyed", [] {
            Scheduler scheduler; AsyncHttp queue(scheduler.post(), response, {1, 512, 4096});
            queue.submit(1, request());
            rejected([&] { queue.submit(1, request()); });
            rejected([&] { queue.submit(2, request()); });
            scheduler.run(); auto done = queue.drain();
            rejected([&] { queue.submit(2, request()); });
            auto held = std::move(done[0]); done.clear();
            rejected([&] { queue.submit(2, request()); });
            // Destruction is the only capacity release; a moved owner retains it.
            { auto release = std::move(held); require(release.response().status == 200); }
            queue.submit(2, request()); scheduler.run();
            require(queue.drain().size() == 1);
        });
        test("per-request stream handlers own their state until queued cancellation completes", [] {
            Scheduler scheduler; size_t calls = 0;
            AsyncHttp queue(scheduler.post(), response);
            auto state = std::make_shared<int>(7); std::weak_ptr<int> lifetime = state;
            const auto ticket = queue.submit(1, request(), [state, &calls](const auto&) {
                ++calls; return HttpResponse{200, {}, std::to_string(*state)};
            });
            state.reset(); queue.cancel(ticket);
            require(!lifetime.expired());
            scheduler.run();
            require(calls == 0 && lifetime.expired() && queue.drain().empty());
            queue.submit(2, request(), [](const auto&) { return HttpResponse{200, {}, "event"}; });
            scheduler.run(); auto done = queue.drain();
            require(done.size() == 1 && done[0].response().body == "event");
        });
        test("aggregate payload reservations bound distinct connections", [] {
            Scheduler scheduler; AsyncHttp queue(scheduler.post(), response, {16, 512, 1100});
            queue.submit(1, request()); queue.submit(2, request());
            rejected([&] { queue.submit(3, request()); });
            scheduler.run(); scheduler.run(); require(queue.drain().size() == 2);
            queue.submit(3, request()); scheduler.run(); require(queue.drain().size() == 1);
        });
        test("cancelled queued work skips the handler and cannot cancel a reused connection", [] {
            Scheduler scheduler; size_t calls = 0;
            AsyncHttp queue(scheduler.post(), [&](const auto& input) { ++calls; return response(input); });
            const auto old = queue.submit(9, request()); queue.cancel(old);
            const auto fresh = queue.submit(9, request()); queue.cancel(old);
            require(old.generation != fresh.generation);
            scheduler.run(); require(calls == 0); scheduler.run();
            auto done = queue.drain(); require(calls == 1 && done.size() == 1 && done[0].ticket() == fresh);
        });
        test("cancelled queued inputs keep their reservation until the scheduler releases them", [] {
            Scheduler scheduler; AsyncHttp queue(scheduler.post(), response, {1, 512, 4096});
            auto ticket = queue.submit(1, request()); queue.cancel(ticket);
            rejected([&] { queue.submit(2, request()); });
            scheduler.run(); queue.submit(2, request()); scheduler.run();
            require(queue.drain().size() == 1);
        });
        test("disconnect during a running handler discards only the old generation", [] {
            Scheduler scheduler; std::promise<void> entered, proceed;
            auto gate = proceed.get_future().share(); std::atomic<size_t> calls = 0;
            AsyncHttp queue(scheduler.post(), [&](const auto& input) {
                if (++calls == 1) { entered.set_value(); require(gate.wait_for(std::chrono::seconds(5)) == std::future_status::ready); }
                return response(input);
            });
            const auto old = queue.submit(4, request());
            auto worker = std::async(std::launch::async, [work = scheduler.take()] { work(false); });
            entered.get_future().wait(); queue.cancel(old);
            const auto fresh = queue.submit(4, request()); scheduler.run();
            auto done = queue.drain();
            proceed.set_value(); worker.get();
            require(done.size() == 1 && done[0].ticket() == fresh && queue.drain().empty());
        });
        test("destroying the mailbox skips queued work but never shuts down the scheduler", [] {
            Scheduler scheduler; size_t calls = 0;
            auto owned = std::make_shared<int>(42); std::weak_ptr<int> weak = owned;
            {
                AsyncHttp queue(scheduler.post(), [owned, &calls](const auto& input) { ++calls; return response(input); });
                queue.submit(1, request()); owned.reset();
            }
            require(!weak.expired()); scheduler.run(); require(calls == 0 && weak.expired());
            scheduler.post()([&](bool discarded) { require(!discarded); ++calls; }); scheduler.run(); require(calls == 1);
        });
        test("stop is nonblocking while a running handler owns its captured web state", [] {
            Scheduler scheduler; std::promise<void> entered, proceed;
            auto gate = proceed.get_future().share(); auto owned = std::make_shared<int>(42); std::weak_ptr<int> weak = owned;
            auto queue = std::make_unique<AsyncHttp>(scheduler.post(), [owned, &entered, gate](const auto& input) {
                entered.set_value(); require(gate.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
                require(*owned == 42); return response(input);
            });
            queue->submit(1, request()); owned.reset();
            auto worker = std::async(std::launch::async, [work = scheduler.take()] { work(false); });
            entered.get_future().wait(); queue.reset(); const bool retained = !weak.expired();
            proceed.set_value(); worker.get(); require(retained && weak.expired());
        });
        test("scheduler rejection releases all reservations and admits the next request", [] {
            Scheduler scheduler; bool reject = true;
            AsyncHttp queue([&](auto work) { if (reject) throw ServiceError(ErrorCode::resource_exhausted, "full"); scheduler.post()(std::move(work)); }, response, {1, 512, 4096});
            rejected([&] { queue.submit(1, request()); }); reject = false;
            queue.submit(1, request()); scheduler.run(); require(queue.drain().size() == 1);
        });
        test("worker shutdown discard returns unavailable without executing domain code", [] {
            Scheduler scheduler; size_t calls = 0;
            AsyncHttp queue(scheduler.post(), [&](const auto& input) { ++calls; return response(input); });
            queue.submit(1, request()); scheduler.run(true); auto done = queue.drain();
            require(calls == 0 && done.size() == 1 && done[0].response().status == 503);
            queue.stop(); queue.stop(); rejected([&] { queue.submit(2, request()); }, ErrorCode::unavailable);
        });
        test("input limits reject before scheduling and unsafe or large output never enters the mailbox", [] {
            Scheduler scheduler;
            AsyncHttp queue(scheduler.post(), [](const auto& input) -> HttpResponse {
                if (input.path == "/throw") throw std::runtime_error("private credential");
                if (input.path == "/header") return {200, {{"Set-Cookie", "secret\r\nInjected: yes"}}, "private"};
                return {200, {}, std::string(513, 'x')};
            }, {16, 512, 4096});
            auto oversized = request(); oversized.body.resize(4097);
            rejected([&] { queue.submit(1, oversized); });
            oversized = request(); oversized.path.resize(2049); rejected([&] { queue.submit(1, oversized); });
            oversized = request(); oversized.headers.emplace_back("Host", std::string(8192, 'x')); rejected([&] { queue.submit(1, oversized); });
            require(scheduler.work.empty());
            for (const auto* path : {"/large", "/throw", "/header"}) {
                auto input = request(); input.path = path;
                queue.submit(1, std::move(input)); scheduler.run(); auto done = queue.drain();
                require(done.size() == 1 && done[0].response().status >= 500 && done[0].response().body.find("private") == std::string::npos);
            }
        });
        test("stream metadata keeps its reservation and reader alive without loading the file", [] {
            Scheduler scheduler; std::weak_ptr<int> lifetime; size_t reads = 0;
            AsyncHttp queue(scheduler.post(), [&](const auto&) {
                auto owner = std::make_shared<int>(42); lifetime = owner;
                auto stream = std::make_shared<HttpStreamBody>(); stream->length = 1ull << 40;
                stream->read = [owner, &reads](uint64_t, size_t maximum) { ++reads; return std::string(maximum, static_cast<char>(*owner)); };
                return HttpResponse{200, {}, {}, std::move(stream)};
            }, {1, 512, 4096});
            queue.submit(1, request()); scheduler.run();
            auto done = queue.drain();
            require(done.size() == 1 && done[0].response().stream && done[0].response().stream->length == (1ull << 40)
                && done[0].response().body.empty() && reads == 0 && !lifetime.expired());
            rejected([&] { queue.submit(2, request()); });
            queue.stop(); require(!lifetime.expired()); done.clear(); require(lifetime.expired());
        });
        test("stream responses cannot also enqueue an ordinary body", [] {
            Scheduler scheduler;
            AsyncHttp queue(scheduler.post(), [](const auto&) {
                auto stream = std::make_shared<HttpStreamBody>(); stream->length = 3;
                stream->read = [](uint64_t, size_t) { return std::string("abc"); };
                return HttpResponse{200, {}, "unexpected", std::move(stream)};
            });
            queue.submit(1, request()); scheduler.run(); const auto done = queue.drain();
            require(done.size() == 1 && done[0].response().status == 503 && !done[0].response().stream);
        });
        test("session revocation while a request is queued is checked by the API before service access", [] {
            struct Owner {
                SessionStore sessions;
                size_t reads = 0;
                HttpApi api{sessions, {{"127.0.0.1:8080", "http://127.0.0.1:8080"}}, [this](const auto&) {
                    ++reads; Json::Value value; value["items"] = Json::Value(Json::arrayValue); return value;
                }, {"fixture-epoch", {"fixture", "1"}}};
            };
            auto owner = std::make_shared<Owner>(); Scheduler scheduler;
            const CallContext local{"local-admin", true, true, true};
            const auto grant = owner->sessions.exchange(owner->sessions.issue_pairing(local).token);
            AsyncHttp queue(scheduler.post(), [owner](const auto& input) { return owner->api.handle(input); });
            auto input = request(); input.headers = {{"Host", "127.0.0.1:8080"}, {"Cookie", "droidvm-session=" + grant.token}};
            queue.submit(1, input); owner->sessions.revoke(local, grant.session.id); scheduler.run();
            auto done = queue.drain(); require(owner->reads == 0 && done.size() == 1 && done[0].response().status == 401);
        });
        test("concurrent submitters cannot oversubscribe the mailbox", [] {
            std::mutex mutex; std::vector<AsyncHttp::Work> accepted; std::atomic<size_t> failures = 0;
            AsyncHttp queue([&](auto work) { std::lock_guard lock(mutex); accepted.push_back(std::move(work)); }, response, {4, 512, 4096});
            std::vector<std::future<void>> callers;
            for (uint64_t id = 1; id <= 16; ++id) callers.push_back(std::async(std::launch::async, [&, id] {
                try { queue.submit(id, request()); } catch (const ServiceError& error) { if (error.code() == ErrorCode::resource_exhausted) ++failures; }
            }));
            for (auto& caller : callers) caller.get();
            require(failures == 12 && accepted.size() == 4);
            for (auto& work : accepted) work(false);
            accepted.clear(); require(queue.drain().size() == 4);
        });
        std::cout << passed << " HTTP queue contract checks passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
