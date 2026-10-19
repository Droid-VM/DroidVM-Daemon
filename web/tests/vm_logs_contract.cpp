// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/vm_logs.h"
#include "common/wire.h"
#include <iostream>
#include <mutex>

using namespace droidvm;
using namespace droidvm::web;
namespace {
void check(bool value) { if (!value) throw std::runtime_error("VM log contract failed"); }
const CallContext local{"local-admin", true, true, true};
template<class F> void test(const char* name, F work) { work(); std::cout << "PASS " << name << '\n'; }
}
int main() {
    try {
        test("one bounded ring preserves binary bytes, wraps and supports contiguous pages", [] {
            vm::ConsoleHistory history;
            std::string reference;
            for (size_t i = 1; i <= 19; ++i) {
                std::string input(i * 8191, static_cast<char>(i));
                history.append(input); reference += input;
                if (reference.size() > vm::ConsoleHistory::capacity) reference.erase(0, reference.size() - vm::ConsoleHistory::capacity);
                check(history.contents() == reference && history.size() == reference.size());
            }
            std::string collected;
            std::optional<vm::LogCursor> cursor;
            for (;;) {
                const auto chunk = history.read(cursor, false);
                check(chunk.bytes.size() <= vm::ConsoleHistory::chunk_bytes && !chunk.reset);
                check(chunk.next - chunk.start == chunk.bytes.size());
                check(wire::decode_base64(wire::encode_base64(chunk.bytes), vm::ConsoleHistory::chunk_bytes) == chunk.bytes);
                collected += chunk.bytes;
                if (chunk.next == chunk.end) break;
                cursor = vm::LogCursor{chunk.generation, chunk.next};
            }
            check(collected == reference);
            const auto tail = history.read({}, true);
            check(tail.bytes == reference.substr(reference.size() - vm::ConsoleHistory::chunk_bytes));
        });
        test("clear and overwritten cursors reset, future offsets fail without changing history", [] {
            vm::ConsoleHistory history;
            history.append(std::string("a\0b", 3));
            const auto first = history.read({}, false);
            history.append(std::string(vm::ConsoleHistory::capacity + 7, 'x'));
            auto gap = history.read(vm::LogCursor{first.generation, first.next}, false);
            check(gap.reset && gap.start == gap.floor && gap.generation == first.generation);
            history.clear(); history.append("new");
            const auto fresh = history.read(vm::LogCursor{gap.generation, gap.next}, false);
            check(fresh.reset && fresh.generation != gap.generation && fresh.bytes == "new" && fresh.start == 0);
            try { history.read(vm::LogCursor{fresh.generation, 4}, false); check(false); }
            catch (const std::invalid_argument&) {}
            check(history.contents() == "new");
            auto end = history.read(vm::LogCursor{fresh.generation, fresh.next}, false);
            check(end.bytes.empty() && !end.reset);
        });
        test("HTTP log boundary binds identity, instance and cursor and excludes private stream metadata", [] {
            SessionStore sessions;
            auto grant = sessions.exchange(sessions.issue_pairing(local).token);
            vm::ConsoleHistory history; history.append(std::string("<script>unsafe</script>\0\xff", 25));
            const std::string instance(32, 'a');
            unsigned reads = 0;
            const auto logs = vm_logs({
                [&](const CallContext& caller, const std::string& id) { check(caller.principal.starts_with("web:")); return VmLogTarget{id, instance, {"stdio", "stderr", "agent"}}; },
                [&](const CallContext&, const VmLogRead& request) {
                    if (request.instance_id != instance) throw ServiceError(ErrorCode::conflict, "VM replaced");
                    ++reads; return history.read(request.cursor, request.tail);
                }
            });
            HttpApi api{sessions, {{"localhost:8080", "http://localhost:8080"}}, [](const auto&) { return Json::Value(); }, {"epoch", {"test", "1"}}, {}, {}, {}, logs};
            auto request = [&](std::string method, std::string path) {
                return HttpRequest{method, path, {{"Host", "localhost:8080"}, {"Origin", "http://localhost:8080"}, {"Cookie", "droidvm-session=" + grant.token},
                    {"Content-Type", "application/json"}, {"X-DroidVM-CSRF", grant.session.csrf}}, {}};
            };
            auto list = api.handle(request("GET", "/api/v1/vm-logs/vm-1"));
            check(list.status == 200 && wire::parse(list.body)["streams"].size() == 2 && list.body.find("path") == std::string::npos);
            Json::Value body;
            body["context"]["daemonEpoch"] = "epoch"; body["context"]["sessionId"] = grant.session.id;
            body["vmId"] = "vm-1"; body["instanceId"] = instance; body["stream"] = "stdio"; body["cursor"] = Json::Value(); body["tail"] = true;
            auto req = request("POST", "/api/v1/vm-logs/read"); req.body = wire::stringify(body);
            auto reply = api.handle(req); check(reply.status == 200 && reads == 1);
            const auto chunk = wire::parse(reply.body); check(wire::decode_base64(chunk["data"].asString(), 65536) == history.contents());
            req.headers.pop_back(); check(api.handle(req).status == 403 && reads == 1);
            req = request("POST", "/api/v1/vm-logs/read");
            body["instanceId"] = std::string(32, 'b'); req.body = wire::stringify(body); check(api.handle(req).status == 409 && reads == 1);
            body["instanceId"] = instance; body["stream"] = "agent"; req.body = wire::stringify(body); check(api.handle(req).status == 403 && reads == 1);
            body["stream"] = "../stdio"; req.body = wire::stringify(body); check(api.handle(req).status == 400);
            body["stream"] = "stdio"; body["context"]["sessionId"] = "stale"; req.body = wire::stringify(body); check(api.handle(req).status == 409 && reads == 1);
        });
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
