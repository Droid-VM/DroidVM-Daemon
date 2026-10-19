// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/vm_terminal.h"
#include "common/wire.h"
#include "vm/console_busy.h"
#include <iostream>
#include <source_location>
#include <stdexcept>

namespace {
using namespace droidvm;
using namespace droidvm::web;
void check(bool value, const std::source_location& at = std::source_location::current()) {
    if (!value) throw std::runtime_error("Terminal contract failed at line " + std::to_string(at.line()));
}
struct Fixture {
    SessionView session{"session", {"web:terminal", true, true, true}, "csrf"};
    vm::Observation observed{std::string(32, 'a'), 9007199254740993ULL};
    vm::ConsoleHistory history;
    VmTerminalChannel::Clock::time_point time{};
    bool revoked = false, running = true, partial = false, target_busy = false, read_busy = false;
    unsigned reads = 0, writes = 0, open_auth = 0, poll_auth = 0;
    std::string accepted;
    VmTerminalSource source() {
        return {
            [this](const CallContext& caller, const std::string& id) {
                check(caller.principal == session.caller.principal);
                if (target_busy) throw vm::ConsoleBusy();
                return VmTerminalTarget{id, observed, running ? std::vector<std::string>{"stdio", "agent", "stdio"} : std::vector<std::string>{}};
            },
            [this](const CallContext&, const VmTerminalRead& request) {
                if (read_busy) throw vm::ConsoleBusy();
                if (!running || request.observed != observed) throw ServiceError(ErrorCode::conflict, "private runtime message");
                check(request.vm_id == "vm" && request.stream == "stdio");
                ++reads; return history.read(request.cursor, request.tail);
            },
            [this](const CallContext&, const VmTerminalWrite& request) {
                if (!running || request.observed != observed) throw ServiceError(ErrorCode::conflict, "private runtime message");
                check(request.vm_id == "vm" && request.stream == "stdio");
                ++writes;
                const size_t count = partial ? 1 : request.bytes.size();
                accepted.append(request.bytes.substr(0, count)); return count;
            }
        };
    }
    VmTerminalChannel channel() {
        return {source(), "epoch", [this](const Json::Value& frame) {
            if (revoked) throw ServiceError(ErrorCode::unauthenticated, "private credential detail");
            if (frame.isNull()) ++poll_auth;
            else {
                ++open_auth;
                if (frame["csrfToken"] != session.csrf) throw ServiceError(ErrorCode::permission_denied, "private CSRF detail");
            }
            return session;
        }, [this] { return time; }};
    }
    Json::Value open() const {
        Json::Value frame;
        frame["type"] = "open"; frame["csrfToken"] = session.csrf;
        frame["context"]["daemonEpoch"] = "epoch"; frame["context"]["sessionId"] = session.id;
        frame["vmId"] = "vm"; frame["expected"]["instanceId"] = observed.instance;
        frame["expected"]["revision"] = std::to_string(observed.revision);
        frame["stream"] = "stdio"; frame["cursor"] = Json::Value(); return frame;
    }
};
HttpResponse send(VmTerminalChannel& channel, const Json::Value& frame) {
    return channel.next({"", "", {}, wire::stringify(frame)});
}
HttpResponse poll(VmTerminalChannel& channel) { return channel.next({"", "", {}, {}}); }
Json::Value output_ack(const Json::Value& output) {
    Json::Value ack; ack["type"] = "ackOutput"; ack["generation"] = output["generation"]; ack["offset"] = output["next"]; return ack;
}
Json::Value input(const std::string& sequence, std::string_view bytes) {
    Json::Value frame; frame["type"] = "input"; frame["sequence"] = sequence; frame["data"] = wire::encode_base64(bytes); return frame;
}
}
int main() {
    try {
        {
            Fixture fixture;
            const auto list = vm_terminal_list(fixture.source(), fixture.session.caller, "vm");
            check(list["streams"].size() == 1 && list["streams"][0] == "stdio");
            check(list["expected"]["revision"] == "9007199254740993" && list["resizeSupported"] == false);
            fixture.history.append(std::string("<script>\0\xff", 10));
            auto channel = fixture.channel();
            const auto ready = send(channel, fixture.open());
            check(ready.status == 200 && wire::parse(ready.body)["type"] == "ready" && fixture.reads == 0);
            const auto first = wire::parse(poll(channel).body);
            check(first["type"] == "output" && wire::decode_base64(first["data"].asString(), 65536) == fixture.history.contents());
            fixture.history.append("later");
            check(poll(channel).status == 204 && fixture.reads == 1); // Render backpressure.
            fixture.time += std::chrono::seconds(15);
            check(wire::parse(poll(channel).body)["type"] == "heartbeat" && fixture.reads == 1);
            fixture.partial = true;
            const auto ack = wire::parse(send(channel, input("1", std::string("\0a", 2))).body);
            check(ack["type"] == "ack" && ack["accepted"].asUInt64() == 1 && ack["sequence"] == "1");
            check(fixture.writes == 1 && fixture.accepted == std::string(1, '\0'));
            check(send(channel, output_ack(first)).status == 204);
            const auto next = wire::parse(poll(channel).body);
            check(next["start"] == first["next"] && wire::decode_base64(next["data"].asString(), 65536) == "later");
            const auto duplicate = send(channel, input("1", "must not repeat"));
            check(duplicate.status == 400 && duplicate.body.empty() && fixture.writes == 1);
            check(poll(channel).status == 410 && fixture.writes == 1);
        }
        {
            Fixture fixture;
            auto channel = fixture.channel();
            check(send(channel, fixture.open()).status == 200);
            const auto empty = wire::parse(poll(channel).body);
            check(empty["type"] == "output" && empty["data"] == "" && empty["next"] == "0");
            check(send(channel, output_ack(empty)).status == 204);
            check(poll(channel).status == 204);
            fixture.history.clear();
            const auto reset = wire::parse(poll(channel).body);
            check(reset["reset"] == true && reset["generation"] != empty["generation"]);
            fixture.running = false;
            const auto stopped = poll(channel); // No output ACK: still check runtime.
            check(stopped.status == 409 && stopped.body.empty());
        }
        {
            Fixture fixture;
            auto csrf = fixture.channel(); auto open = fixture.open(); open["csrfToken"] = "wrong";
            check(send(csrf, open).status == 403 && fixture.writes == 0);
            auto changed = fixture.channel(); open = fixture.open(); open["expected"]["revision"] = "9007199254740992";
            check(send(changed, open).status == 409);
            auto agent = fixture.channel(); open = fixture.open(); open["stream"] = "agent";
            check(send(agent, open).status == 403);
            auto revoked = fixture.channel(); check(send(revoked, fixture.open()).status == 200);
            fixture.revoked = true;
            const auto denied = send(revoked, input("1", "x"));
            check(denied.status == 401 && denied.body.empty() && fixture.writes == 0);
        }
        {
            Fixture fixture;
            auto channel = fixture.channel(); check(send(channel, fixture.open()).status == 200);
            fixture.read_busy = true;
            check(poll(channel).status == 204 && fixture.reads == 0);
            fixture.read_busy = false; fixture.history.append("after contention");
            const auto output = wire::parse(poll(channel).body);
            check(output["type"] == "output" && fixture.reads == 1);
            fixture.target_busy = true;
            check(poll(channel).status == 204 && fixture.reads == 1);
            fixture.target_busy = false;
            check(poll(channel).status == 204 && fixture.reads == 1); // Still awaits the same ACK.
            fixture.target_busy = true; fixture.revoked = true;
            const auto revoked = poll(channel);
            check(revoked.status == 401 && revoked.body.empty() && fixture.reads == 1);
        }
        {
            Fixture fixture;
            auto channel = fixture.channel(); check(send(channel, fixture.open()).status == 200);
            auto invalid = input("1", std::string(513, 'x'));
            check(send(channel, invalid).status == 400 && fixture.writes == 0);
            auto skipped = fixture.channel(); check(send(skipped, fixture.open()).status == 200);
            check(send(skipped, input("2", "x")).status == 400 && fixture.writes == 0);
            auto malformed = fixture.channel(); check(send(malformed, fixture.open()).status == 200);
            invalid = input("1", "a"); invalid["data"] = "YR=="; // Noncanonical pad bits.
            check(send(malformed, invalid).status == 400 && fixture.writes == 0);
            auto wrong_ack = fixture.channel(); check(send(wrong_ack, fixture.open()).status == 200);
            auto ack = output_ack(wire::parse(poll(wrong_ack).body)); ack["offset"] = "1";
            check(send(wrong_ack, ack).status == 400);
            auto changed = fixture.channel(); check(send(changed, fixture.open()).status == 200);
            ++fixture.observed.revision;
            check(send(changed, input("1", "x")).status == 409 && fixture.writes == 0);
        }
        std::cout << "Terminal bounded duplex data, output backpressure, partial ACK, no replay, session/runtime binding and private stream contract passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
