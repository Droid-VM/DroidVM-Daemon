// SPDX-License-Identifier: GPL-3.0-or-later
#include "vm/observation.h"
#include "vm/qmp_control.h"
#include "common/wire.h"
#include "services/context.h"
#include <deque>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>

using namespace droidvm;
namespace {
void require(bool value) { if (!value) throw std::runtime_error("VM control assertion failed"); }
template<class F> void conflict(F run) {
    try { run(); } catch (const ServiceError& error) { require(error.code() == ErrorCode::conflict); return; }
    throw std::runtime_error("Expected lifecycle conflict");
}
const std::string greeting = "{\"QMP\":{\"version\":{},\"capabilities\":[]}}\r\n";
const std::string capabilities = "{\"return\":{},\"id\":\"capabilities\"}\r\n";
const std::string acknowledged = "{\"return\":{},\"id\":\"command\"}\r\n";
const std::string event = "{\"event\":\"STOP\",\"timestamp\":{\"seconds\":1}}\r\n";
struct Peer {
    std::deque<std::string> chunks;
    std::vector<Json::Value> sent;
    size_t reads = 0;
    bool send_failure = false;
    bool run() {
        Json::Value command; command["execute"] = "stop";
        return vm::qmp_control(command, [&](std::string_view text) {
            sent.push_back(wire::parse(text)); return !send_failure;
        }, [&]() -> std::string {
            ++reads;
            if (chunks.empty()) return {};
            auto chunk = std::move(chunks.front()); chunks.pop_front(); return chunk;
        });
    }
};
size_t passed = 0;
template<class F> void test(const char* name, F run) { run(); ++passed; std::cout << "PASS " << name << '\n'; }
}
int main() {
    try {
        test("new instances and state ABA invalidate old observations", [] {
            vm::RuntimeVersion first, replacement;
            const auto old = first.observe();
            require(!old.instance.empty() && old.instance != replacement.observe().instance);
            conflict([&] { replacement.admit(old); });
            first.changed(); first.changed(); // RUNNING -> SUSPENDED -> RUNNING
            conflict([&] { first.admit(old); });
            first.admit(first.observe());
        });
        test("legacy commands invalidate remote observations without changing VM state", [] {
            vm::RuntimeVersion version; const auto old = version.observe();
            version.admit({}); // e.g. reboot request before worker publishes a transition
            conflict([&] { version.admit(old); });
            require(version.observe().revision == old.revision + 1);
        });
        test("one observed revision admits at most one concurrent command", [] {
            vm::RuntimeVersion version; const auto old = version.observe();
            std::mutex state; size_t admitted = 0, rejected = 0;
            std::vector<std::thread> clients;
            for (size_t i = 0; i < 16; ++i) clients.emplace_back([&] {
                std::lock_guard lock(state); // Same ownership discipline as VmRuntime.
                try { version.admit(old); ++admitted; }
                catch (const ServiceError& error) { if (error.code() == ErrorCode::conflict) ++rejected; }
            });
            for (auto& client : clients) client.join();
            require(admitted == 1 && rejected == 15);
        });
        test("fragmented and coalesced QMP frames match the exact command ACK", [] {
            const auto stream = greeting + event + capabilities + event + acknowledged;
            for (size_t at = 1; at < stream.size(); ++at) {
                Peer peer; peer.chunks = {stream.substr(0, at), stream.substr(at)};
                require(peer.run() && peer.sent.size() == 2);
                require(peer.sent[0]["execute"] == "qmp_capabilities" && peer.sent[0]["id"] == "capabilities");
                require(peer.sent[1]["execute"] == "stop" && peer.sent[1]["id"] == "command");
            }
            Peer peer; for (char c : stream) peer.chunks.push_back(std::string(1, c));
            require(peer.run());
        });
        test("events EOF wrong IDs and error objects are not successful control replies", [] {
            for (const auto& response : {event, std::string("{}\n"), std::string("{\"return\":{},\"id\":\"other\"}\n"),
                std::string("{\"error\":{},\"id\":\"command\"}\n"), std::string("{\"return\":{},\"error\":{},\"id\":\"command\"}\n"),
                std::string("{\"return\":null,\"id\":\"command\"}\n")}) {
                Peer peer; peer.chunks = {greeting + capabilities + response};
                require(!peer.run() && peer.sent.size() == 2);
            }
        });
        test("failed negotiation cannot send the command and failed writes are not retried", [] {
            Peer peer; peer.chunks = {greeting + "{\"error\":{},\"id\":\"capabilities\"}\n" + acknowledged};
            require(!peer.run() && peer.sent.size() == 1);
            Peer bad; bad.chunks = {"{}\n"}; require(!bad.run() && bad.sent.empty());
            Peer write; write.chunks = {greeting + capabilities + acknowledged}; write.send_failure = true;
            require(!write.run() && write.sent.size() == 1);
        });
        test("malformed duplicate-key and trailing JSON frames are rejected", [] {
            for (const auto& response : {"not-json\n", "{\"return\":{},\"id\":\"other\",\"id\":\"command\"}\n",
                "{\"return\":{},\"id\":\"command\"}{}\n", "{\"return\":{},\"id\":\"command\",}\n"}) {
                Peer peer; peer.chunks = {greeting + capabilities + response}; require(!peer.run());
            }
        });
        test("byte and event floods are bounded independently of transport timeouts", [] {
            Peer bytes; bytes.chunks = {greeting + capabilities, std::string(65536, 'x')};
            require(!bytes.run() && bytes.reads == 2);
            Peer events; events.chunks = {greeting + capabilities};
            for (size_t i = 0; i < 200; ++i) events.chunks.push_back(event);
            require(!events.run() && events.reads <= 128);
            Peer incomplete; incomplete.chunks = {greeting + capabilities + "{\"return\":{}}"};
            require(!incomplete.run());
        });
        test("transport failures never become acknowledgement or replay", [] {
            Json::Value command; command["execute"] = "cont";
            size_t calls = 0;
            require(!vm::qmp_control(command, [](auto) { return true; }, [&]() -> std::string { ++calls; throw std::runtime_error("read failed"); }));
            require(calls == 1);
        });
        std::cout << passed << " VM control groups passed\n"; return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
