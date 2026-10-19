// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/vm_display.h"
#include "common/wire.h"
#include <algorithm>
#include <iostream>
#include <source_location>

using namespace droidvm;
using namespace droidvm::web;
namespace {
void require(bool value, const std::source_location& at = std::source_location::current()) {
    if (!value) throw std::runtime_error("Display contract failed at line " + std::to_string(at.line()));
}
void contract() {
    auto now = VmDisplayChannel::Clock::now();
    SessionStore sessions({}, [&] { return now; });
    const CallContext local{"local-admin", true, true, true};
    const auto grant = sessions.exchange(sessions.issue_pairing(local).token);
    const vm::Observation expected{"0123456789abcdef0123456789abcdef", 7};
    bool connected = false, current = true;
    size_t opens = 0, closes = 0, written = 0, maximum_write = 2;
    std::string outgoing = "RFB 003.008\n", accepted;
    auto validate = [&] { if (!current) throw ServiceError(ErrorCode::conflict, "Display runtime changed"); };
    auto source = std::make_shared<VmDisplaySource>(VmDisplaySource{
        [&](const CallContext& caller, const std::string& id) {
            require(caller.principal == grant.session.caller.principal && id == "vm");
            return VmDisplayTarget{id, expected, {{"gpu-0", true, "", true}, {"simplefb", false, "not-vnc", false}}};
        },
        [&](const CallContext& caller, const std::string& id, const std::string& screen, const vm::Observation& actual) {
            require(caller.principal == grant.session.caller.principal && id == "vm" && screen == "gpu-0" && actual == expected);
            ++opens;
            return VmDisplayStream{
                [&] { validate(); return connected; },
                [&](size_t limit) { validate(); require(limit == 65536); return std::exchange(outgoing, {}); },
                [&](std::string_view data) { validate(); const auto count = std::min(data.size(), maximum_write); accepted += data.substr(0, count); written += count; return count; },
                [&] { ++closes; }, "private-rfb-password"
            };
        }
    });
    ResourceCatalogs resources; resources.display_source = source;
    HttpApi api(sessions, {{"127.0.0.1:8080", "http://127.0.0.1:8080"}}, [](const CallContext&) { return Json::Value(); },
        {"epoch", {"test", "1"}}, {}, {}, {}, {}, false, {}, resources);
    const Headers headers{{"Host", "127.0.0.1:8080"}, {"Origin", "http://127.0.0.1:8080"}, {"Cookie", "droidvm-session=" + grant.token}};
    const auto metadata_response = api.handle({"GET", "/api/v1/vm-displays/vm", headers, {}});
    require(metadata_response.status == 200 && metadata_response.body.find("password") == std::string::npos);
    const auto metadata = wire::parse(metadata_response.body);
    require(metadata["screens"].size() == 2 && metadata["screens"][1]["reason"] == "not-vnc");
    HttpRequest request{"GET", "/api/v1/display", headers, {}};
    auto authorize = [&](const Json::Value& value) { return api.authorize_display(request, value); };
    auto first = api.reserve_display(request), second = api.reserve_display(request);
    try { (void)api.reserve_display(request); require(false); }
    catch (const ServiceError& error) { require(error.code() == ErrorCode::resource_exhausted); }
    second.reset(); second = api.reserve_display(request); second.reset();
    auto frame = wire::parse(R"({"type":"open","vmId":"vm","screenId":"gpu-0"})");
    frame["context"] = metadata["context"]; frame["expected"] = metadata["expected"]; frame["csrfToken"] = grant.session.csrf;
    {
        VmDisplayChannel channel(*source, "epoch", authorize, std::move(first), [&] { return now; });
        require(channel.next({{}, {}, {}, wire::stringify(frame)}).status == 204 && opens == 1);
        connected = true;
        const auto ready = channel.next({}); require(ready.status == 200 && !ready.binary);
        require(wire::parse(ready.body)["password"] == "private-rfb-password");
        auto output = channel.next({}); require(output.status == 200 && output.binary && output.body == "RFB 003.008\n");
        require(channel.next({{}, {}, {}, "abcd", true}).status == 204 && written == 2 && accepted == "ab");
        require(channel.next({}).status == 204 && written == 4 && accepted == "abcd");
        require(channel.next({"CHECK", "/api/v1/display", {}, {}}).status == 204 && written == 4);
        current = false;
        require(channel.next({"CHECK", "/api/v1/display", {}, {}}).status == 409 && closes == 1);
        require(channel.next({{}, {}, {}, "abcd", true}).status == 410 && written == 4);
    }
    require(closes == 1);
    current = true;
    {
        VmDisplayChannel channel(*source, "epoch", authorize, api.reserve_display(request), [&] { return now; });
        auto stale = frame; stale["expected"]["revision"] = "8";
        require(channel.next({{}, {}, {}, wire::stringify(stale)}).status == 409 && opens == 1);
    }
    {
        VmDisplayChannel channel(*source, "epoch", authorize, api.reserve_display(request), [&] { return now; });
        require(channel.next({{}, {}, {}, wire::stringify(frame)}).status == 200);
        maximum_write = 0;
        require(channel.next({{}, {}, {}, "blocked", true}).status == 204);
        now += std::chrono::seconds(11);
        require(channel.next({}).status == 503 && written == 4);
    }
    {
        VmDisplayChannel channel(*source, "epoch", authorize, api.reserve_display(request), [&] { return now; });
        require(channel.next({{}, {}, {}, wire::stringify(frame)}).status == 200);
        sessions.revoke(local, grant.session.id);
        require(channel.next({"CHECK", "/api/v1/display", {}, {}}).status == 401);
    }
    require(opens == 3 && closes == 3);
}
}
int main() {
    try { contract(); std::cout << "Display channel contract passed\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
