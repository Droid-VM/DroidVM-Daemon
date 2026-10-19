// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "transport/dispatcher.h"

using namespace droidvm;
using namespace droidvm::test;
namespace {
void web_ipc_boundary() {
    TaskService tasks;
    SystemService system([] { return true; }, [] { return "test"; }, "test", tasks.epoch());
    RequestDispatcher dispatcher(system, tasks);
    ClientSession session; session.caller.authorized = true;
    const Json::Value request(Json::objectValue);
    check(!dispatcher.execute(session, "capabilities", request).isMember("webui"), "unbound WebUI is not advertised");
    unsigned calls = 0, ticks = 0, stops = 0;
    dispatcher.set_web([&](const CallContext& caller, const std::string& command, const Json::Value&) {
        check(caller.principal == "local-admin" && caller.authenticated && caller.administrator, "only local identity reaches WebUI control");
        ++calls;
        if (command == "web_configure") throw ServiceError(ErrorCode::conflict, "Reload settings");
        Json::Value result; result["marker"] = "control"; return result;
    }, [&] { ++ticks; }, [&] { ++stops; });
    check(dispatcher.execute(session, "capabilities", request)["webui"] == "http-session-v1", "bound feature advertises protocol");
    for (const auto* command : {"web_status", "web_configure", "web_reload", "web_pair", "web_revoke"}) {
        check(dispatcher.background(command), "every control operation runs on workers");
        check(dispatcher.execute_background({}, command, request)["error"]["code"] == "UNAUTHENTICATED", "anonymous rejected before callback");
        check(dispatcher.execute_background({"web:test", true, true, true}, command, request)["error"]["code"] == "PERMISSION_DENIED", "browser admin rejected before callback");
    }
    check(calls == 0, "denied requests never invoke control");
    check(dispatcher.execute(session, "web_status", request)["marker"] == "control", "synchronous adapter uses same identity gate");
    check(dispatcher.execute_background({"local-admin", true, true, true}, "web_configure", request)["error"]["code"] == "CONFLICT", "structured service errors preserved");
    check(dispatcher.has_maintenance(), "WebUI makes existing maintenance loop active");
    dispatcher.maintenance(); dispatcher.stop_web();
    check(ticks == 1 && stops == 1 && calls == 2, "callbacks routed exactly once");
}
}
int main() { return run({{"web_ipc_boundary", web_ipc_boundary}}); }
