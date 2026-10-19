// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/http_api.h"
#include "web/vm_read_model.h"
#include "web/host_overview.h"
#include <limits>
#include <iostream>
#include <sstream>

using namespace droidvm;
using namespace droidvm::web;
namespace {
const CallContext local{"local-admin", true, true, true};
void require(bool condition) { if (!condition) throw std::runtime_error("HTTP contract assertion failed"); }
Json::Value parse(const std::string& text) {
    Json::Value result; Json::CharReaderBuilder builder; std::istringstream input(text);
    require(Json::parseFromStream(builder, input, &result, nullptr)); return result;
}
std::string field(const HttpResponse& response, const std::string& name) {
    for (const auto& entry : response.headers) if (entry.first == name) return entry.second;
    return {};
}
std::string cookie_field(const HttpResponse& response, const std::string& name) {
    for (const auto& [key, value] : response.headers)
        if (key == "Set-Cookie" && value.starts_with(name + "=")) return value;
    return {};
}
struct Fixture {
    SessionStore sessions;
    explicit Fixture(SessionPersistence persistence = {})
        : sessions({}, SessionStore::Clock::now, {}, std::move(persistence)) {}
    size_t reads = 0;
    bool service_fail = false;
    HttpApi api{sessions, {{"127.0.0.1:8080", "http://127.0.0.1:8080"},
                         {"192.168.1.20:8080", "http://192.168.1.20:8080"}}, [this](const CallContext& caller) {
        require(caller.authenticated && caller.administrator && caller.principal.starts_with("web:"));
        ++reads;
        if (service_fail) throw std::runtime_error("sensitive host path or credential");
        Json::Value value(Json::objectValue); value["items"] = Json::Value(Json::arrayValue); return value;
    }, {"fixture-epoch", {"fixture", "9007199254740993"}}};
    HttpRequest request(std::string method, std::string path = "/api/v1/session") {
        return {std::move(method), std::move(path), {{"Host", "127.0.0.1:8080"},
            {"Origin", "http://127.0.0.1:8080"}}, {}};
    }
    HttpResponse login() {
        auto req = request("POST"); req.headers.emplace_back("Content-Type", "application/json");
        req.body = "{\"pairingToken\":\"" + sessions.issue_pairing(local).token + "\"}";
        auto result = api.handle(req); require(result.status == 201); return result;
    }
    HttpRequest authorized(const HttpResponse& login, std::string method, std::string path = "/api/v1/session") {
        auto req = request(std::move(method), std::move(path));
        const auto set_cookie = field(login, "Set-Cookie");
        req.headers.emplace_back("Cookie", set_cookie.substr(0, set_cookie.find(';')));
        return req;
    }
};
size_t passed = 0;
template<class Function> void test(const char* name, Function function) {
    function(); ++passed; std::cout << "PASS " << name << '\n';
}
}
int main() {
    try {
        test("host overview preserves exact observations and unknown samples", [] {
            HostOverview value;
            value.observed_at_ms = 1792339200000ULL;
            value.daemon = {42, "contract"};
            auto data = host_overview_catalog(value);
            require(data["cpu"]["usagePercent"].isNull() && data["memory"]["totalBytes"].isNull());
            require(data["storage"]["freeBytes"].isNull() && data["host"]["deviceModel"].isNull());
            require(data["inventory"]["vmCount"].isNull() && data["observedAtMs"] == "1792339200000");
            value.memory = {std::numeric_limits<uint64_t>::max(), 9007199254740993ULL};
            value.storage = {100, 40, 30}; value.inventory.vm_count = 0;
            value.cpu = {8, 37.5, 3000};
            data = host_overview_catalog(value);
            require(data["memory"]["totalBytes"] == "18446744073709551615" && data["memory"]["availableBytes"] == "9007199254740993");
            require(data["storage"]["freeBytes"] == "40" && data["storage"]["availableBytes"] == "30");
            require(data["cpu"]["usagePercent"].asDouble() == 37.5 && data["inventory"]["vmCount"].asUInt() == 0);
            value.cpu.usage_percent = std::numeric_limits<double>::quiet_NaN();
            value.storage = {100, 101, 102}; value.host.device_model = "invalid\nlabel";
            data = host_overview_catalog(value);
            require(data["cpu"]["usagePercent"].isNull() && data["cpu"]["sampleWindowMs"].isNull());
            require(data["storage"]["freeBytes"].isNull() && data["storage"]["availableBytes"].isNull());
            require(data["host"]["deviceModel"].isNull());
        });
        test("disk compression is explicit authenticated read-only inspection", [] {
            Fixture f; const auto login = f.login(); size_t checks = 0, details = 0;
            ResourceCatalogs resources;
            resources.disk_detail = [&](const CallContext&, const std::string&) { ++details; return Json::Value(); };
            resources.disk_compression = [&](const CallContext& caller, const std::string& id) {
                require(caller.administrator && caller.authenticated && id == "disk"); ++checks;
                Json::Value value; value["inspection"]["effectiveCompression"] = "none"; return value;
            };
            HttpApi api{f.sessions, {{"127.0.0.1:8080", "http://127.0.0.1:8080"}},
                [](const auto&) { return Json::Value(); }, {"fixture-epoch", {"fixture", "1"}},
                {}, {}, {}, {}, false, {}, resources};
            constexpr auto path = "/api/v1/disks/disk/compression";
            require(api.handle(f.request("GET", path)).status == 401 && checks == 0);
            require(api.handle(f.authorized(login, "GET", "/api/v1/disks/disk")).status == 200 && details == 1 && checks == 0);
            require(api.handle(f.authorized(login, "POST", path)).status == 405 && checks == 0);
            auto req = f.authorized(login, "GET", path); req.headers[1].second = "http://evil.invalid";
            require(api.handle(req).status == 403 && checks == 0);
            req = f.authorized(login, "GET", path); req.body = "{}";
            require(api.handle(req).status == 400 && checks == 0);
            require(api.handle(f.authorized(login, "GET", "/api/v1/disks/disk/extra/compression")).status == 400 && checks == 0);
            require(f.api.handle(f.authorized(login, "GET", path)).status == 501);
            const auto response = api.handle(f.authorized(login, "GET", path));
            require(response.status == 200 && checks == 1 && field(response, "Cache-Control") == "no-store");
            require(parse(response.body)["inspection"]["effectiveCompression"] == "none");
            bool found = false;
            const auto caps = parse(api.handle(f.authorized(login, "GET", "/api/v1/capabilities")).body);
            for (const auto& capability : caps["server"]["capabilities"])
                found |= capability == "disks.compression.v1";
            require(found && checks == 1);
        });
        test("clone directory capability requires an explicit disk binding opt-in", [] {
            Fixture f; const auto login = f.login(); const auto session = parse(login.body);
            size_t writes = 0;
            for (const bool enabled : {false, true}) {
                ResourceCatalogs resources;
                resources.disk_clone_directory = enabled;
                resources.disk_actions.submit = [&](const CallContext&, const Json::Value&) { ++writes; return Json::Value(); };
                resources.disk_actions.find = [](const CallContext&, const std::string&) { return Json::Value(); };
                HttpApi api{f.sessions, {{"127.0.0.1:8080", "http://127.0.0.1:8080"}},
                    [](const auto&) { return Json::Value(); }, {"fixture-epoch", {"fixture", "1"}},
                    {}, {}, {}, {}, false, {}, resources};
                const auto capabilities = parse(api.handle(f.authorized(login, "GET", "/api/v1/capabilities")).body);
                bool advertised = false;
                for (const auto& cap : capabilities["server"]["capabilities"]) advertised |= cap == "disks.clone-directory.v1";
                require(advertised == enabled);
                auto request = f.authorized(login, "POST", "/api/v1/disk-operations");
                request.headers.emplace_back("X-DroidVM-CSRF", session["csrfToken"].asString());
                request.headers.emplace_back("Content-Type", "application/json");
                auto input = parse(R"({"requestId":"clone-directory","revision":"disks","vmRevision":"vms","operation":{"action":"clone","diskId":"disk","folder":"/fixture/Linux","name":"disk.qcow2","createFolder":true}})");
                input["context"]["daemonEpoch"] = "fixture-epoch"; input["context"]["sessionId"] = session["id"];
                Json::StreamWriterBuilder writer; request.body = Json::writeString(writer, input);
                require(api.handle(request).status == (enabled ? 202 : 501));
                require(writes == (enabled ? 1u : 0u));
            }
        });
        test("host overview uses authenticated read-only admission and capability", [] {
            Fixture f; const auto login = f.login(); size_t reads = 0;
            ResourceCatalogs resources;
            resources.host_overview = [&](const CallContext& caller) {
                require(caller.administrator && caller.authenticated); ++reads;
                HostOverview value; value.daemon = {42, "contract"}; return host_overview_catalog(value);
            };
            HttpApi api{f.sessions, {{"127.0.0.1:8080", "http://127.0.0.1:8080"}},
                [](const auto&) { return Json::Value(); }, {"fixture-epoch", {"fixture", "1"}},
                {}, {}, {}, {}, false, {}, resources};
            constexpr auto path = "/api/v1/host/overview";
            require(api.handle(f.request("GET", path)).status == 401 && reads == 0);
            auto req = f.authorized(login, "GET", path); req.headers[1].second = "http://evil.invalid";
            require(api.handle(req).status == 403 && reads == 0);
            require(api.handle(f.authorized(login, "POST", path)).status == 405 && reads == 0);
            req = f.authorized(login, "GET", path); req.body = "{}";
            require(api.handle(req).status == 400 && reads == 0);
            require(f.api.handle(f.authorized(login, "GET", path)).status == 501);
            const auto response = api.handle(f.authorized(login, "GET", path));
            require(response.status == 200 && reads == 1 && field(response, "Cache-Control") == "no-store");
            const auto data = parse(response.body);
            require(data["context"]["sessionId"] == parse(login.body)["id"]);
            require(data["context"]["daemonEpoch"] == "fixture-epoch" && data["cpu"]["usagePercent"].isNull());
            const auto capabilities = parse(api.handle(f.authorized(login, "GET", "/api/v1/capabilities")).body);
            bool found = false;
            for (const auto& capability : capabilities["server"]["capabilities"]) found |= capability == "host.overview.v1";
            require(found && reads == 1);
        });
        test("hugepage management keeps pure reads and guarded task admission", [] {
            Fixture f; const auto login = f.login(); const auto session = parse(login.body);
            size_t reads = 0, writes = 0;
            ResourceCatalogs resources;
            resources.hugepages.read = [&](const CallContext&) { ++reads; Json::Value value; value["loaded"] = true; return value; };
            resources.hugepages.tasks.submit = [&](const CallContext&, const Json::Value& input) {
                require(input.size() == 3 && input["operation"]["kind"] == "reconcile"); ++writes; return Json::Value(Json::objectValue);
            };
            resources.hugepages.tasks.find = [](const CallContext&, const std::string&) { return Json::Value(); };
            HttpApi api{f.sessions, {{"127.0.0.1:8080", "http://127.0.0.1:8080"}},
                [](const auto&) { return Json::Value(); }, {"fixture-epoch", {"fixture", "1"}}, {}, {}, {}, {}, false, {}, resources};
            const auto caps = parse(api.handle(f.authorized(login, "GET", "/api/v1/capabilities")).body);
            bool basic = false, manage = false;
            for (const auto& capability : caps["server"]["capabilities"]) { basic |= capability == "host.hugepages.v1"; manage |= capability == "host.hugepages.manage.v1"; }
            require(basic && manage);
            require(api.handle(f.request("GET", "/api/v1/host/hugepages")).status == 401);
            const auto read = api.handle(f.authorized(login, "GET", "/api/v1/host/hugepages"));
            require(read.status == 200 && reads == 1 && writes == 0 && field(read, "Cache-Control") == "no-store");
            require(api.handle(f.authorized(login, "POST", "/api/v1/host/hugepages")).status == 405 && writes == 0);
            auto request = f.authorized(login, "POST", "/api/v1/hugepage-operations");
            request.headers.emplace_back("Content-Type", "application/json");
            Json::Value body; body["requestId"] = "explicit-reconcile"; body["expected"]["fingerprint"] = "current";
            body["operation"]["kind"] = "reconcile"; body["context"] = parse(read.body)["context"];
            request.body = body.toStyledString();
            require(api.handle(request).status == 403 && writes == 0);
            request.headers.emplace_back("X-DroidVM-CSRF", session["csrfToken"].asString());
            body["context"]["sessionId"] = "other"; request.body = body.toStyledString();
            require(api.handle(request).status == 409 && writes == 0);
            body["context"] = parse(read.body)["context"]; request.body = body.toStyledString();
            require(api.handle(request).status == 202 && writes == 1 && reads == 1);
        });
        test("hugepage process routes constrain sources and protect stack and signals", [] {
            Fixture f; const auto login = f.login(); const auto session = parse(login.body);
            size_t reads = 0, stacks = 0, writes = 0, finds = 0;
            ResourceCatalogs resources;
            resources.hugepage_processes.list = [&](const CallContext& caller, const std::string& source) {
                require(caller.administrator && source == "scan"); ++reads;
                Json::Value value; value["source"] = source; return value;
            };
            resources.hugepage_processes.stack = [&](const CallContext&, const Json::Value& expected) {
                ++stacks; Json::Value value; value["expected"] = expected; return value;
            };
            resources.hugepage_processes.tasks.submit = [&](const CallContext&, const Json::Value& input) {
                require(input.size() == 3 && input["signal"] == "term"); ++writes; return Json::Value(Json::objectValue);
            };
            resources.hugepage_processes.tasks.find = [&](const CallContext&, const std::string& id) {
                require(id == "process-request"); ++finds; return Json::Value();
            };
            HttpApi api{f.sessions, {{"127.0.0.1:8080", "http://127.0.0.1:8080"}},
                [](const auto&) { return Json::Value(); }, {"fixture-epoch", {"fixture", "1"}}, {}, {}, {}, {}, false, {}, resources};
            require(api.handle(f.request("GET", "/api/v1/host/hugepage-processes")).status == 401);
            const auto read = api.handle(f.authorized(login, "GET", "/api/v1/host/hugepage-processes/scan"));
            require(read.status == 200 && reads == 1 && stacks == 0 && writes == 0);
            for (const auto* suffix : {"/all", "/scan/ko", "/", "/%73can"})
                require(api.handle(f.authorized(login, "GET", std::string("/api/v1/host/hugepage-processes") + suffix)).status == 400);
            require(reads == 1);
            auto request = f.authorized(login, "POST", "/api/v1/hugepage-process-stack");
            request.headers.emplace_back("Content-Type", "application/json");
            Json::Value body; body["expected"] = parse(R"({"pid":42,"startTicks":"123","source":"scan","membership":"token"})");
            body["context"] = parse(read.body)["context"]; request.body = body.toStyledString();
            require(api.handle(request).status == 403 && stacks == 0);
            request.headers.emplace_back("X-DroidVM-CSRF", session["csrfToken"].asString());
            body["context"]["sessionId"] = "other"; request.body = body.toStyledString();
            require(api.handle(request).status == 409 && stacks == 0);
            body["context"] = parse(read.body)["context"]; request.body = body.toStyledString();
            require(api.handle(request).status == 200 && stacks == 1 && writes == 0);
            body["requestId"] = "process-request"; body["signal"] = "term"; request.body = body.toStyledString();
            request.path = "/api/v1/hugepage-process-operations";
            require(api.handle(request).status == 202 && writes == 1);
            require(api.handle(f.authorized(login, "GET", "/api/v1/hugepage-process-operations/process-request")).status == 200);
            require(finds == 1 && writes == 1);
            const auto caps = parse(api.handle(f.authorized(login, "GET", "/api/v1/capabilities")).body);
            bool found = false;
            for (const auto& capability : caps["server"]["capabilities"]) found |= capability == "host.hugepages.processes.v1";
            require(found);
        });
        test("capabilities require authentication and describe only browser adapters", [] {
            Fixture f;
            require(f.api.handle(f.request("GET", "/api/v1/capabilities")).status == 401 && f.reads == 0);
            const auto login = f.login();
            const auto view = parse(login.body);
            require(view["server"]["apiMajor"] == 1 && view["server"]["apiMinor"] == 0);
            require(view["server"]["versionCode"].asString() == "9007199254740993");
            const auto result = f.api.handle(f.authorized(login, "GET", "/api/v1/capabilities"));
            require(result.status == 200 && field(result, "Cache-Control") == "no-store" && f.reads == 0);
            const auto data = parse(result.body);
            require(data["server"] == view["server"] && data["context"]["sessionId"] == view["id"]);
            require(data["context"]["daemonEpoch"] == "fixture-epoch");
            require(data["server"]["capabilities"].size() == 3);
            require(data["server"]["capabilities"][0] == "session.v1" &&
                data["server"]["capabilities"][1] == "session.lan-auto.v1" &&
                data["server"]["capabilities"][2] == "vm.list.v1");
            require(!data.isMember("csrfToken") && !data.isMember("commands"));
        });
        test("VM response identity belongs to its authenticated request", [] {
            Fixture f; const auto first = f.login(), second = f.login();
            const auto a = parse(f.api.handle(f.authorized(first, "GET", "/api/v1/vms")).body);
            const auto b = parse(f.api.handle(f.authorized(second, "GET", "/api/v1/vms")).body);
            require(a["context"]["daemonEpoch"] == b["context"]["daemonEpoch"]);
            require(a["context"]["sessionId"] == parse(first.body)["id"]);
            require(b["context"]["sessionId"] == parse(second.body)["id"]);
            require(a["context"]["sessionId"] != b["context"]["sessionId"]);
        });
        test("capability reads preserve origin and method boundaries", [] {
            Fixture f; const auto login = f.login();
            auto request = f.authorized(login, "GET", "/api/v1/capabilities");
            request.headers[1].second = "http://evil.invalid"; require(f.api.handle(request).status == 403);
            request = f.authorized(login, "POST", "/api/v1/capabilities"); require(f.api.handle(request).status == 405);
        });
        test("Agent routes preserve admission boundaries and never replay unknown receipts", [] {
            Fixture f; const auto login = f.login(); const auto session = parse(login.body);
            size_t submitted = 0, found = 0, recovered = 0;
            bool fail = false;
            ResourceCatalogs resources;
            resources.agent_actions.submit = [&](const CallContext& caller, const Json::Value& input) {
                require(caller.administrator && caller.manage_tasks && input.size() == 4);
                require(input["operation"]["password"] == "Private123!");
                ++submitted;
                if (fail) throw std::runtime_error("Private123! /private/host-path");
                Json::Value result; result["id"] = "agent-task"; return result;
            };
            resources.agent_actions.find = [&](const CallContext&, const std::string& id) {
                require(id == "agent-request"); ++found; return Json::Value();
            };
            resources.agent_recovery.status = [](const CallContext&) {
                Json::Value result; result["pendingRecords"] = 2; return result;
            };
            resources.agent_recovery.tasks.submit = [&](const CallContext&, const Json::Value& input) {
                require(input.size() == 1 && input["requestId"] == "agent-request"); ++recovered;
                Json::Value result; result["id"] = "recovery-task"; return result;
            };
            resources.agent_recovery.tasks.find = [&](const CallContext&, const std::string& id) {
                require(id == "agent-request"); ++found; return Json::Value();
            };
            HttpApi api{f.sessions, {{"127.0.0.1:8080", "http://127.0.0.1:8080"}},
                [](const auto&) { return Json::Value(); }, {"fixture-epoch", {"fixture", "1"}},
                {}, {}, {}, {}, false, {}, resources};
            auto post = [&](std::string path = "/api/v1/agent-operations") {
                auto req = f.authorized(login, "POST", path);
                req.headers.emplace_back("Content-Type", "application/json");
                req.headers.emplace_back("X-DroidVM-CSRF", session["csrfToken"].asString());
                Json::Value input;
                input["context"]["daemonEpoch"] = "fixture-epoch";
                input["context"]["sessionId"] = session["id"];
                input["requestId"] = "agent-request";
                if (path == "/api/v1/agent-operations") {
                    input["revision"] = "disk-revision"; input["vmRevision"] = "vm-revision";
                    input["operation"]["action"] = "chpasswd";
                    input["operation"]["diskId"] = "12345678-1234-1234-1234-123456789abc";
                    input["operation"]["password"] = "Private123!";
                }
                req.body = input.toStyledString(); return req;
            };
            const auto capabilities = parse(api.handle(f.authorized(login, "GET", "/api/v1/capabilities")).body);
            bool operation_capability = false, recovery_capability = false;
            for (const auto& capability : capabilities["server"]["capabilities"]) {
                operation_capability |= capability == "agent.operations.v1";
                recovery_capability |= capability == "agent.recovery.v1";
            }
            require(operation_capability && recovery_capability);
            auto req = post(); req.headers.pop_back(); require(api.handle(req).status == 403);
            req = post(); req.headers[1].second = "http://evil.invalid"; require(api.handle(req).status == 403);
            req = post(); req.headers.erase(req.headers.begin() + 2); require(api.handle(req).status == 401);
            req = post(); auto input = parse(req.body); input["context"]["sessionId"] = "other";
            req.body = input.toStyledString(); require(api.handle(req).status == 409);
            req = post(); req.body.resize(4097, ' '); require(api.handle(req).status == 413);
            require(submitted == 0);
            require(api.handle(f.authorized(login, "GET", "/api/v1/agent-operations")).status == 405);
            require(api.handle(f.authorized(login, "POST", "/api/v1/agent-operations/agent-request")).status == 405);
            require(api.handle(f.authorized(login, "GET", "/api/v1/agent-operations?password=Private123!")).status == 404);
            const auto accepted = api.handle(post()); require(accepted.status == 202 && submitted == 1);
            require(parse(accepted.body)["task"]["id"] == "agent-task" && accepted.body.find("Private123!") == std::string::npos);
            const auto lookup = api.handle(f.authorized(login, "GET", "/api/v1/agent-operations/agent-request"));
            require(lookup.status == 200 && parse(lookup.body)["task"].isNull() && found == 1 && submitted == 1);
            fail = true; const auto failed = api.handle(post());
            require(failed.status == 500 && failed.body.find("Private123!") == std::string::npos && failed.body.find("host-path") == std::string::npos);
            const auto status = api.handle(f.authorized(login, "GET", "/api/v1/agent-recovery"));
            require(status.status == 200 && parse(status.body)["pendingRecords"] == 2 && recovered == 0);
            require(api.handle(f.authorized(login, "DELETE", "/api/v1/agent-recovery")).status == 405);
            require(api.handle(post("/api/v1/agent-recovery")).status == 202 && recovered == 1);
            require(api.handle(f.authorized(login, "GET", "/api/v1/agent-recovery/agent-request")).status == 200 && found == 2 && recovered == 1);
            require(f.api.handle(post()).status == 501);
            require(HttpApi::request_limit("/api/v1/agent-operations") == 4096 &&
                HttpApi::request_limit("/api/v1/agent-recovery") == 4096);
        });
        test("unauthenticated session and VM reads are denied before service invocation", [] {
            Fixture f;
            require(f.api.handle(f.request("GET")).status == 401);
            require(f.api.handle(f.request("GET", "/api/v1/vms")).status == 401 && f.reads == 0);
        });
        test("pairing establishes HTTP cookie with no credential in response JSON", [] {
            Fixture f; auto login = f.login(); const auto cookie = field(login, "Set-Cookie");
            require(cookie.starts_with("droidvm-session=") && cookie.find("HttpOnly") != std::string::npos);
            require(cookie.find("SameSite=Strict") != std::string::npos && cookie.find("Path=/") != std::string::npos);
            require(cookie.find("Secure") == std::string::npos && cookie.find("Domain") == std::string::npos);
            require(cookie.find("Max-Age") == std::string::npos && !parse(login.body)["remembered"].asBool());
            require(field(login, "Cache-Control") == "no-store");
            const auto secret = cookie.substr(16, 64);
            require(login.body.find(secret) == std::string::npos);
            const auto read = f.api.handle(f.authorized(login, "GET"));
            require(read.status == 200 && parse(read.body)["csrfToken"] == parse(login.body)["csrfToken"]);
        });
        test("LAN automatic session requires same-origin intent and cannot authenticate remotely", [] {
            Fixture f;
            auto req = f.request("GET"); req.trusted_lan = true;
            require(f.api.handle(req).status == 403);
            req.headers.emplace_back("X-DroidVM-Session", "1");
            req.headers[1].second = "http://evil.invalid";
            require(f.api.handle(req).status == 403);
            req.headers[1].second = "http://127.0.0.1:8080";
            req.headers.emplace_back("Sec-Fetch-Site", "cross-site");
            require(f.api.handle(req).status == 403);
            require(f.sessions.session_ids(local).empty());
            req.headers.pop_back();
            req.headers.erase(req.headers.begin() + 1); // Plain HTTP fetch may omit Origin/Fetch Metadata.
            const auto login = f.api.handle(req);
            require(login.status == 200 && parse(login.body)["lanOnly"].asBool());
            require(!parse(login.body)["remembered"].asBool());
            require(cookie_field(login, "droidvm-session").find("Max-Age") == std::string::npos);
            auto read = f.authorized(login, "GET", "/api/v1/vms");
            require(f.api.handle(read).status == 401 && f.reads == 0);
            read.trusted_lan = true;
            require(f.api.handle(read).status == 200 && f.reads == 1);
            auto stream = f.authorized(login, "GET", "/api/v1/events");
            stream.trusted_lan = true;
            require(f.api.authorize_stream(stream).id == parse(login.body)["id"].asString());
            stream.trusted_lan = false;
            bool denied = false;
            try { f.api.authorize_stream(stream); }
            catch (const ServiceError& error) { denied = error.code() == ErrorCode::unauthenticated; }
            require(denied);
        });
        test("LAN logout suppresses automatic entry until an explicit local login", [] {
            Fixture f;
            auto req = f.request("GET"); req.trusted_lan = true;
            req.headers.emplace_back("X-DroidVM-Session", "1");
            const auto login = f.api.handle(req); require(login.status == 200);
            auto logout = f.authorized(login, "DELETE"); logout.trusted_lan = true;
            const auto forbidden = f.api.handle(logout);
            require(forbidden.status == 403 && field(forbidden, "Set-Cookie").empty());
            logout.headers.emplace_back("X-DroidVM-CSRF", parse(login.body)["csrfToken"].asString());
            const auto result = f.api.handle(logout);
            require(result.status == 204);
            const auto marker = cookie_field(result, "droidvm-local-logout");
            require(marker == "droidvm-local-logout=1; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000");
            const auto expired = f.api.handle(logout);
            require(expired.status == 401 && cookie_field(expired, "droidvm-local-logout") == marker);
            req.headers.emplace_back("Cookie", marker.substr(0, marker.find(';')));
            require(f.api.handle(req).status == 401);
            auto enter = f.request("POST", "/api/v1/session/local");
            enter.headers.emplace_back("Content-Type", "application/json");
            enter.headers.emplace_back("Cookie", "droidvm-local-logout=1"); enter.body = "{}";
            require(f.api.handle(enter).status == 403);
            enter.trusted_lan = true;
            const auto renewed = f.api.handle(enter);
            require(renewed.status == 201 && parse(renewed.body)["lanOnly"].asBool());
            require(cookie_field(renewed, "droidvm-local-logout") ==
                "droidvm-local-logout=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
            require(parse(renewed.body)["id"] != parse(login.body)["id"]);
        });
        test("remembered pairing advertises support and issues a thirty day HttpOnly cookie", [] {
            Json::Value disk;
            SessionPersistence persistence;
            persistence.load = [&] { return disk; };
            persistence.save = [&](const Json::Value& value) { disk = value; };
            // Digest double; production crypto is covered by the native persistence adapter.
            persistence.digest = [](std::string_view value) {
                auto result = std::string(value);
                for (auto& c : result) c = "fedcba9876543210"[std::string_view("0123456789abcdef").find(c)];
                return result;
            };
            Fixture f(std::move(persistence));
            auto options = f.request("GET", "/api/v1/session/options");
            const auto remote = parse(f.api.handle(options).body);
            require(remote["rememberSupported"].asBool() && !remote["lanAvailable"].asBool());
            options.trusted_lan = true;
            require(parse(f.api.handle(options).body)["lanAvailable"].asBool());
            auto req = f.request("POST"); req.headers.emplace_back("Content-Type", "application/json");
            Json::Value input; input["pairingToken"] = f.sessions.issue_pairing(local).token; input["remember"] = true;
            req.body = input.toStyledString();
            const auto login = f.api.handle(req);
            require(login.status == 201 && parse(login.body)["remembered"].asBool());
            require(!parse(login.body)["lanOnly"].asBool() && disk["sessions"].size() == 1);
            const auto cookie = cookie_field(login, "droidvm-session");
            require(cookie.find("HttpOnly") != std::string::npos && cookie.find("Max-Age=2592000") != std::string::npos);
            require(f.api.handle(f.authorized(login, "GET", "/api/v1/vms")).status == 200);
        });
        test("authenticated read delegates browser context to the existing service adapter", [] {
            Fixture f; const auto login = f.login();
            const auto result = f.api.handle(f.authorized(login, "GET", "/api/v1/vms"));
            require(result.status == 200 && f.reads == 1 && parse(result.body)["items"].isArray());
        });
        test("Host Origin mismatches and missing mutation Origin fail closed", [] {
            Fixture f;
            auto req = f.request("POST"); req.headers.pop_back(); require(f.api.handle(req).status == 403);
            req = f.request("GET"); req.headers[0].second = "evil.invalid"; require(f.api.handle(req).status == 403);
            req = f.request("POST"); req.headers[1].second = "null"; require(f.api.handle(req).status == 403);
            req = f.request("POST"); req.headers[1].second = "http://192.168.1.20:8080"; require(f.api.handle(req).status == 403);
            require(f.reads == 0);
        });
        test("ambiguous headers and duplicate cookies are rejected", [] {
            Fixture f; const auto login = f.login();
            for (const auto* name : {"hOsT", "oRiGiN", "cOoKiE"}) {
                auto req = f.authorized(login, "GET"); req.headers.emplace_back(name, "ambiguous");
                require(f.api.handle(req).status == 400);
            }
            auto req = f.authorized(login, "GET"); req.headers.back().second += "; droidvm-session=second";
            require(f.api.handle(req).status == 400);
        });
        test("invalid JSON extra fields duplicate keys and unsupported media rejected", [] {
            Fixture f;
            for (const auto* body : {"{}", "[]", "{", "{\"pairingToken\":1}",
                 "{\"pairingToken\":\"x\",\"administrator\":true}",
                 "{\"pairingToken\":\"x\",\"remember\":\"true\"}",
                 "{\"pairingToken\":\"x\",\"pairingToken\":\"y\"}", "{\"pairingToken\":\"x\"} {}"}) {
                auto req = f.request("POST"); req.headers.emplace_back("Content-Type", "application/json"); req.body = body;
                require(f.api.handle(req).status == 400);
            }
            auto req = f.request("POST"); req.body = "{}"; require(f.api.handle(req).status == 400);
            req.headers.emplace_back("Content-Type", "text/plain"); require(f.api.handle(req).status == 400);
        });
        test("oversized bodies and header control characters rejected", [] {
            Fixture f; auto req = f.request("POST"); req.body = std::string(4097, 'x');
            require(f.api.handle(req).status == 413);
            req = f.request("GET"); req.headers.emplace_back("X-Test", "a\r\nb"); require(f.api.handle(req).status == 400);
            req = f.request("GET"); req.headers.emplace_back("X-Test", std::string(8192, 'x')); require(f.api.handle(req).status == 400);
        });
        test("logout enforces session-bound CSRF and clears the same cookie", [] {
            Fixture f; auto login = f.login(); auto req = f.authorized(login, "DELETE");
            require(f.api.handle(req).status == 403);
            req.headers.emplace_back("X-DroidVM-CSRF", parse(login.body)["csrfToken"].asString());
            const auto result = f.api.handle(req);
            require(result.status == 204 && result.body.empty());
            require(field(result, "Set-Cookie") == "droidvm-session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
            require(f.api.handle(f.authorized(login, "GET", "/api/v1/vms")).status == 401);
        });
        test("service failures never expose raw messages", [] {
            Fixture f; auto login = f.login(); f.service_fail = true;
            const auto result = f.api.handle(f.authorized(login, "GET", "/api/v1/vms"));
            require(result.status == 500 && result.body.find("sensitive") == std::string::npos);
            require(parse(result.body)["error"]["code"] == "internal");
        });
        test("unknown APIs and credentials in query never fall back to a page", [] {
            Fixture f;
            const auto result = f.api.handle(f.request("GET", "/api/v1/session?token=abc"));
            require(result.status == 404 && field(result, "Content-Type").starts_with("application/json"));
            auto bad_method = f.api.handle(f.request("POST", "/api/v1/vms"));
            require(bad_method.status == 405 && field(bad_method, "Allow") == "GET");
        });
        test("WS uses the same session Origin and revocation checks", [] {
            Fixture f; auto login = f.login(); auto req = f.authorized(login, "GET", "/api/v1/events");
            auto view = f.api.authorize_stream(req);
            require(view.id == parse(login.body)["id"].asString());
            req.headers.erase(req.headers.begin() + 1);
            bool denied = false;
            try { f.api.authorize_stream(req); } catch (const ServiceError& e) { denied = e.code() == ErrorCode::permission_denied; }
            require(denied);
            f.sessions.revoke(local, view.id); req = f.authorized(login, "GET", "/api/v1/events"); denied = false;
            try { f.api.authorize_stream(req); } catch (const ServiceError& e) { denied = e.code() == ErrorCode::unauthenticated; }
            require(denied);
        });
        test("VM list projects only permitted fields without credentials or paths", [] {
            auto source = parse(R"({"id":"9007199254740993","name":"VM","state":"RUNNING","backend":"QEMU","cpu_count":4,"memory_mb":2048,"password":"secret","environment":{"TOKEN":"secret"},"disks":[{"path":"/private/disk"}]})");
            Json::Value inventory(Json::arrayValue); inventory.append(source);
            const auto result = vm_snapshot(inventory), view = result["items"][0];
            require(view.size() == 8 && view["id"].asString() == "9007199254740993");
            require(view["cpuCount"].asInt() == 4 && view["memoryMiB"].asInt() == 2048);
            require(!view.isMember("password") && !view.isMember("environment") && !view.isMember("disks"));
            require(source["password"] == "secret");
        });
        test("VM quantities stay unknown rather than inventing defaults", [] {
            auto row = parse(R"({"id":"vm","state":"STOPPED","cpu_count":"4","memory_mb":true})");
            Json::Value inventory(Json::arrayValue); inventory.append(row);
            auto view = vm_snapshot(inventory)["items"][0];
            require(view["cpuCount"].isNull() && view["memoryMiB"].isNull() && view["backend"].isNull() && view["name"] == "vm");
            inventory[0]["cpu_count"] = Json::UInt64(9007199254740992ULL);
            inventory[0]["memory_mb"] = -1;
            view = vm_snapshot(inventory)["items"][0];
            require(view["cpuCount"].isNull() && view["memoryMiB"].isNull());
        });
        test("duplicate VM IDs and unsupported states reject the entire projection", [] {
            auto inventory = parse(R"([{"id":"vm","state":"RUNNING"},{"id":"vm","state":"STOPPED"}])");
            bool denied = false;
            try { vm_snapshot(inventory); } catch (const ServiceError& e) { denied = e.code() == ErrorCode::unavailable; }
            require(denied); denied = false;
            inventory = parse(R"([{"id":"vm","state":"UNKNOWN"}])");
            try { vm_snapshot(inventory); } catch (const ServiceError& e) { denied = e.code() == ErrorCode::unavailable; }
            require(denied);
        });
        test("VM observations require current runtime and actual matching unexpired leases", [] {
            auto inventory = parse(R"([{"id":"vm","state":"RUNNING","runtime_instance":"run","runtime_revision":"2","runtime_uptime_ms":"90001","networks":[{"network_id":"net","mac_address":"02:AA:BB:CC:DD:EE","vlan_id":7,"dhcp4_lease":{"enabled":true,"offset":64}}]}])");
            auto leases = parse(R"([{"mac":"02:aa:bb:cc:dd:ee","ip":"192.0.2.7","vlan":7,"expires":9223372036854775807},{"mac":"02:aa:bb:cc:dd:ee","ip":"192.0.2.8","vlan":8,"expires":9223372036854775807},{"mac":"02:aa:bb:cc:dd:ee","ip":"192.0.2.9","vlan":7,"expires":1}])");
            auto lookup = [&](const std::string& network) { require(network == "net"); return leases; };
            auto current = [](const std::string& id, const std::string& instance, const std::string& revision) { return id == "vm" && instance == "run" && revision == "2"; };
            const auto observed = vm_snapshot(inventory, nullptr, lookup, current)["items"][0];
            require(observed["uptimeMs"] == "90001" && observed["ipAddresses"].size() == 1 && observed["ipAddresses"][0] == "192.0.2.7");
            inventory[0]["runtime_revision"] = "3";
            require(vm_snapshot(inventory, nullptr, lookup, current)["items"][0]["ipAddresses"].isNull());
            inventory[0]["state"] = "STOPPED";
            const auto stopped = vm_snapshot(inventory, nullptr, lookup, current)["items"][0];
            require(stopped["ipAddresses"].isNull() && stopped["uptimeMs"].isNull());
        });
        std::cout << passed << " HTTP API contract groups passed\n"; return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
