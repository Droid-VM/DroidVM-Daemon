// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/backup_config.h"
#include "common/wire.h"
#include <chrono>
#include <iostream>
#include <source_location>
#include <thread>

using namespace droidvm;
using namespace droidvm::web;
using namespace std::chrono_literals;
namespace {
void require(bool value, const std::source_location& at = std::source_location::current()) {
    if (!value) throw std::runtime_error("Backup configuration contract failed at line " + std::to_string(at.line()));
}
void contract() {
    TaskLimits limits; limits.background_workers = 1;
    TaskService tasks(limits);
    SessionStore sessions;
    const CallContext local{"local-admin", true, true, true};
    const auto grant = sessions.exchange(sessions.issue_pairing(local).token);
    size_t appends = 0, commits = 0, opens = 0, reads = 0;
    BackupConfigBindings bindings;
    bindings.begin = [](const CallContext&, size_t bytes) { require(bytes == 3); return "upload"; };
    bindings.append = [&](const CallContext&, const std::string& id, size_t offset, std::string_view bytes) {
        require(id == "upload" && offset == 0 && bytes == "abc"); ++appends; return size_t(3);
    };
    bindings.preview = [](const CallContext&, const std::string& id) {
        require(id == "upload");
        return wire::parse(R"({"previewToken":"proof","revisions":{"vms":"v1","disks":"d1","networks":"n1"},"categories":{"vms":{"present":true,"count":2,"added":1,"replaced":1},"disks":{"present":false,"count":0,"added":0,"replaced":0},"networks":{"present":true,"count":1,"added":1,"replaced":0}},"private":"PRIVATE"})");
    };
    bindings.commit = [&](const CallContext&, const std::string& id, const std::string& token) {
        require(id == "upload" && token == "proof"); ++commits;
        return wire::parse(R"({"completed":["networks"],"failedStage":"vm_disks","uncertainStage":"vm_disks","recoveryRequired":true,"error":{"code":"COMMIT_UNCERTAIN","message":"PRIVATE"},"rawDocument":"PRIVATE"})");
    };
    bindings.abort = [](const CallContext&, const std::string&) {};
    bindings.export_file = [&](const CallContext&) {
        ++opens; auto stream = std::make_shared<HttpStreamBody>(); stream->length = 3;
        stream->read = [&](uint64_t offset, size_t maximum) {
            ++reads; require(offset <= 3 && maximum <= 3 - offset); return std::string("abc").substr(static_cast<size_t>(offset), maximum);
        };
        return stream;
    };
    ResourceCatalogs resources; resources.configuration_backup = backup_configuration(tasks, bindings);
    HttpApi api(sessions, {{"127.0.0.1:8080", "http://127.0.0.1:8080"}}, [](const CallContext&) { return Json::Value(); },
        {"epoch", {"test", "1"}}, {}, {}, {}, {}, false, {}, resources);
    auto request = [&](std::string method, std::string path, Json::Value body = {}) {
        HttpRequest req{method, std::move(path), {{"Host", "127.0.0.1:8080"}, {"Cookie", "droidvm-session=" + grant.token}}, {}};
        if (method == "POST") {
            req.headers.emplace_back("Origin", "http://127.0.0.1:8080"); req.headers.emplace_back("X-DroidVM-CSRF", grant.session.csrf);
        }
        if (!body.isNull()) { req.headers.emplace_back("Content-Type", "application/json"); req.body = wire::stringify(body); }
        return req;
    };
    const auto caps = wire::parse(api.handle(request("GET", "/api/v1/capabilities")).body);
    bool enabled = false; for (const auto& cap : caps["server"]["capabilities"]) enabled |= cap == "configuration.backup.v1";
    require(enabled);
    auto post = [&](const std::string& operation, Json::Value input) {
        input["context"] = caps["context"]; return request("POST", "/api/v1/configuration-backup/" + operation, input);
    };
    auto begin = post("begin", wire::parse(R"({"bytes":3})"));
    auto no_csrf = begin; no_csrf.headers.erase(no_csrf.headers.begin() + 3);
    require(api.handle(no_csrf).status == 403);
    require(api.handle(begin).status == 200);
    require(api.handle(post("begin", wire::parse(R"({"bytes":32505857})"))).status == 400);
    require(api.handle(post("append", wire::parse(R"({"uploadId":"upload","offset":0,"data":"YWJj"})"))).status == 200 && appends == 1);
    require(api.handle(post("append", wire::parse(R"({"uploadId":"upload","offset":"0","data":"YWJj"})"))).status == 400);
    auto preview = api.handle(post("preview", wire::parse(R"({"uploadId":"upload"})")));
    require(preview.status == 200 && preview.body.find("PRIVATE") == std::string::npos);
    const auto commit = post("commit", wire::parse(R"({"uploadId":"upload","previewToken":"proof","requestId":"commit"})"));
    require(api.handle(commit).status == 202);
    Json::Value task;
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    do {
        task = wire::parse(api.handle(post("status", wire::parse(R"({"requestId":"commit"})"))).body)["task"];
        if (task["state"] == "failed") break;
        std::this_thread::sleep_for(1ms);
    } while (std::chrono::steady_clock::now() < deadline);
    require(task["state"] == "failed" && task["errorCode"] == "COMMIT_UNCERTAIN");
    require(task["configurationBackup"]["completed"][0] == "networks" && task["configurationBackup"]["recoveryRequired"] == true);
    require(wire::stringify(task).find("PRIVATE") == std::string::npos);
    require(api.handle(commit).status == 202 && commits == 1);
    require(api.handle(post("commit", wire::parse(R"({"uploadId":"upload","previewToken":"other","requestId":"commit"})"))).status == 409);
    const auto other = sessions.exchange(sessions.issue_pairing(local).token);
    auto foreign = post("status", wire::parse(R"({"requestId":"commit"})"));
    foreign.headers[1].second = "droidvm-session=" + other.token; foreign.headers[3].second = other.session.csrf;
    auto foreign_body = wire::parse(foreign.body); foreign_body["context"]["sessionId"] = other.session.id; foreign.body = wire::stringify(foreign_body);
    require(wire::parse(api.handle(foreign).body)["task"].isNull());
    const std::string file = "/api/v1/configuration-backup/file";
    require(api.handle(request("HEAD", file)).status == 405 && opens == 0);
    auto range = request("GET", file); range.headers.emplace_back("Range", "bytes=0-1");
    require(api.handle(range).status == 416 && opens == 0);
    auto download = api.handle(request("GET", file));
    require(download.status == 200 && download.stream && download.body.empty() && opens == 1);
    require(download.stream->read(0, 3) == "abc" && reads == 1);
    sessions.revoke(local, grant.session.id);
    try { (void)download.stream->read(0, 3); require(false); } catch (const ServiceError&) {}
    require(reads == 1);
    tasks.shutdown();
}
}
int main() {
    try { contract(); std::cout << "backup configuration contract passed\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
