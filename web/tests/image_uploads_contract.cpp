// SPDX-License-Identifier: GPL-3.0-or-later
#include "image_upload_fixture.h"
#include <chrono>
#include <iostream>
#include <source_location>
#include <thread>

using namespace droidvm;
using namespace droidvm::web;
using namespace std::chrono_literals;
namespace {
void require(bool value, const std::source_location& at = std::source_location::current()) {
    if (!value) throw std::runtime_error("Image upload contract failed at line " + std::to_string(at.line()));
}
void contract() {
    TaskLimits limits; limits.background_workers = 1; TaskService tasks(limits);
    SessionStore sessions; const CallContext local{"local-admin", true, true, true};
    const auto grant = sessions.exchange(sessions.issue_pairing(local).token);
    auto storage = std::make_shared<FixtureImageUploads>();
    ResourceCatalogs resources; resources.image_uploads = image_uploads(tasks, storage->bindings());
    HttpApi api(sessions, {{"127.0.0.1:8080", "http://127.0.0.1:8080"}}, [](const CallContext&) { return Json::Value(); },
        {"epoch", {"test", "1"}}, {}, {}, {}, {}, false, {}, resources);
    auto request = [&](std::string method, std::string path, Json::Value body = {}) {
        HttpRequest req{method, std::move(path), {{"Host", "127.0.0.1:8080"}, {"Cookie", "droidvm-session=" + grant.token}}, {}};
        if (method == "POST" || method == "DELETE") {
            req.headers.emplace_back("Origin", "http://127.0.0.1:8080"); req.headers.emplace_back("X-DroidVM-CSRF", grant.session.csrf);
        }
        if (!body.isNull()) { req.headers.emplace_back("Content-Type", "application/json"); req.body = wire::stringify(body); }
        return req;
    };
    const auto caps = wire::parse(api.handle(request("GET", "/api/v1/capabilities")).body);
    bool enabled = false; for (const auto& cap : caps["server"]["capabilities"]) enabled |= cap == "images.upload.v1";
    require(enabled);
    const std::string uploads = "/api/v1/image-uploads", installs = "/api/v1/image-installs";
    auto post = [&](const std::string& path, Json::Value body) { body["context"] = caps["context"]; return request("POST", path, body); };
    auto begin = wire::parse(R"({"requestId":"upload","files":[{"name":"guest.qcow2","sizeBytes":"3"}]})");
    auto denied = post(uploads, begin); denied.headers.erase(denied.headers.begin() + 3);
    require(api.handle(denied).status == 403);
    auto stale = post(uploads, begin); auto stale_body = wire::parse(stale.body); stale_body["context"]["daemonEpoch"] = "stale"; stale.body = wire::stringify(stale_body);
    require(api.handle(stale).status == 409);
    auto extra = begin; extra["files"].append(begin["files"][0]);
    require(api.handle(post(uploads, extra)).status == 400);
    auto started = api.handle(post(uploads, begin)); require(started.status == 200 && started.body.find("private") == std::string::npos);
    require(api.handle(post(uploads + "/upload/finish", Json::Value(Json::objectValue))).status == 409);
    auto chunk = wire::parse(R"({"index":0,"offset":"0","data":"YWJj"})");
    auto wrong_index = chunk; wrong_index["index"] = 1;
    require(api.handle(post(uploads + "/upload/chunks", wrong_index)).status == 400);
    auto wrong_offset = chunk; wrong_offset["offset"] = "00";
    require(api.handle(post(uploads + "/upload/chunks", wrong_offset)).status == 400);
    require(api.handle(post(uploads + "/upload/chunks", chunk)).status == 200);
    const auto observed = api.handle(request("GET", uploads + "/upload"));
    require(wire::parse(observed.body)["transfer"]["files"][0]["offsetBytes"] == "3" && storage->stats()["chunks"].asUInt64() == 1);
    require(api.handle(post(uploads + "/upload/chunks", chunk)).status == 409 && storage->stats()["chunks"].asUInt64() == 1);
    const auto ready = api.handle(post(uploads + "/upload/finish", Json::Value(Json::objectValue)));
    require(ready.status == 200 && !wire::parse(ready.body)["transfer"].isMember("source") && ready.body.find("/cache") == std::string::npos);
    try { resources.image_uploads.uploads.status({"foreign", true, true, true}, "upload"); require(false); }
    catch (const ServiceError& error) { require(error.code() == ErrorCode::not_found); }
    auto raw = storage->bindings().status(grant.session.caller, "upload");
    try { (void)project_package_transfer(raw, "upload"); require(false); }
    catch (const ServiceError& error) { require(error.code() == ErrorCode::internal); }
    auto finish = [&](const std::string& id) {
        const auto deadline = std::chrono::steady_clock::now() + 5s;
        do {
            const auto response = api.handle(request("GET", installs + "/" + id)); require(response.status == 200);
            require(response.body.find("private") == std::string::npos);
            auto value = wire::parse(response.body)["task"];
            if (value["state"] == "succeeded" || value["state"] == "failed" || value["state"] == "cancelled") return value;
            std::this_thread::sleep_for(1ms);
        } while (std::chrono::steady_clock::now() < deadline);
        throw std::runtime_error("Image install did not finish");
    };
    auto install = wire::parse(R"({"requestId":"install","uploadId":"upload","folder":"/fixture","name":"guest.qcow2"})");
    require(api.handle(post(installs, install)).status == 202);
    const auto done = finish("install");
    require(done["state"] == "succeeded" && done["kind"] == "image_install" && done["resource"] == "image");
    require(done["imageInstall"]["source"] == "/fixture/guest.qcow2" && done["imageInstall"]["durabilityConfirmed"].asBool());
    require(api.handle(post(installs, install)).status == 202 && storage->stats()["installs"].asUInt64() == 1);
    auto changed = install; changed["name"] = "different.qcow2";
    require(api.handle(post(installs, changed)).status == 409 && storage->stats()["installs"].asUInt64() == 1);
    auto repeated = install; repeated["requestId"] = "another-install";
    require(api.handle(post(installs, repeated)).status == 202 && finish("another-install")["state"] == "failed" && storage->stats()["installs"].asUInt64() == 1);
    begin["requestId"] = "uncertain-upload";
    require(api.handle(post(uploads, begin)).status == 200);
    require(api.handle(post(uploads + "/uncertain-upload/chunks", chunk)).status == 200);
    require(api.handle(post(uploads + "/uncertain-upload/finish", Json::Value(Json::objectValue))).status == 200);
    install["requestId"] = "uncertain-install"; install["uploadId"] = "uncertain-upload"; install["name"] = "uncertain.qcow2";
    require(api.handle(post(installs, install)).status == 202);
    const auto uncertain = finish("uncertain-install");
    require(uncertain["state"] == "failed" && uncertain["errorCode"] == "COMMIT_UNCERTAIN");
    require(uncertain["imageInstall"]["installationUncertain"].asBool() && uncertain["imageInstall"]["recoveryRequired"].asBool());
    require(!uncertain["imageInstall"]["durabilityConfirmed"].asBool() && storage->stats()["installs"].asUInt64() == 2);
    require(wire::parse(api.handle(request("GET", installs + "/unknown-request")).body)["task"].isNull());
    require(api.handle(request("DELETE", uploads + "/upload")).status == 204);
    require(api.handle(request("GET", uploads + "/upload")).status == 404);
    require(HttpApi::request_limit(uploads + "/upload/chunks") == (384u << 10));
}
}
int main() {
    try { contract(); std::cout << "Image upload API contract passed\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
