// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/package_transfers.h"
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
    if (!value) throw std::runtime_error("Package transfer contract failed at line " + std::to_string(at.line()));
}
template<class Work> void rejected(ErrorCode code, Work work) {
    try { work(); } catch (const ServiceError& error) { require(error.code() == code); return; }
    throw std::runtime_error("Expected transfer rejection");
}
Json::Value raw(const std::string& id, bool download) {
    auto result = wire::parse(R"({"id":"id","kind":"upload","state":"receiving","files":[{"index":0,"name":"guest.vmpkg","size_bytes":"3","offset_bytes":"0"}],"limits":{"max_files":1000,"max_file_bytes":"68719476736","max_session_bytes":"137438953472","max_total_bytes":"137438953472","chunk_bytes":262144,"ttl_ms":7200000},"private":"PRIVATE_PATH"})");
    result["id"] = id;
    if (download) {
        result["kind"] = "download"; result["state"] = "ready";
        result["files"][0]["offset_bytes"] = "3"; result["files"][0]["name"] = "a\"\xC3\xA9.vmpkg";
    }
    return result;
}
void contract() {
    TaskService tasks;
    SessionStore sessions;
    const CallContext local{"local-admin", true, true, true};
    const auto grant = sessions.exchange(sessions.issue_pairing(local).token);
    const auto caller = grant.session.caller;
    Json::Value upload, download;
    size_t appends = 0, opens = 0, reads = 0;
    bool deleted = false;
    PackageTransferBindings bindings;
    bindings.begin_upload = [&](const CallContext&, const std::string& id, const std::vector<PackageTransferFile>& files) {
        require(files.size() == 1 && files[0].name == "guest.vmpkg" && files[0].size == 3);
        upload = raw(id, false); return upload;
    };
    bindings.status = [&](const CallContext& actual, const std::string& id) {
        if (actual.principal != caller.principal || deleted) throw ServiceError(ErrorCode::not_found, "Transfer not found");
        if (upload["id"] == id) return upload;
        if (download["id"] == id) return download;
        throw ServiceError(ErrorCode::not_found, "Transfer not found");
    };
    bindings.append = [&](const CallContext&, const std::string& id, size_t index, uint64_t offset, std::string_view bytes) {
        require(id == "upload" && index == 0 && offset == 0 && bytes == "abc");
        ++appends; upload["files"][0]["offset_bytes"] = "3"; return upload;
    };
    bindings.finish = [&](const CallContext&, const std::string&) {
        upload["state"] = "ready"; upload["master_path"] = "/cache/random/guest.vmpkg"; return upload;
    };
    bindings.erase = [&](const CallContext&, const std::string&) { deleted = true; };
    bindings.prepare_download = [&](const CallContext&, const std::string& id, const Json::Value& result) {
        require(result["native"] == "PRIVATE_PATH"); download = raw(id, true); return download;
    };
    bindings.open_download = [&](const CallContext&, const std::string&, size_t index) {
        require(index == 0); ++opens;
        auto stream = std::make_shared<HttpStreamBody>(); stream->length = 3;
        stream->read = [&](uint64_t offset, size_t maximum) {
            ++reads; require(offset <= 3 && maximum <= 3 - offset); return std::string("abc").substr(static_cast<size_t>(offset), maximum);
        };
        return stream;
    };
    ResourceCatalogs resources; resources.package_transfers = package_transfers(tasks, bindings);
    HttpApi api(sessions, {{"127.0.0.1:8080", "http://127.0.0.1:8080"}}, [](const CallContext&) { return Json::Value(); },
        {"epoch", {"test", "1"}}, {}, {}, {}, {}, false, {}, resources);
    auto request = [&](std::string method, std::string path, Json::Value body = {}) {
        HttpRequest req{method, std::move(path), {{"Host", "127.0.0.1:8080"}, {"Cookie", "droidvm-session=" + grant.token}}, {}};
        if (method == "POST" || method == "DELETE") {
            req.headers.emplace_back("Origin", "http://127.0.0.1:8080");
            req.headers.emplace_back("X-DroidVM-CSRF", grant.session.csrf);
        }
        if (!body.isNull()) { req.headers.emplace_back("Content-Type", "application/json"); req.body = wire::stringify(body); }
        return req;
    };
    const auto capabilities = wire::parse(api.handle(request("GET", "/api/v1/capabilities")).body);
    bool enabled = false; for (const auto& cap : capabilities["server"]["capabilities"]) enabled |= cap == "packages.transfer.v1";
    require(enabled);
    auto begin = wire::parse(R"({"requestId":"upload","files":[{"name":"guest.vmpkg","sizeBytes":"3"}]})");
    begin["context"] = capabilities["context"];
    auto denied = request("POST", "/api/v1/package-uploads", begin); denied.headers.erase(denied.headers.begin() + 3);
    require(api.handle(denied).status == 403);
    const auto started = api.handle(request("POST", "/api/v1/package-uploads", begin));
    require(started.status == 200 && started.body.find("PRIVATE_PATH") == std::string::npos);
    auto chunk = wire::parse(R"({"index":0,"offset":"0","data":"YWJj"})"); chunk["context"] = capabilities["context"];
    require(api.handle(request("POST", "/api/v1/package-uploads/upload/chunks", chunk)).status == 200 && appends == 1);
    chunk["offset"] = "00";
    require(api.handle(request("POST", "/api/v1/package-uploads/upload/chunks", chunk)).status == 400 && appends == 1);
    chunk["offset"] = "0"; chunk["data"] = "!!!!";
    require(api.handle(request("POST", "/api/v1/package-uploads/upload/chunks", chunk)).status == 400 && appends == 1);
    Json::Value finish; finish["context"] = capabilities["context"];
    const auto completed = api.handle(request("POST", "/api/v1/package-uploads/upload/finish", finish));
    require(completed.status == 200 && wire::parse(completed.body)["transfer"]["source"] == "/cache/random/guest.vmpkg");
    rejected(ErrorCode::not_found, [&] { resources.package_transfers.uploads.status({"foreign", true, true, true}, "upload"); });

    TaskSpec spec{"vm_export", "package", 1024}; spec.request_id = "export"; spec.request_signature = "export";
    const auto exported = tasks.submit(caller, spec, [](TaskControl&) { Json::Value result; result["native"] = "PRIVATE_PATH"; return TaskCompletion::success(result); });
    const auto end = TaskService::Clock::now() + 5s;
    while (!task_terminal(tasks.get(caller, exported).state) && TaskService::Clock::now() < end) std::this_thread::sleep_for(1ms);
    require(tasks.get(caller, exported).state == TaskState::succeeded);
    Json::Value preparation; preparation["context"] = capabilities["context"]; preparation["requestId"] = "download"; preparation["exportRequestId"] = "export";
    require(api.handle(request("POST", "/api/v1/package-downloads", preparation)).status == 200);
    const std::string file = "/api/v1/package-downloads/download/files/0";
    require(api.handle(request("HEAD", file)).status == 405 && opens == 0);
    auto range = request("GET", file); range.headers.emplace_back("Range", "bytes=1-");
    require(api.handle(range).status == 416 && opens == 0);
    auto foreign = request("GET", file); foreign.headers.emplace_back("Origin", "http://foreign.invalid");
    require(api.handle(foreign).status == 403 && opens == 0);
    auto response = api.handle(request("GET", file)); // Browser navigation has no Origin.
    require(response.status == 200 && response.body.empty() && response.stream && response.stream->length == 3 && opens == 1);
    bool attachment = false;
    for (const auto& [key, value] : response.headers) if (key == "Content-Disposition") attachment = value.find("%22%C3%A9") != std::string::npos;
    require(attachment && response.stream->read(0, 3) == "abc" && reads == 1);
    sessions.revoke(local, grant.session.id);
    rejected(ErrorCode::unauthenticated, [&] { response.stream->read(0, 3); });
    require(reads == 1); // Revocation is checked before the next backend read.
    resources.package_transfers.downloads.erase(caller, "download"); require(deleted);
}
}
int main() {
    try { contract(); std::cout << "Package transfer API contract passed\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
