// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/http_api.h"
#include <iostream>
#include <stdexcept>

using namespace droidvm::web;
namespace {
void require(bool value) { if (!value) throw std::runtime_error("Static asset contract failed"); }
std::string header(const HttpResponse& response, std::string_view name) {
    for (const auto& [key, value] : response.headers) if (key == name) return value;
    return {};
}
}
int main() {
    try {
        const StaticAsset assets[] = {
            {"/index.html", "text/html; charset=utf-8", "\"index-hash\"", "<html></html>", "compressed-index"},
            {"/assets/index-abcdefgh.js", "text/javascript; charset=utf-8", "\"js-hash\"", "console.log(1)", ""}
        };
        SessionStore sessions;
        HttpApi api(sessions, {{"127.0.0.1:8080", "http://127.0.0.1:8080"}},
            [](const auto&) -> Json::Value { throw std::runtime_error("Static access must not read VMs"); }, {"fixture-epoch", {"fixture", "1"}}, assets);
        HttpRequest request{"GET", "/", {{"Host", "127.0.0.1:8080"}}, {}};
        auto response = api.handle(request);
        require(response.status == 200 && response.body == assets[0].body);
        require(header(response, "Content-Type") == assets[0].type && header(response, "Cache-Control") == "no-cache");
        require(header(response, "X-Content-Type-Options") == "nosniff" && header(response, "Set-Cookie").empty());
        require(header(response, "Content-Security-Policy").find("frame-ancestors 'none'") != std::string::npos);
        request.method = "HEAD"; require(api.handle(request).status == 200); request.method = "GET";
        request.headers.emplace_back("Accept-Encoding", "gzip");
        response = api.handle(request);
        require(response.body == assets[0].gzip && header(response, "Content-Encoding") == "gzip");
        require(header(response, "ETag") == "\"index-hash-gzip\"" && header(response, "Vary") == "Accept-Encoding");
        request.headers.emplace_back("If-None-Match", "\"other\", W/\"index-hash-gzip\"");
        response = api.handle(request); require(response.status == 304 && response.body.empty());
        request.headers.back().second = "\"index-hash\""; require(api.handle(request).status == 200);
        request.headers.emplace_back("if-none-match", "*"); require(api.handle(request).status == 400);
        request.headers.pop_back(); request.headers.pop_back();
        request.headers.back().second = "gzip;q=0";
        require(api.handle(request).body == assets[0].body);
        request.headers.back().second = "*;q=0"; require(api.handle(request).status == 406);
        request.headers.back().second = "gzip;q=0.8, identity;q=0.5"; require(api.handle(request).body == assets[0].gzip);
        request.headers.back().second = "gzip;q=nan"; require(api.handle(request).body == assets[0].body);
        request.headers.pop_back();
        request.path = "/assets/index-abcdefgh.js";
        response = api.handle(request); require(response.status == 200 && header(response, "Cache-Control").ends_with("immutable"));
        for (const auto* path : {"/api/v1/missing", "/api/v1/vms?token=x", "/../index.html", "/%2e%2e/index.html", "/assets/../../secret", "/index.html?token=x", "/dev.html", "/.env", "/assets/missing.js", "/vms"}) {
            request.path = path; require(api.handle(request).status == 404);
        }
        request.path = "/api/v1/vms"; require(api.handle(request).status == 401);
        request.path = "/"; request.headers[0].second = "evil.invalid"; require(api.handle(request).status == 403);
        request.headers[0].second = "127.0.0.1:8080";
        request.headers.emplace_back("Origin", "http://evil.invalid"); require(api.handle(request).status == 403);
        request.headers.back().second = "http://127.0.0.1:8080";
        request.method = "POST"; response = api.handle(request);
        require(response.status == 405 && header(response, "Allow") == "GET, HEAD");
        request.method = "GET"; request.body = "x"; require(api.handle(request).status == 400);
        std::cout << "PASS static asset routing, origin, methods, MIME, cache, compression and API isolation\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
