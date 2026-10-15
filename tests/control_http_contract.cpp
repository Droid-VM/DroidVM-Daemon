// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "network/control_http.h"
#include "network/links.h"
#include "runtime/managed_process.h"
#include "common/identity.h"
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <future>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

using namespace droidvm;
using namespace droidvm::network;
using namespace droidvm::test;
namespace {
const std::string token = "contract-secret-token";
std::string work = "/data/local/tmp", binaries;
template<class F> void failure(ControlFailure expected, F&& fn) {
    try { fn(); } catch (const ControlError& e) {
        check(e.reason == expected, e.what());
        check(std::string_view(e.what()).find(token) == std::string_view::npos, "credential absent from diagnostic");
        return;
    }
    throw std::runtime_error("expected control request failure");
}
bool send_bytes(int fd, std::string_view bytes) {
    while (!bytes.empty()) {
        const auto n = send(fd, bytes.data(), bytes.size(), MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        bytes.remove_prefix(n);
    }
    return true;
}
struct Server {
    std::string path = work + "/h" + random_id(false).substr(0, 10);
    Fd listener{socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)};
    std::future<void> worker;
    Server(std::function<void(int)> serve, size_t requests = 1) {
        check(path.size() < sizeof(sockaddr_un::sun_path), "fixture socket path length");
        sockaddr_un addr{}; addr.sun_family = AF_UNIX;
        std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
        check(bind(listener.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0, "bind fixture");
        check(listen(listener.get(), 8) == 0, "listen fixture");
        worker = std::async(std::launch::async, [this, serve, requests] {
            for (size_t i = 0; i < requests; ++i) {
                pollfd ready{listener.get(), POLLIN, 0};
                check(poll(&ready, 1, 3000) > 0, "fixture accept deadline");
                Fd peer(accept4(listener.get(), nullptr, nullptr, SOCK_CLOEXEC));
                check(peer.get() >= 0, "accept fixture");
                timeval timeout{3, 0};
                setsockopt(peer.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                setsockopt(peer.get(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
                serve(peer.get());
            }
        });
    }
    ~Server() { if (worker.valid()) worker.wait(); unlink(path.c_str()); }
    void finish() { worker.get(); }
};
std::string request_head(int fd) {
    std::string data;
    while (!data.ends_with("\r\n\r\n")) {
        char c;
        check(recv(fd, &c, 1, 0) == 1 && data.size() < 16384, "fixture request header");
        data += c;
    }
    check(data.find("Authorization: Bearer " + token + "\r\n") != std::string::npos, "bearer authentication");
    check(data.find("Connection: close\r\n") != std::string::npos, "per-request connection");
    return data;
}
ControlResponse response(std::string bytes, bool fragmented = false) {
    Server server([&](int fd) {
        request_head(fd);
        if (fragmented) { for (char c : bytes) if (!send_bytes(fd, std::string_view(&c, 1))) break; }
        else send_bytes(fd, bytes);
    });
    auto result = ControlHttp(server.path, token).request(HttpMethod::get, "/api/v1/ports");
    server.finish(); return result;
}
void valid_framing_and_methods() {
    const std::string body = "{\"name\":\"网络🌏\"}";
    auto result = response("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\ncOnTeNt-LeNgTh: " +
        std::to_string(body.size()) + "\r\n\r\n" + body, true);
    check(result.success() && result.body == body, "interim, mixed-case header and fragmented UTF8 body");
    result = response("HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n3;x=\"a\\\"b\"\r\nabc\r\n2;y=z\r\nde\r\n0\r\nX-End: yes\r\n\r\n", true);
    check(result.body == "abcde", "chunk extensions, trailers and boundaries");
    result = response("HTTP/1.0 404 Not Found\r\nX-Test: yes\r\n\r\nmissing");
    check(!result.success() && result.code == 404 && result.body == "missing", "EOF framing and status preserved");
    check(response("HTTP/1.1 204 No Content\r\n\r\n").body.empty(), "204 no body");
    check(response("HTTP/1.1 304 Not Modified\r\nContent-Length: 99\r\n\r\n").body.empty(), "304 representation length is not a body");
    for (auto method : {HttpMethod::post, HttpMethod::put, HttpMethod::remove}) {
        Server server([&](int fd) {
            const auto head = request_head(fd);
            const char* verb = method == HttpMethod::post ? "POST" : method == HttpMethod::put ? "PUT" : "DELETE";
            check(head.starts_with(std::string(verb) + " /x HTTP/1.1\r\n"), "request method and path");
            check(head.find("Content-Length: " + std::to_string(body.size()) + "\r\n") != std::string::npos, "UTF8 byte content length");
            std::string received(body.size(), '\0');
            size_t n = 0;
            while (n < received.size()) { const auto count = recv(fd, received.data() + n, received.size() - n, 0); check(count > 0, "request body read"); n += count; }
            check(received == body, "body unchanged");
            send_bytes(fd, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        });
        check(ControlHttp(server.path, token).request(method, "/x", body).success(), "mutation response"); server.finish();
    }
    check(ControlHttp::component("a/网络 %?") == "a%2F%E7%BD%91%E7%BB%9C%20%25%3F", "opaque path escaping");
}
void malformed_and_truncated() {
    for (const auto& bytes : {
        "HTTP/1.1 200 OK\n\n", "HTTP/1.1 20x OK\r\n\r\n", "HTTP/1.1 101 Upgrade\r\n\r\n",
        "HTTP/1.1 204 OK\r\nContent-Length: 0\r\n\r\n", "HTTP/1.1 200 OK\r\n Bad: fold\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nab",
        "HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\n\r\nab", "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nab", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nx",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nxQ\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;x=\"bad\r\nx\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 0\r\n\r\n"
    }) failure(ControlFailure::protocol, [&] { response(bytes); });
}
void limits_and_injection() {
    const auto too_large = std::to_string(ControlHttp::response_limit + 1);
    failure(ControlFailure::limit, [&] { response("HTTP/1.1 200 OK\r\nContent-Length: " + too_large + "\r\n\r\n"); });
    failure(ControlFailure::limit, [&] { response("HTTP/1.1 200 OK\r\n\r\n" + std::string(ControlHttp::response_limit + 1, 'x')); });
    failure(ControlFailure::limit, [&] { response("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n200001\r\n"); });
    failure(ControlFailure::limit, [&] { response("HTTP/1.1 200 OK\r\nX: " + std::string(8192, 'x') + "\r\n\r\n"); });
    std::string headers = "HTTP/1.1 200 OK\r\n";
    for (int i = 0; i < 5000; ++i) headers += "X: y\r\n";
    failure(ControlFailure::limit, [&] { response(headers); });
    std::string chunks = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    for (int i = 0; i < 14000; ++i) chunks += "1\r\nx\r\n";
    failure(ControlFailure::limit, [&] { response(chunks); });
    std::string interim;
    for (int i = 0; i < 9; ++i) interim += "HTTP/1.1 100 Continue\r\n\r\n";
    failure(ControlFailure::limit, [&] { response(interim); });
    ControlHttp client("/does/not/exist", token);
    for (const auto* path : {"/x\r\nAuthorization: bad", "/a b", "/x#fragment", "http://host/", "/\\x"})
        failure(ControlFailure::invalid_request, [&] { client.request(HttpMethod::get, path); });
    failure(ControlFailure::invalid_request, [&] { ControlHttp("/x", "secret\r\nInjected: yes"); });
    failure(ControlFailure::invalid_request, [&] { ControlHttp(std::string(200, '/'), token); });
    failure(ControlFailure::limit, [&] { client.request(HttpMethod::post, "/x", std::string(ControlHttp::request_limit + 1, 'x')); });
    failure(ControlFailure::io, [&] { client.request(HttpMethod::get, "/x"); });
}
void deadline_and_cancellation() {
    for (const bool drip : {false, true}) {
        Server server([&](int fd) {
            request_head(fd);
            if (drip) for (char c : std::string("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")) {
                if (!send_bytes(fd, std::string_view(&c, 1))) break;
                std::this_thread::sleep_for(20ms);
            }
            else std::this_thread::sleep_for(180ms);
        });
        const auto start = std::chrono::steady_clock::now();
        failure(ControlFailure::timeout, [&] { ControlHttp(server.path, token).request(HttpMethod::get, "/", {}, {80ms, {}}); });
        check(std::chrono::steady_clock::now() - start < 500ms, "whole response deadline despite progress"); server.finish();
    }
    Server server([](int fd) { request_head(fd); std::this_thread::sleep_for(180ms); });
    const auto start = std::chrono::steady_clock::now();
    failure(ControlFailure::cancelled, [&] {
        ControlHttp(server.path, token).request(HttpMethod::get, "/", {}, {2s, [&] { return std::chrono::steady_clock::now() - start >= 60ms; }});
    });
    server.finish();
    // Peer accepts but never reads: the same deadline covers request writes.
    Server blocked([](int) { std::this_thread::sleep_for(180ms); });
    failure(ControlFailure::timeout, [&] { ControlHttp(blocked.path, token).request(HttpMethod::post, "/", std::string(ControlHttp::request_limit, 'x'), {80ms, {}}); });
    blocked.finish();
}
size_t descriptor_count() {
    DIR* dir = opendir("/proc/self/fd"); check(dir, "open FD inventory");
    size_t count = 0;
    while (const auto* entry = readdir(dir)) if (entry->d_name[0] != '.') ++count;
    closedir(dir); return count;
}
void concurrent_connections_and_fd_cleanup() {
    const auto before = descriptor_count();
    {
        Server server([](int fd) {
            const auto head = request_head(fd);
            send_bytes(fd, head.starts_with("GET /ok ") ?
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}" : "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nx");
        }, 64);
        const ControlHttp shared(server.path, token);
        std::vector<std::future<void>> clients;
        for (int i = 0; i < 4; ++i) clients.push_back(std::async(std::launch::async, [&] {
            for (int j = 0; j < 8; ++j) {
                check(shared.request(HttpMethod::get, "/ok").body == "{}", "shared immutable client concurrent request");
                failure(ControlFailure::protocol, [&] { shared.request(HttpMethod::get, "/bad"); });
            }
        }));
        for (auto& client : clients) client.get();
        server.finish();
    }
    check(descriptor_count() == before, "success and failure close every connection FD");
    {
        Server server([](int fd) {
            request_head(fd);
            send_bytes(fd, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
            std::this_thread::sleep_for(180ms);
        });
        check(ControlHttp(server.path, token).request(HttpMethod::get, "/", {}, {80ms, {}}).body == "{}",
            "framed response completes without waiting for peer close");
        server.finish();
    }
    failure(ControlFailure::cancelled, [&] {
        ControlHttp("/absent", token).request(HttpMethod::post, "/", {}, {2s, [] { return true; }});
    });
    check(descriptor_count() == before, "early cancellation releases FD");
}
void write_file(const std::string& path, std::string_view bytes) {
    Fd fd(open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
    check(fd.get() >= 0, "create private helper config");
    while (!bytes.empty()) { const auto n = write(fd.get(), bytes.data(), bytes.size()); check(n > 0, "write helper config"); bytes.remove_prefix(n); }
}
void ready(ManagedProcess& process, const ControlHttp& client, const char* path) {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline) {
        check(process.status().running, "real helper remains running during startup");
        try { if (client.request(HttpMethod::get, path, {}, {200ms, {}}).success()) return; }
        catch (const ControlError& e) { if (e.reason != ControlFailure::io && e.reason != ControlFailure::timeout) throw; }
        std::this_thread::sleep_for(20ms);
    }
    throw std::runtime_error("real helper readiness deadline");
}
void real_gvswitch() {
    const auto path = work + "/gv";
    check(mkdir(path.c_str(), 0700) == 0, "unique gvswitch test directory");
    write_file(path + "/config", R"({"gateways":[{"vlan":0,"enable_internet_routing":false,"ipv4":{"address":"192.0.2.1","prefix_len":24},"dhcp4":{"enabled":true,"pool_start":"192.0.2.10","pool_end":"192.0.2.20"}}]})");
    Fd directory(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    Netbox netbox(binaries + "/netbox");
    OwnedLinks links(directory.get(), getuid(), netbox);
    const auto tap = "gc" + random_id(false).substr(0, 8);
    ManagedProcess process;
    ChildOptions options; options.argv = {binaries + "/gvswitch", "-listen", path + "/s", "-auth-token", token, "-config", path + "/config"};
    process.start(options);
    ControlHttp client(path + "/s", token);
    ready(process, client, "/api/v1/ports");
    try {
        links.tap("control-test", tap); netbox.state(tap, true);
        Json::Value port;
        port["identifier"] = tap; port["vlan"] = 0; port["mode"] = "client";
        port["transport"] = "af_xdp"; port["interface"] = tap; port["bpdu_guard"] = true;
        check(client.request(HttpMethod::post, "/api/v1/ports", wire::stringify(port)).success(), "real gvswitch AF_XDP port POST");
        auto ports = wire::parse(client.request(HttpMethod::get, "/api/v1/ports").body);
        check(ports.isArray() && ports.size() == 1 && ports[0]["identifier"] == tap, "real created port read back");
        check(client.request(HttpMethod::remove, "/api/v1/ports/" + ControlHttp::component(tap)).success(), "real gvswitch port DELETE");
        check(wire::parse(client.request(HttpMethod::get, "/api/v1/ports").body).empty(), "real deleted port absent");
        check(links.cleanup("control-test").empty(), "remove owned gvswitch TAP");
    } catch (...) {
        process.stop(); links.cleanup("control-test"); throw;
    }
    auto unauthorized = ControlHttp(path + "/s", "wrong").request(HttpMethod::get, "/api/v1/ports");
    check(unauthorized.code == 401 || unauthorized.code == 403, "real gvswitch rejects wrong token");
    check(wire::parse(client.request(HttpMethod::get, "/api/v1/ports").body).isArray(), "real gvswitch ports schema");
    const std::string endpoint = "/api/v1/gateways/0/dhcp4/static/probe";
    check(client.request(HttpMethod::put, endpoint, R"({"id":"probe","mac":"02:00:00:12:34:56","ip":"192.0.2.15"})").success(), "real gvswitch static lease PUT");
    check(client.request(HttpMethod::get, "/api/v1/gateways/0/dhcp4/leases").success(), "real gvswitch lease query");
    check(client.request(HttpMethod::remove, endpoint).success(), "real gvswitch static lease DELETE");
    check(!client.request(HttpMethod::post, "/api/v1/ports", "{}").success(), "real gvswitch invalid port rejected");
    check(client.request(HttpMethod::get, "/contract-missing").code == 404, "real gvswitch 404 preserved");
    process.stop();
    check(!process.status().running, "real gvswitch stopped");
    for (const char* name : {"s", "config", "network-links.json", "network-links.json.bak"}) unlinkat(directory.get(), name, 0);
    check(rmdir(path.c_str()) == 0, "gvswitch test files removed");
}
void real_bridgedhcp() {
    const auto path = work + "/dh";
    check(mkdir(path.c_str(), 0700) == 0, "unique bridgedhcp test directory");
    Fd dir(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    Netbox netbox(binaries + "/netbox");
    OwnedLinks links(dir.get(), getuid(), netbox);
    const auto bridge = "dh" + random_id(false).substr(0, 8);
    links.bridge("control-test", bridge); netbox.state(bridge, true);
    // DHCP is configured on a dedicated empty bridge, with no host uplink,
    // forwarding or PD. No existing network interface is configured.
    Json::Value config;
    config["api_socket"] = path + "/s"; config["api_key_file"] = path + "/key"; config["state_file"] = path + "/state";
    Json::Value iface;
    iface["name"] = bridge; iface["tag"] = "0"; iface["prefix4"] = "192.0.2.1/24";
    iface["dhcp4"]["pool_offset_start"] = 10; iface["dhcp4"]["pool_offset_end"] = 20;
    iface["dhcp4"]["lease_time"] = "12h";
    config["interfaces"].append(iface);
    write_file(path + "/key", token); write_file(path + "/config", wire::stringify(config));
    ManagedProcess process;
    try {
        ChildOptions options; options.argv = {binaries + "/bridgedhcp", "--config", path + "/config"};
        process.start(options);
        ControlHttp client(path + "/s", token);
        ready(process, client, "/v1/status");
        const auto status = wire::parse(client.request(HttpMethod::get, "/v1/status").body);
        check(status["ifaces"].isArray() && status["ifaces"].size() == 1, "real bridgedhcp interface status");
        const auto unauthorized = ControlHttp(path + "/s", "wrong").request(HttpMethod::get, "/v1/status");
        check(unauthorized.code == 401 || unauthorized.code == 403, "real bridgedhcp rejects wrong token");
        const auto endpoint = "/v1/ifaces/" + ControlHttp::component(bridge);
        check(client.request(HttpMethod::put, endpoint + "/statics/4", R"({"statics":[{"id":"probe","mac":"02:00:00:12:34:56","offset":15}]})").success(), "real bridgedhcp static lease PUT");
        check(client.request(HttpMethod::get, endpoint + "/leases/4").success(), "real bridgedhcp leases query");
        check(client.request(HttpMethod::put, endpoint + "/statics/4", R"({"statics":[]})").success(), "real bridgedhcp static lease removal");
        check(!client.request(HttpMethod::post, endpoint + "/pd/renew").success(), "real bridgedhcp rejects PD on non-PD interface");
        process.stop();
    } catch (...) {
        process.stop(); links.cleanup("control-test"); throw;
    }
    check(links.cleanup("control-test").empty(), "remove owned DHCP bridge");
    for (const char* name : {"s", "key", "config", "state", "network-links.json", "network-links.json.bak"}) unlinkat(dir.get(), name, 0);
    check(rmdir(path.c_str()) == 0, "bridgedhcp test files removed");
}
}
int main(int argc, char** argv) {
    if (argc == 3) { binaries = argv[1]; work = argv[2]; }
    if (!binaries.empty()) return run({{"real_gvswitch_control", real_gvswitch}, {"real_bridgedhcp_control", real_bridgedhcp}});
    return run({{"framing_and_methods", valid_framing_and_methods}, {"malformed_and_truncated", malformed_and_truncated},
        {"limits_and_injection", limits_and_injection}, {"whole_request_deadline_and_cancel", deadline_and_cancellation},
        {"concurrent_connections_and_fd_cleanup", concurrent_connections_and_fd_cleanup}});
}
