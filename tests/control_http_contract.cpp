// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "network/control_http.h"
#include "network/links.h"
#include "network/helper_config.h"
#include "services/network_config.h"
#include "services/network.h"
#include "network/gvswitch.h"
#include "runtime/managed_process.h"
#include "runtime/helper_identity.h"
#include "common/identity.h"
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <future>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <signal.h>

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
    auto network = wire::parse(R"({"schema":2,"name":"helper contract","bridge_name":"test","bridge_type":"gvisor","l3":{"vlans":[{"vlan_id":0,"ipv4":{"cidr":"192.0.2.1/24","dhcp":{"enabled":true,"offset_start":10,"offset_end":20}}},{"vlan_id":123,"ipv6":{"cidr":"2001:db8::1/64","dhcp":{"enabled":true},"slaac":{"enabled":true}}}]}})");
    Fd directory(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    network["id"] = random_id(true);
    NetworkConfigService configs(directory.get(), getuid());
    auto lease = configs.prepare_runtime(admin, configs.create(admin, network));
    write_file(path + "/config", wire::stringify(gvswitch_config(lease->config())));
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
    check(client.request(HttpMethod::get, "/api/v1/gateways/123/dhcp6/leases").success(), "real generated second VLAN DHCP6 gateway");
    check(client.request(HttpMethod::remove, endpoint).success(), "real gvswitch static lease DELETE");
    check(!client.request(HttpMethod::post, "/api/v1/ports", "{}").success(), "real gvswitch invalid port rejected");
    check(client.request(HttpMethod::get, "/contract-missing").code == 404, "real gvswitch 404 preserved");
    process.stop();
    check(!process.status().running, "real gvswitch stopped");
    lease.reset();
    for (const char* name : {"s", "config", "networks.json", "networks.json.bak", "network-links.json", "network-links.json.bak"}) unlinkat(directory.get(), name, 0);
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
    auto network = wire::parse(R"({"schema":2,"name":"helper contract","l3":{"vlans":[{"vlan_id":0,"ipv4":{"cidr":"192.0.2.1/24","dhcp":{"enabled":true,"offset_start":10,"offset_end":20}},"ipv6":{"cidr":"2001:db8::1/64","dhcp":{"enabled":true},"slaac":{"enabled":true}}}]}})");
    network["bridge_name"] = bridge;
    network["id"] = random_id(true);
    NetworkConfigService configs(dir.get(), getuid());
    auto lease = configs.prepare_runtime(admin, configs.create(admin, network));
    netbox.mac(bridge, lease->bridge_mac());
    DhcpStatics initial;
    initial.ipv4 = wire::parse(R"([{"id":"initial4","mac":"02:00:00:12:34:56","offset":15}])");
    initial.ipv6 = wire::parse(R"([{"id":"initial6","mac":"02:00:00:12:34:56","offset":19}])");
    auto plan = bridgedhcp_config(lease->config(), {path + "/s", path + "/key", path + "/state"}, {}, {{0, initial}});
    check(plan.needed && plan.unresolved_pd.empty(), "generated DHCP helper required with no unresolved PD");
    write_file(path + "/key", token); write_file(path + "/config", wire::stringify(plan.config));
    ManagedProcess process;
    try {
        // Parse a PD plan through the real helper's validation-only mode.
        // This must not solicit a delegation or allocate any route/rule.
        auto pd_network = network;
        pd_network["id"] = "12345678-1234-1234-abcd-123456789abc";
        pd_network["name"] = "PD preparation contract";
        auto& pd_vlan = pd_network["l3"]["vlans"][0];
        pd_vlan["vlan_id"] = 2;
        pd_vlan["ipv6"]["source"] = "dhcp_pd";
        pd_vlan["ipv6"]["pd"]["uplink"] = bridge;
        pd_vlan["ipv6"]["pd"]["route_table"] = Json::Int64(4000000000LL);
        auto pd_lease = configs.prepare_runtime(admin, configs.create(admin, pd_network));
        auto pd_plan = bridgedhcp_config(pd_lease->config(), {path + "/pd-s", path + "/key", path + "/pd-state"}, {{2, bridge}});
        write_file(path + "/pd-config", wire::stringify(pd_plan.config));
        ChildOptions validate; validate.argv = {binaries + "/bridgedhcp", "--config", path + "/pd-config", "-check"};
        Child validation(validate);
        auto validated = validation.communicate({}, 3s);
        check(validated.exit_code == 0 && !validated.timed_out, "real helper validates PD configuration with unsigned IAID/table");
        ChildOptions options; options.argv = {binaries + "/bridgedhcp", "--config", path + "/config"};
        process.start(options);
        ControlHttp client(path + "/s", token);
        ready(process, client, "/v1/status");
        const auto status = wire::parse(client.request(HttpMethod::get, "/v1/status").body);
        std::cerr << "bridgedhcp generated config status: " << wire::stringify(status) << std::endl;
        check(status["ifaces"].isArray() && status["ifaces"].size() == 1, "real bridgedhcp interface status");
        const auto& iface_status = status["ifaces"][0];
        check(iface_status["exists"].asBool() && iface_status["up"].asBool() && iface_status["dhcp4"].asBool() &&
            iface_status["dhcp6"].asBool() && iface_status["slaac"].asBool(), "generated dual-stack services active on owned bridge");
        check(iface_status["mac"] == lease->bridge_mac(), "helper observes persisted bridge MAC");
        check(iface_status["statics4"].size() == 1 && iface_status["statics4"][0]["id"] == "initial4" &&
            iface_status["statics6"].size() == 1 && iface_status["statics6"][0]["id"] == "initial6", "generated static bindings read back from helper");
        const auto unauthorized = ControlHttp(path + "/s", "wrong").request(HttpMethod::get, "/v1/status");
        check(unauthorized.code == 401 || unauthorized.code == 403, "real bridgedhcp rejects wrong token");
        const auto endpoint = "/v1/ifaces/" + ControlHttp::component(bridge);
        check(client.request(HttpMethod::put, endpoint + "/statics/4", R"({"statics":[{"id":"probe","mac":"02:00:00:12:34:56","offset":15}]})").success(), "real bridgedhcp static lease PUT");
        check(client.request(HttpMethod::get, endpoint + "/leases/4").success(), "real bridgedhcp leases query");
        check(client.request(HttpMethod::get, endpoint + "/leases/6").success(), "real generated DHCP6 interface");
        check(client.request(HttpMethod::put, endpoint + "/statics/4", R"({"statics":[]})").success(), "real bridgedhcp static lease removal");
        check(wire::parse(client.request(HttpMethod::get, "/v1/status").body)["ifaces"][0]["statics4"].empty(), "removed static binding absent in helper state");
        check(!client.request(HttpMethod::post, endpoint + "/pd/renew").success(), "real bridgedhcp rejects PD on non-PD interface");
        process.stop();
    } catch (...) {
        process.stop(); links.cleanup("control-test"); throw;
    }
    check(links.cleanup("control-test").empty(), "remove owned DHCP bridge");
    lease.reset();
    for (const char* name : {"s", "key", "config", "state", "pd-config", "networks.json", "networks.json.bak", "network-links.json", "network-links.json.bak"}) unlinkat(dir.get(), name, 0);
    check(rmdir(path.c_str()) == 0, "bridgedhcp test files removed");
}
std::string switch_directory(const std::string& parent) {
    DIR* scan = opendir(parent.c_str()); check(scan, "scan isolated lifecycle directory");
    std::string found;
    while (const auto* entry = readdir(scan)) if (std::string_view(entry->d_name).starts_with("gv-")) {
        if (!found.empty()) { closedir(scan); throw std::runtime_error("ambiguous test switch directory"); }
        found = parent + "/" + entry->d_name;
    }
    closedir(scan); check(!found.empty(), "real switch created private directory"); return found;
}
void await_exit(Gvswitch& backend) {
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (backend.status().running && std::chrono::steady_clock::now() < deadline) std::this_thread::sleep_for(5ms);
    check(!backend.status().running, "owned helper death observed");
}
void real_network_lifecycle() {
    const auto path = work + "/lifecycle";
    check(mkdir(path.c_str(), 0700) == 0, "create lifecycle case directory");
    Fd dir(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    NetworkConfigService configs(dir.get(), getuid());
    auto configuration = wire::parse(R"({"schema":2,"name":"lifecycle","bridge_name":"test","bridge_type":"gvisor","l3":{"vlans":[]}})");
    configuration["id"] = random_id(true);
    const auto id = configs.create(admin, configuration);
    Gvswitch* backend = nullptr;
    bool missing = false, unready = false;
    auto now = NetworkService::Clock::now();
    NetworkService service(configs, [&](const Json::Value&) {
        auto result = std::make_unique<Gvswitch>(unready ? path + "/unready" : binaries + (missing ? "/absent-helper" : "/gvswitch"), dir.get());
        backend = result.get(); return result;
    }, [&] { return now; });
    error(ErrorCode::permission_denied, [&] { service.start(owner, id); });
    auto existing_lease = configs.prepare_runtime(admin, id);
    error(ErrorCode::conflict, [&] { service.start(admin, id); });
    check(service.get(admin, id).state == NetworkState::stopped && backend == nullptr,
        "runtime lease conflict preserves error code without creating backend");
    error(ErrorCode::conflict, [&] { configs.update(admin, configuration); });
    existing_lease.reset();
    missing = true;
    error(ErrorCode::unavailable, [&] { service.start(admin, id); });
    check(service.get(admin, id).state == NetworkState::stopped && !service.get(admin, id).error.empty(), "exec failure cleans resources and reports STOPPED with error");
    configs.update(admin, configuration); // failed start released lease after cleanup
    missing = false;
    write_file(path + "/unready", "#!/system/bin/sh\nexec /system/bin/sleep 30\n");
    check(chmod((path + "/unready").c_str(), 0700) == 0, "make readiness deadline fixture executable");
    unready = true;
    const auto waiting = std::chrono::steady_clock::now();
    error(ErrorCode::unavailable, [&] { service.start(admin, id); });
    check(std::chrono::steady_clock::now() - waiting >= 4900ms && std::chrono::steady_clock::now() - waiting < 7s &&
        service.get(admin, id).state == NetworkState::stopped, "live process without API fails bounded readiness and is cleaned up");
    unready = false;
    check(service.start(admin, id).state == NetworkState::running && backend->healthy(), "real API readiness precedes RUNNING");
    const auto first_generation = backend->status().generation;
    check(service.start(admin, id).state == NetworkState::running && backend->status().generation == first_generation, "duplicate healthy start is idempotent");
    error(ErrorCode::conflict, [&] { configs.update(admin, configuration); });
    check(backend->signal(SIGKILL), "kill only held test switch pidfd"); await_exit(*backend);
    error(ErrorCode::unavailable, [&] { service.start(admin, id); });
    check(service.reconcile(admin, id).state == NetworkState::running && backend->status().generation > first_generation,
        "real switch crash recovers without dropping configuration lease");
    auto directory = switch_directory(path);
    write_file(directory + "/retained", "unknown file must survive cleanup");
    check(backend->signal(SIGKILL), "kill recovery helper"); await_exit(*backend);
    now += 5s;
    check(service.reconcile(admin, id).state == NetworkState::failed, "cleanup failure blocks recovery");
    const auto failed_generation = service.get(admin, id).generation;
    check(service.reconcile(admin, id).generation == failed_generation, "failed recovery respects retry budget");
    error(ErrorCode::conflict, [&] { configs.update(admin, configuration); });
    check(unlink((directory + "/retained").c_str()) == 0, "remove test-owned cleanup obstruction");
    now += 5s;
    check(service.reconcile(admin, id).state == NetworkState::running, "recovery retries after cleanup becomes possible");
    directory = switch_directory(path);
    write_file(directory + "/retained", "stop failure");
    error(ErrorCode::io_error, [&] { service.stop(admin, id); });
    check(service.get(admin, id).state == NetworkState::failed && !service.get(admin, id).desired_running && !backend->status().running,
        "stop failure is visible after process is reaped");
    now += 10s;
    check(service.reconcile(admin, id).state == NetworkState::failed, "watchdog never resurrects explicitly stopped network");
    configuration["id"] = random_id(true); configuration["name"] = "independent";
    const auto second = configs.create(admin, configuration);
    check(service.start(admin, second).state == NetworkState::running, "independent network starts despite cleanup failure");
    check(service.shutdown().size() == 1 && service.get(admin, second).state == NetworkState::stopped,
        "shutdown reports failed cleanup and still stops independent network");
    check(unlink((directory + "/retained").c_str()) == 0, "resolve original cleanup obstruction");
    check(service.shutdown().empty() && service.get(admin, id).state == NetworkState::stopped, "shutdown cleanup can be retried");
    error(ErrorCode::unavailable, [&] { service.start(admin, second); });
    configs.update(admin, configuration); // all leases released after successful cleanup
    for (const char* file : {"networks.json", "networks.json.bak", "unready"}) unlinkat(dir.get(), file, 0);
    check(rmdir(path.c_str()) == 0, "lifecycle leaves no runtime directories");
}
void real_network_parallel_and_start_cleanup() {
    const auto path = work + "/parallel";
    check(mkdir(path.c_str(), 0700) == 0, "create parallel lifecycle directory");
    Fd dir(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    NetworkConfigService configs(dir.get(), getuid());
    auto configuration = wire::parse(R"({"schema":2,"name":"gated","bridge_name":"test","bridge_type":"gvisor","l3":{"vlans":[]}})");
    configuration["id"] = random_id(true);
    const auto first = configs.create(admin, configuration);
    auto second_config = configuration; second_config["id"] = random_id(true); second_config["name"] = "independent";
    const auto second = configs.create(admin, second_config);
    Gate entered, proceed;
    bool fail_after_ready = false;
    struct ObservedBackend final : Backend {
        Gvswitch real;
        Gate& entered;
        Gate& proceed;
        const bool& fail;
        std::string path;
        ObservedBackend(const std::string& executable, int directory, Gate& entered, Gate& proceed, const bool& fail, std::string path)
            : real(executable, directory), entered(entered), proceed(proceed), fail(fail), path(std::move(path)) {}
        void start(const Json::Value& config) override {
            entered.release(); proceed.wait(); real.start(config);
            if (fail) {
                write_file(switch_directory(path) + "/retained", "injected post-readiness failure");
                throw std::runtime_error("injected post-readiness start failure");
            }
        }
        bool healthy() const override { return real.healthy(); }
        void recover(const Json::Value& config) override { real.recover(config); }
        void stop() override { real.stop(); }
    };
    NetworkService service(configs, [&](const Json::Value& config) -> std::unique_ptr<Backend> {
        if (config["name"] == "gated") return std::make_unique<ObservedBackend>(binaries + "/gvswitch", dir.get(), entered, proceed, fail_after_ready, path);
        return std::make_unique<Gvswitch>(binaries + "/gvswitch", dir.get());
    });
    auto startup = std::async(std::launch::async, [&] { return service.start(admin, first); });
    entered.wait();
    check(service.get(admin, first).state == NetworkState::starting, "queries observe STARTING without waiting for backend I/O");
    error(ErrorCode::conflict, [&] { service.start(admin, first); });
    error(ErrorCode::conflict, [&] { service.stop(admin, first); });
    error(ErrorCode::conflict, [&] { configs.update(admin, configuration); });
    check(service.start(admin, second).state == NetworkState::running, "independent network completes while first is blocked");
    proceed.release();
    check(startup.get().state == NetworkState::running, "blocked startup eventually reaches real readiness");
    service.stop(admin, first); service.stop(admin, second);
    fail_after_ready = true;
    error(ErrorCode::unavailable, [&] { service.start(admin, first); });
    check(service.get(admin, first).state == NetworkState::failed && !service.get(admin, first).desired_running,
        "start cleanup failure retained as FAILED, not STOPPED");
    error(ErrorCode::conflict, [&] { configs.update(admin, configuration); });
    const auto directory = switch_directory(path);
    check(unlink((directory + "/retained").c_str()) == 0, "resolve failed-start obstruction");
    check(service.stop(admin, first).state == NetworkState::stopped, "explicit stop retries failed-start cleanup");
    check(service.shutdown().empty(), "parallel lifecycle shutdown complete");
    for (const char* file : {"networks.json", "networks.json.bak"}) unlinkat(dir.get(), file, 0);
    check(rmdir(path.c_str()) == 0, "parallel lifecycle leaves no resources");
}
Json::Value orphan_configuration() {
    return wire::parse(R"({"schema":2,"id":"aa000000-0000-4000-8000-000000000001","name":"orphan","bridge_name":"test","bridge_type":"gvisor","l3":{"vlans":[]}})");
}
void real_switch_owner_death() {
    const auto path = work + "/owner-death";
    check(mkdir(path.c_str(), 0700) == 0, "create real orphan fixture");
    Fd dir(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    ChildOptions options; options.argv = {"/proc/self/exe", "--orphan-switch", binaries, path};
    const auto result = Child(options).communicate({}, 10s);
    check(result.exit_code == -SIGKILL, "real switch owner killed after readiness");
    const auto directory = switch_directory(path);
    Fd runtime(open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    const auto record = config::JsonFile(runtime.get(), "helper.json", getuid()).load();
    check(record.has_value(), "real switch identity persisted before execution");
    Fd helper(static_cast<int>(syscall(SYS_pidfd_open, record->value["pid"].asInt(), 0)));
    pollfd death{helper.get(), POLLIN, 0};
    check(helper.get() >= 0 && poll(&death, 1, 0) == 0, "real gvswitch survives daemon SIGKILL");
    HelperIdentity::recover(runtime.get(), getuid(), 200ms);
    check(poll(&death, 1, 0) > 0 && (death.revents & POLLIN), "fresh owner recovers real switch via inherited marker and pidfd");
    HelperIdentity::recover(runtime.get(), getuid(), 200ms);
    for (const char* name : {"helper.json", "helper.identity", "s", "config.json"})
        check(unlinkat(runtime.get(), name, 0) == 0 || errno == ENOENT, "remove known orphan fixture file");
    check(rmdir(directory.c_str()) == 0, "real orphan runtime reclaimed");
    Gvswitch replacement(binaries + "/gvswitch", dir.get());
    replacement.start(orphan_configuration());
    check(replacement.healthy(), "switch restarts after orphan recovery");
    replacement.stop();
    check(rmdir(path.c_str()) == 0, "owner-death fixture fully reclaimed");
}
}
int main(int argc, char** argv) {
    if (argc == 4 && std::string_view(argv[1]) == "--orphan-switch") {
        Fd directory(open(argv[3], O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        Gvswitch backend(std::string(argv[2]) + "/gvswitch", directory.get());
        backend.start(orphan_configuration());
        kill(getpid(), SIGKILL);
        return 99;
    }
    if (argc == 3) { binaries = argv[1]; work = argv[2]; }
    if (!binaries.empty()) return run({{"real_gvswitch_control", real_gvswitch}, {"real_bridgedhcp_control", real_bridgedhcp},
        {"real_network_lifecycle", real_network_lifecycle}, {"real_network_parallel_and_start_cleanup", real_network_parallel_and_start_cleanup},
        {"real_switch_owner_sigkill", real_switch_owner_death}});
    return run({{"framing_and_methods", valid_framing_and_methods}, {"malformed_and_truncated", malformed_and_truncated},
        {"limits_and_injection", limits_and_injection}, {"whole_request_deadline_and_cancel", deadline_and_cancellation},
        {"concurrent_connections_and_fd_cleanup", concurrent_connections_and_fd_cleanup}});
}
