// SPDX-License-Identifier: GPL-3.0-or-later
// Loopback-only lifecycle fixture. Persisted settings and host discovery are
// injected; real listener, API, sessions and TaskService are used unchanged.
#include "web/service.h"
#include "services/tasks.h"
#include <atomic>
#include <charconv>
#include <future>
#include <iostream>
#include <mutex>
#include <sstream>

using namespace droidvm;
using namespace droidvm::web;
namespace {
const CallContext local{"local-admin", true, true, true};
void output(const Json::Value& value) {
    Json::StreamWriterBuilder writer; writer["indentation"] = "";
    std::cout << Json::writeString(writer, value) << std::endl;
}
}
int main(int argc, char** argv) {
    if (argc < 2 || argc > 4) return 2;
    bool enabled = false, force_ipv4 = false;
    for (int i = 2; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--enabled") enabled = true;
        else if (std::string_view(argv[i]) == "--ipv4") force_ipv4 = true;
        else return 2;
    }
    unsigned port = 0; const std::string number = argv[1];
    const auto parsed = std::from_chars(number.data(), number.data() + number.size(), port);
    if (parsed.ec != std::errc{} || parsed.ptr != number.data() + number.size() || port < 1024 || port > 65535) return 2;
    try {
        TaskLimits limits; limits.background_workers = 1;
        TaskService workers(limits);
        WebSettings saved; saved.port = static_cast<uint16_t>(port); saved.enabled = enabled;
        std::mutex saved_mutex;
        std::atomic<int> scan_mode{0}, save_mode{0};
        std::atomic<unsigned> scans{0}, saves{0};
        WebService service(workers, saved, [&] {
            ++scans;
            if (scan_mode == 1) throw std::runtime_error("discovery failed");
            network::HostNetworkSnapshot result;
            if (scan_mode == 2) {
                network::HostInterface iface; iface.name = "test-radio"; iface.index = 7;
                iface.up = iface.wireless = iface.ethernet = iface.leaf = true; result.interfaces.push_back(iface);
                Json::Value link; link["ifname"] = iface.name; link["kind"] = ""; link["master"] = ""; result.links.append(link);
                Json::Value address; address["ifname"] = iface.name; address["local"] = "203.0.113.240";
                address["family"] = 4; address["prefixlen"] = 24; address["scope"] = "global"; result.addresses.append(address);
            }
            return result;
        }, [](const CallContext& caller) {
            if (!caller.authenticated || !caller.principal.starts_with("web:")) throw std::runtime_error("wrong identity");
            Json::Value result; result["items"] = Json::Value(Json::arrayValue); return result;
        }, [&](const Json::Value& settings) {
            std::lock_guard lock(saved_mutex);
            if (settings["scope"] == "all" && scan_mode != 1)
                throw ServiceError(ErrorCode::permission_denied, "Fixture cannot activate wildcard listeners");
            ++saves;
            if (save_mode == 1) throw std::runtime_error("before persistence");
            saved = WebSettings::parse(settings);
            if (save_mode == 2) throw std::runtime_error("after persistence");
        }, [&] { std::lock_guard lock(saved_mutex); return saved; }, {"service-fixture", "1"}, [force_ipv4] { return !force_ipv4 && ipv6_available(); });
        Json::Value ready; ready["ready"] = true; output(ready);
        for (std::string line; std::getline(std::cin, line) && line != "quit";) {
            Json::Value request, result; Json::CharReaderBuilder reader; std::istringstream input(line);
            if (!Json::parseFromStream(reader, input, &request, nullptr)) return 2;
            try {
                const auto op = request["op"].asString();
                if (op == "scan") {
                    std::lock_guard lock(saved_mutex);
                    if (saved.scope == ListenScope::all && request["mode"].asInt() != 1) return 2;
                    scan_mode = request["mode"].asInt(); result["ok"] = true;
                }
                else if (op == "save") { save_mode = request["mode"].asInt(); result["ok"] = true; }
                else if (op == "tick") { service.schedule(); result["ok"] = true; }
                else if (op == "stats") { result["scans"] = scans.load(); result["saves"] = saves.load(); }
                else if (op == "stop") {
                    service.stop();
                    auto promise = std::make_shared<std::promise<bool>>(); auto completed = promise->get_future();
                    workers.post(local, [promise](bool discarded) { promise->set_value(!discarded); });
                    if (completed.wait_for(std::chrono::seconds(5)) != std::future_status::ready || !completed.get()) return 1;
                    result["workersAlive"] = true;
                } else if (op == "ipc") {
                    const auto command = request["command"].asString();
                    // This host fixture may never activate a wildcard, even
                    // when malformed input is supplied by a test driver.
                    if (command == "web_configure" && request["request"]["settings"]["scope"] == "all" && scan_mode != 1) return 2;
                    auto caller = local;
                    if (request["identity"] == "browser") caller.principal = "web:test";
                    if (request["identity"] == "anonymous") caller.authenticated = false;
                    result = service.execute(caller, command, request["request"]);
                } else return 2;
            } catch (const ServiceError& error) { result["errorCode"] = error_code_name(error.code()); }
            output(result);
        }
        service.stop(); workers.shutdown(); return 0;
    } catch (...) { std::cerr << "Web service fixture failed\n"; return 1; }
}
