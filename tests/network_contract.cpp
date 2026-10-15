// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "services/network_config.h"
#include "store/network_config.h"
#include "common/identity.h"
#include <atomic>
#include <dirent.h>
#include <fcntl.h>
#include <future>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>

using namespace droidvm;
using namespace droidvm::test;
namespace {
struct Temporary {
    std::string path = "/data/local/tmp/droidvm-network-" + random_id(false);
    Fd directory;
    Temporary() {
        check(mkdir(path.c_str(), 0700) == 0, "create test directory");
        directory = Fd(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        check(directory.get() >= 0, "open test directory");
    }
    ~Temporary() {
        DIR* scan = opendir(path.c_str());
        if (scan) {
            while (auto* entry = readdir(scan)) if (std::string_view(entry->d_name) != "." && std::string_view(entry->d_name) != "..")
                unlinkat(directory.get(), entry->d_name, 0);
            closedir(scan);
        }
        rmdir(path.c_str());
    }
};
Json::Value network(const std::string& name) {
    Json::Value value;
    value["id"] = random_id(true);
    value["schema"] = 2;
    value["name"] = name;
    value["bridge_name"] = "brtest";
    return value;
}
void migration_retention_identity() {
    Temporary temp;
    auto active = network("active"), future = network("future"), invalid = network("bad legacy");
    future["schema"] = 9;
    future["opaque"]["integer"] = Json::Int64(INT64_MAX);
    invalid.removeMember("schema"); invalid["bridge_name"] = "0bad";
    Json::Value document;
    document["root_extension"] = "保留";
    auto& rows = document["networks"] = Json::Value(Json::arrayValue);
    rows.append(active); rows.append(future); rows.append(invalid);
    config::JsonFile file(temp.directory.get(), "networks.json", getuid());
    file.save(document);
    NetworkConfigService service(temp.directory.get(), getuid());
    check(service.list(admin).size() == 1 && service.inactive() == 2, "inactive entries retained but not activated");
    auto reserved = future; reserved["schema"] = 2; reserved["name"] = "new name";
    error(ErrorCode::conflict, [&] { service.create(admin, reserved); });
    auto second = network("second");
    auto id = service.create(admin, second);
    check(service.exists(admin, id) && !service.exists(admin, "bad"), "identity lookup");
    auto loaded = file.load()->value;
    check(loaded["root_extension"] == "保留" && loaded["networks"][1] == future && loaded["networks"][2] == invalid, "save keeps opaque entries and root fields");
    error(ErrorCode::unauthenticated, [&] { service.list({}); });
    error(ErrorCode::permission_denied, [&] { service.create(owner, network("denied")); });
    auto collision = active; collision["name"] = "second";
    error(ErrorCode::invalid_argument, [&] { service.update(admin, collision); });
    check(service.get(admin, active["id"].asString())["name"] == "active", "failed update keeps previous record");
    NetworkConfigService restart(temp.directory.get(), getuid());
    check(restart.list(admin).size() == 2 && restart.inactive() == 2, "restart preserves index and opaque entries");
}
void extension_merge_and_null() {
    Temporary temp;
    NetworkConfigService service(temp.directory.get(), getuid());
    auto original = network("original");
    original["extension"] = "old";
    original["l3"]["future_section"] = true;
    auto first = config::default_vlan(1), second = config::default_vlan(2);
    first["future_vlan"] = 11;
    first["ipv4"]["future_family"] = 12;
    first["ipv4"]["dhcp"]["future_dhcp"] = 13;
    original["l3"]["vlans"].append(first); original["l3"]["vlans"].append(second);
    auto id = service.create(admin, original);
    auto edited = network("edited"); edited["id"] = id;
    edited["l3"]["vlans"].append(config::default_vlan(2)); edited["l3"]["vlans"].append(config::default_vlan(1));
    edited["l3"]["vlans"][1]["vlan_id"] = Json::Int64(4294967297LL); // Java int narrowing still identifies VLAN 1.
    service.update(admin, edited);
    auto result = service.get(admin, id);
    check(result["extension"] == "old" && result["l3"]["future_section"].asBool(), "unknown fields survive old client replacement");
    check(result["l3"]["vlans"][1]["future_vlan"] == 11 && result["l3"]["vlans"][1]["ipv4"]["dhcp"]["future_dhcp"] == 13,
          "VLAN identity merge survives reordering");
    edited.removeMember("l3"); edited["extension"] = Json::Value();
    service.update(admin, edited);
    result = service.get(admin, id);
    check(result.isMember("extension") && result["extension"].isNull() && result["l3"]["future_section"].asBool() && !result["l3"].isMember("vlans"),
          "explicit null and removal of known fields remain distinct");
}
void concurrent_creation() {
    Temporary temp;
    NetworkConfigService service(temp.directory.get(), getuid());
    auto value = network("concurrent");
    std::atomic<int> created{0}, conflicts{0}, failures{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < 12; ++i) threads.emplace_back([&] {
        try { service.create(admin, value); ++created; }
        catch (const ServiceError& error) { if (error.code() == ErrorCode::conflict) ++conflicts; else ++failures; }
        catch (...) { ++failures; }
    });
    for (auto& thread : threads) thread.join();
    check(created == 1 && conflicts == 11 && failures == 0 && service.list(admin).size() == 1, "one atomic winner for concurrent duplicate creation");
}
void commit_visibility_and_failure() {
    Temporary temp;
    Gate reached, proceed;
    std::string fail_stage;
    bool block = false;
    NetworkConfigService service(temp.directory.get(), getuid(), [&](const char* stage) {
        if (fail_stage == stage) throw std::runtime_error("injected persistence failure");
        if (block && std::string_view(stage) == "before_install") { reached.release(); proceed.wait(); }
    });
    auto value = network("before");
    auto id = service.create(admin, value);
    value["name"] = "after";
    block = true;
    auto write = std::async(std::launch::async, [&] { service.update(admin, value); });
    reached.wait();
    auto reading = std::async(std::launch::async, [&] { return service.get(admin, id); });
    auto ready = reading.wait_for(500ms) == std::future_status::ready;
    proceed.release();
    check(ready && reading.get()["name"] == "before", "reads see previous snapshot without waiting for disk");
    write.get(); block = false;
    check(service.get(admin, id)["name"] == "after", "new snapshot visible after commit");
    value["name"] = "failed"; fail_stage = "before_write";
    error(ErrorCode::io_error, [&] { service.update(admin, value); });
    check(service.get(admin, id)["name"] == "after", "failed write retains memory snapshot");
    value["name"] = "installed"; fail_stage = "installed";
    error(ErrorCode::commit_uncertain, [&] { service.update(admin, value); });
    check(service.get(admin, id)["name"] == "installed", "post-rename failure reconciles installed memory");
    NetworkConfigService restart(temp.directory.get(), getuid());
    check(restart.get(admin, id)["name"] == "installed", "restart agrees after uncertain durability");
}
void shared_worker_queue() {
    TaskLimits limits; limits.workers = 1; limits.queued = 1;
    TaskService tasks(limits);
    Gate started, proceed;
    std::atomic<bool> discarded{false};
    tasks.post(admin, [&](bool cancelled) { check(!cancelled, "running callback executes"); started.release(); proceed.wait(); });
    started.wait();
    tasks.post(admin, [&](bool cancelled) { discarded = cancelled; });
    error(ErrorCode::resource_exhausted, [&] { tasks.submit(admin, spec(), ok); });
    auto stopping = std::async(std::launch::async, [&] { tasks.shutdown(); });
    const auto deadline = std::chrono::steady_clock::now() + 1s;
    while (!discarded && std::chrono::steady_clock::now() < deadline) std::this_thread::yield();
    proceed.release(); stopping.get();
    check(discarded && tasks.snapshot(admin).total == 0, "RPC callbacks share limits without retained task records");
}
int half_close(int port, const char* token) {
    Fd socket(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    check(socket.get() >= 0, "create client socket");
    timeval timeout{10, 0};
    setsockopt(socket.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(socket.get(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    sockaddr_in address{};
    address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = htons(port);
    check(connect(socket.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0, "connect client");
    auto send_request = [&](Json::Value value) {
        value["type"] = "request"; value["request_id"] = random_id(true);
        auto bytes = wire::frame(wire::stringify(value), true);
        size_t offset = 0;
        while (offset < bytes.size()) {
            auto count = send(socket.get(), bytes.data() + offset, bytes.size() - offset, MSG_NOSIGNAL);
            check(count > 0, "send request"); offset += static_cast<size_t>(count);
        }
    };
    auto receive = [&] {
        uint32_t header;
        check(recv(socket.get(), &header, sizeof(header), MSG_WAITALL) == sizeof(header), "receive response header");
        auto size = wire::payload_size(&header);
        std::string bytes(size, '\0');
        check(recv(socket.get(), bytes.data(), size, MSG_WAITALL) == static_cast<ssize_t>(size), "receive response body");
        return wire::parse(bytes);
    };
    Json::Value auth;
    auth["command"] = "auth"; auth["token"] = token;
    send_request(auth); check(receive()["success"].asBool(), "authenticate client");
    auto value = network("half-close");
    Json::Value create;
    create["command"] = "network_create"; create["config"] = value;
    send_request(create);
    check(shutdown(socket.get(), SHUT_WR) == 0, "half-close write direction");
    auto reply = receive();
    check(reply["success"].asBool() && reply["network_id"] == value["id"], "half-close waits for committed response");
    char byte;
    check(recv(socket.get(), &byte, 1, 0) == 0, "server closes after response");
    std::cout << wire::stringify(reply) << std::endl;
    return 0;
}
}
int main(int argc, char** argv) {
    if (argc == 4 && std::string_view(argv[1]) == "--half-close") {
        try { return half_close(std::stoi(argv[2]), argv[3]); }
        catch (const std::exception& error) { std::cerr << error.what() << std::endl; return 1; }
    }
    return run({{"migration_opaque_identity_permissions", migration_retention_identity}, {"nested_extensions_vlan_identity_null", extension_merge_and_null},
        {"twelve_concurrent_duplicate_creates", concurrent_creation}, {"read_snapshot_io_failure_commit_uncertain", commit_visibility_and_failure},
        {"shared_bounded_worker_shutdown", shared_worker_queue}});
}
