// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "services/network_config.h"
#include "store/network_config.h"
#include "common/identity.h"
#include <atomic>
#include <dirent.h>
#include <fcntl.h>
#include <future>
#include <regex>
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
void configuration_event_handoff() {
    Temporary temp;
    TaskService tasks;
    std::string fail_stage;
    NetworkConfigService service(temp.directory.get(), getuid(), [&](const char* stage) {
        if (fail_stage == stage) throw std::runtime_error("injected failure");
    }, &tasks);
    auto before = tasks.network_config_snapshot(admin);
    check(before.total == 0 && before.cursor.epoch == tasks.epoch(), "network shares task epoch");
    auto value = network("event handoff");
    auto id = service.create(admin, value);
    auto subscription = tasks.subscribe(admin, before.cursor);
    auto changed = tasks.poll(admin, subscription);
    check(changed.events.size() == 1 && wire::parse(changed.events[0].encoded)["kind"] == "network.config.invalidated",
        "commit between snapshot and subscribe is replayed");
    auto current = tasks.network_config_snapshot(admin);
    check(current.total == 1 && wire::parse(current.items[0]) == service.get(admin, id), "snapshot agrees with committed configuration");
    check(tasks.snapshot_page(admin, before.id, 0).total == 0, "old empty view remains fixed");
    tasks.release_snapshot(admin, before.id);
    value["name"] = "not installed"; fail_stage = "before_write";
    error(ErrorCode::io_error, [&] { service.update(admin, value); });
    check(tasks.poll(admin, subscription).events.empty(), "failed save emits no event");
    value["name"] = "installed uncertain"; fail_stage = "installed";
    error(ErrorCode::commit_uncertain, [&] { service.update(admin, value); });
    check(tasks.poll(admin, subscription).events.size() == 1, "installed uncertain commit emits invalidation");
    auto uncertain = tasks.network_config_snapshot(admin);
    check(wire::parse(uncertain.items[0])["name"] == "installed uncertain", "uncertain commit updates snapshot");
    check(wire::parse(tasks.snapshot_page(admin, current.id, 0).items[0])["name"] == "event handoff", "old view survives update");
    tasks.release_snapshot(admin, uncertain.id);
    fail_stage.clear();
    auto lease = service.prepare_runtime(admin, id);
    check(tasks.poll(admin, subscription).events.size() == 1, "runtime identity persistence invalidates configuration");
    lease.reset();
    service.remove(admin, id);
    check(tasks.poll(admin, subscription).events.size() == 1, "delete invalidates configuration");
    auto empty = tasks.network_config_snapshot(admin);
    check(empty.total == 0, "delete removed projected row");
    tasks.release_snapshot(admin, empty.id);
    error(ErrorCode::permission_denied, [&] { tasks.network_config_snapshot(owner); });
    error(ErrorCode::unauthenticated, [&] { tasks.network_config_snapshot({}); });
    error(ErrorCode::permission_denied, [&] { tasks.snapshot_page(owner, current.id, 0); });
    CallContext system{"system", true, true, false};
    auto hidden = tasks.subscribe(system, current.cursor);
    check(tasks.poll(system, hidden).events.empty(), "admin events hidden even from matching principal name");
    tasks.unsubscribe(system, hidden);
    TaskService restart;
    NetworkConfigService reopened(temp.directory.get(), getuid(), {}, &restart);
    error(ErrorCode::resync_required, [&] { restart.subscribe(admin, current.cursor); });
    tasks.release_snapshot(admin, current.id);
    tasks.unsubscribe(admin, subscription);
}
void configuration_snapshot_races_and_limits() {
    Temporary temp;
    TaskService tasks;
    Gate saving, proceed;
    bool block = false;
    NetworkConfigService service(temp.directory.get(), getuid(), [&](const char* stage) {
        if (block && std::string_view(stage) == "before_install") { saving.release(); proceed.wait(); }
    }, &tasks);
    auto value = network("before");
    const auto id = service.create(admin, value);
    block = true;
    value["name"] = "after";
    auto writer = std::async(std::launch::async, [&] { service.update(admin, value); });
    saving.wait();
    auto reading = std::async(std::launch::async, [&] { return tasks.network_config_snapshot(admin); });
    const auto ready = reading.wait_for(500ms) == std::future_status::ready;
    proceed.release(); writer.get(); block = false;
    auto snapshot = reading.get();
    check(ready && wire::parse(snapshot.items[0])["name"] == "before", "disk write never holds journal lock");
    auto subscription = tasks.subscribe(admin, snapshot.cursor);
    check(tasks.poll(admin, subscription).events.size() == 1, "blocked disk commit replayed after earlier snapshot");
    tasks.unsubscribe(admin, subscription);
    tasks.release_snapshot(admin, snapshot.id);
    for (int i = 0; i < 32; ++i) {
        value["name"] = "race " + std::to_string(i);
        auto write = std::async(std::launch::async, [&] { service.update(admin, value); });
        auto view = tasks.network_config_snapshot(admin);
        auto sub = tasks.subscribe(admin, view.cursor);
        write.get();
        auto tail = tasks.poll(admin, sub);
        check(wire::parse(view.items[0]) == service.get(admin, id) || !tail.events.empty(), "racing commit appears in snapshot or invalidation");
        tasks.unsubscribe(admin, sub);
        tasks.release_snapshot(admin, view.id);
    }
    value["extension"] = std::string(20000, 'x');
    service.update(admin, value);
    // A too-small first page must fail and release the cache slot, never loop
    // forever with next_offset equal to the requested offset.
    for (int i = 0; i < 10; ++i)
        error(ErrorCode::resource_exhausted, [&] { tasks.network_config_snapshot(admin, (16u << 10) + 64); });
    auto large = tasks.network_config_snapshot(admin);
    check(wire::parse(large.items[0]) == service.get(admin, id), "configuration larger than event limit remains readable");
    tasks.release_snapshot(admin, large.id);
    auto second = network("second page"), third = network("third page");
    second["extension"] = third["extension"] = std::string(20000, 'y');
    service.create(admin, second); service.create(admin, third);
    auto pages = tasks.network_config_snapshot(admin, 24000);
    check(pages.total == 3 && pages.items.size() == 1 && pages.next == 1, "configuration snapshot paginates");
    service.remove(admin, second["id"].asString());
    auto page2 = tasks.snapshot_page(admin, pages.id, 1, 24000);
    auto page3 = tasks.snapshot_page(admin, pages.id, 2, 24000);
    check(page2.cursor.sequence == pages.cursor.sequence && page3.cursor.sequence == pages.cursor.sequence &&
        wire::parse(page2.items[0])["id"] == second["id"] && wire::parse(page3.items[0])["id"] == third["id"] &&
        page2.next == 2 && !page3.next, "all pages retain deleted rows and original cursor");
    tasks.release_snapshot(admin, pages.id);
    std::vector<std::string> held;
    for (int i = 0; i < 8; ++i) held.push_back(i % 2 ? tasks.snapshot(admin).id : tasks.network_config_snapshot(admin).id);
    error(ErrorCode::resource_exhausted, [&] { tasks.snapshot(admin); });
    error(ErrorCode::resource_exhausted, [&] { tasks.network_config_snapshot(admin); });
    for (const auto& cache : held) tasks.release_snapshot(admin, cache);
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
Json::Value pd_network(const std::string& name, int vid = 0) {
    auto value = network(name);
    auto vlan = config::default_vlan(vid);
    vlan["ipv6"]["source"] = "dhcp_pd";
    vlan["ipv6"]["pd"]["uplink"] = "wlan0";
    value["l3"]["vlans"].append(vlan);
    return value;
}
const Json::Value& pd(const Json::Value& value, int index = 0) { return value["l3"]["vlans"][index]["ipv6"]["pd"]; }
void runtime_identity_and_edit_guard() {
    Temporary temp;
    unsigned writes = 0;
    NetworkConfigService service(temp.directory.get(), getuid(), [&](const char* stage) { if (std::string_view(stage) == "before_write") ++writes; });
    auto value = pd_network("prepared");
    value["extension"] = "keep";
    const auto id = service.create(admin, value);
    error(ErrorCode::unauthenticated, [&] { service.prepare_runtime({}, id); });
    error(ErrorCode::permission_denied, [&] { service.prepare_runtime(owner, id); });
    auto lease = service.prepare_runtime(admin, id, {9991, 9993});
    const auto first = lease->config();
    const auto mac = lease->bridge_mac();
    check(std::regex_match(mac, std::regex("02(:[0-9a-f]{2}){5}")), "legacy random MAC shape");
    check(first["generated_mac"] == mac && pd(first)["duid"] == "00:03:00:01:" + mac && pd(first)["route_table"] == 9992,
        "stable identities prepared with host table exclusion");
    check(first["extension"] == "keep" && service.get(admin, id) == first, "durable identities published together");
    config::JsonFile disk(temp.directory.get(), "networks.json", getuid());
    check(disk.load()->value["networks"][0] == first, "lease returned only after persisted snapshot");
    error(ErrorCode::conflict, [&] { service.update(admin, value); });
    error(ErrorCode::conflict, [&] { service.prepare_runtime(admin, id); });
    service.create(admin, network("other"));
    lease.reset();
    const auto count = writes;
    lease = service.prepare_runtime(admin, id, {9992});
    check(lease->config() == first && writes == count, "idempotent prepare never reallocates an existing table or rewrites");
    lease.reset();
    NetworkConfigService restart(temp.directory.get(), getuid());
    auto restarted = restart.prepare_runtime(admin, id);
    check(restarted->config() == first && restarted->bridge_mac() == mac, "restart preserves exact identities");
    restarted.reset();
    auto edited = first; edited["name"] = "edited";
    restart.update(admin, edited);
    check(restart.get(admin, id)["name"] == "edited", "successful cleanup/release permits editing");
}
void runtime_tables_concurrent_and_opaque() {
    Temporary temp;
    auto future = pd_network("future"); future["schema"] = 9;
    future["l3"]["vlans"][0]["ipv6"]["pd"]["route_table"] = 9991;
    Json::Value document; document["networks"].append(future);
    config::JsonFile file(temp.directory.get(), "networks.json", getuid()); file.save(document);
    NetworkConfigService service(temp.directory.get(), getuid());
    std::vector<std::string> ids;
    for (int i = 0; i < 12; ++i) ids.push_back(service.create(admin, pd_network("concurrent-" + std::to_string(i))));
    std::vector<std::future<std::unique_ptr<NetworkRuntimeLease>>> jobs;
    for (const auto& id : ids) jobs.push_back(std::async(std::launch::async, [&, id] { return service.prepare_runtime(admin, id, {9993}); }));
    std::set<uint32_t> tables;
    std::vector<std::unique_ptr<NetworkRuntimeLease>> leases;
    for (auto& job : jobs) {
        auto lease = job.get();
        auto table = pd(lease->config())["route_table"].asUInt();
        check(table != 9991 && table != 9993 && tables.insert(table).second, "concurrent preparations reserve unique tables");
        leases.push_back(std::move(lease));
    }
    check(file.load()->value["networks"][0] == future, "inactive future entry remains unchanged and reserves table");
    auto duplicate = pd_network("duplicate");
    duplicate["l3"]["vlans"][0]["ipv6"]["pd"]["route_table"] = *tables.begin();
    const auto duplicate_id = service.create(admin, duplicate);
    error(ErrorCode::conflict, [&] { service.prepare_runtime(admin, duplicate_id); });
    auto stored = pd_network("configured");
    stored["l3"]["mac_address"] = "02:AA:BB:CC:DD:EE";
    stored["l3"]["vlans"][0]["ipv6"]["pd"]["duid"] = "00:AA:BB";
    stored["l3"]["vlans"][0]["ipv6"]["pd"]["route_table"] = Json::Int64(4000000000LL);
    auto fixed = service.prepare_runtime(admin, service.create(admin, stored));
    check(fixed->bridge_mac() == "02:AA:BB:CC:DD:EE" && pd(fixed->config())["duid"] == "00:AA:BB" &&
        pd(fixed->config())["route_table"].asInt64() == 4000000000LL && !fixed->config().isMember("generated_mac"), "explicit persisted identities retained");
    for (int64_t table : {-1LL, 253LL, 254LL, 255LL, 4294967296LL}) {
        auto invalid = pd_network("invalid-" + std::to_string(table));
        invalid["l3"]["vlans"][0]["ipv6"]["pd"]["route_table"] = Json::Int64(table);
        const auto invalid_id = service.create(admin, invalid);
        error(ErrorCode::invalid_argument, [&] { service.prepare_runtime(admin, invalid_id); });
        check(!service.get(admin, invalid_id).isMember("generated_mac"), "invalid table rejects entire preparation transaction");
    }
}
void runtime_durable_failures_and_racing_edit() {
    Temporary temp;
    std::string fail_stage;
    Gate reached, proceed;
    bool block = false;
    NetworkConfigService service(temp.directory.get(), getuid(), [&](const char* stage) {
        if (fail_stage == stage) throw std::runtime_error("injected runtime save failure");
        if (block && std::string_view(stage) == "before_install") { reached.release(); proceed.wait(); }
    });
    auto original = pd_network("before"); const auto id = service.create(admin, original);
    fail_stage = "before_write";
    error(ErrorCode::io_error, [&] { service.prepare_runtime(admin, id); });
    check(!service.get(admin, id).isMember("generated_mac"), "failed preparation publishes no identity");
    original["name"] = "after failure"; fail_stage.clear(); service.update(admin, original);
    fail_stage = "installed";
    error(ErrorCode::commit_uncertain, [&] { service.prepare_runtime(admin, id); });
    const auto installed = service.get(admin, id);
    check(installed.isMember("generated_mac"), "installed uncertain identity remains visible for reconciliation");
    fail_stage = "before_write";
    error(ErrorCode::io_error, [&] { service.prepare_runtime(admin, id); });
    check(service.get(admin, id) == installed, "retry attempts durable write even with unchanged identities");
    {
        NetworkConfigService restart(temp.directory.get(), getuid(), [](const char* stage) {
            if (std::string_view(stage) == "before_write") throw std::runtime_error("restart sync failure");
        });
        error(ErrorCode::io_error, [&] { restart.prepare_runtime(admin, id); });
    }
    fail_stage.clear(); block = true;
    auto startup = std::async(std::launch::async, [&] { return service.prepare_runtime(admin, id); });
    reached.wait();
    check(service.get(admin, id) == installed, "readers retain immutable snapshot during startup write");
    auto update = std::async(std::launch::async, [&] {
        auto value = installed; value["name"] = "racing";
        error(ErrorCode::conflict, [&] { service.update(admin, value); });
    });
    proceed.release();
    auto lease = startup.get(); update.get(); block = false;
    check(lease->config() == installed, "edit cannot slip between durable preparation and lease publication");
}
void runtime_modes_and_single_owner() {
    Temporary temp;
    NetworkConfigService service(temp.directory.get(), getuid());
    auto value = pd_network("multiple VLANs");
    auto second = value["l3"]["vlans"][0]; second["vlan_id"] = 257;
    value["l3"]["vlans"].append(second);
    const auto id = service.create(admin, value);
    std::vector<std::future<std::unique_ptr<NetworkRuntimeLease>>> jobs;
    for (int i = 0; i < 12; ++i) jobs.push_back(std::async(std::launch::async, [&]() -> std::unique_ptr<NetworkRuntimeLease> {
        try { return service.prepare_runtime(admin, id); }
        catch (const ServiceError& e) { check(e.code() == ErrorCode::conflict, "duplicate startup rejected as conflict"); return {}; }
    }));
    std::unique_ptr<NetworkRuntimeLease> winner;
    unsigned count = 0;
    for (auto& job : jobs) if (auto lease = job.get()) { ++count; winner = std::move(lease); }
    check(count == 1 && pd(winner->config())["route_table"] == 9991 && pd(winner->config(), 1)["route_table"] == 9992 &&
        pd(winner->config())["duid"] == pd(winner->config(), 1)["duid"], "one runtime owner and distinct per-VLAN tables");
    auto l2 = network("L2"); l2["uplink_mode"] = "l2"; l2["l2"]["uplink"] = "wlan0";
    l2["l3"]["mac_address"] = "02:00:00:00:00:01";
    auto l2_lease = service.prepare_runtime(admin, service.create(admin, l2));
    check(l2_lease->bridge_mac() == l2_lease->config()["generated_mac"].asString() &&
        l2_lease->bridge_mac() != "02:00:00:00:00:01", "L2 uses stable generated MAC, not ignored L3 setting");
    auto gvisor = network("gvisor"); gvisor["bridge_type"] = "gvisor";
    auto gvisor_lease = service.prepare_runtime(admin, service.create(admin, gvisor));
    check(gvisor_lease->bridge_mac().empty() && !gvisor_lease->config().isMember("generated_mac"), "gvisor retains implicit helper MAC behavior");
    auto invalid = network("invalid MAC"); invalid["generated_mac"] = "broken";
    const auto bad_id = service.create(admin, invalid);
    error(ErrorCode::invalid_argument, [&] { service.prepare_runtime(admin, bad_id); });
    std::unique_ptr<NetworkRuntimeLease> surviving;
    {
        Temporary other;
        NetworkConfigService short_lived(other.directory.get(), getuid());
        surviving = short_lived.prepare_runtime(admin, short_lived.create(admin, network("guard lifetime")));
    }
    surviving.reset(); // guard registry has no dangling service reference
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
        {"network_snapshot_replay_failure_permissions", configuration_event_handoff},
        {"network_snapshot_races_shared_limits", configuration_snapshot_races_and_limits},
        {"shared_bounded_worker_shutdown", shared_worker_queue}, {"runtime_identity_and_edit_guard", runtime_identity_and_edit_guard},
        {"runtime_tables_concurrent_and_opaque", runtime_tables_concurrent_and_opaque},
        {"runtime_durable_failures_and_racing_edit", runtime_durable_failures_and_racing_edit},
        {"runtime_modes_and_single_owner", runtime_modes_and_single_owner}});
}
