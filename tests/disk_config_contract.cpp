// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "snapshot_document.h"
#include "common/identity.h"
#include "services/disk_config.h"
#include "store/vm_ownership.h"
#include "store/disk_config.h"
#include "transport/dispatcher.h"
#include <atomic>
#include <dirent.h>
#include <fcntl.h>
#include <future>
#include <sys/stat.h>
#include <unistd.h>

using namespace droidvm;
using namespace droidvm::test;
namespace {
struct Temporary {
    std::string path = "/data/local/tmp/droidvm-disk-config-" + random_id(false);
    Fd directory;
    Temporary() {
        check(mkdir(path.c_str(), 0700) == 0, "create isolated disk registry directory");
        directory = Fd(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        check(directory.get() >= 0, "open isolated directory");
    }
    ~Temporary() {
        if (auto* scan = opendir(path.c_str())) {
            while (auto* entry = readdir(scan)) if (std::string_view(entry->d_name) != "." && std::string_view(entry->d_name) != "..")
                unlinkat(directory.get(), entry->d_name, 0);
            closedir(scan);
        }
        rmdir(path.c_str());
    }
    void raw(const char* name, const std::string& bytes) {
        Fd file(openat(directory.get(), name, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600));
        check(file.get() >= 0 && write(file.get(), bytes.data(), bytes.size()) == static_cast<ssize_t>(bytes.size()), "write isolated fixture");
    }
};
Json::Value document() {
    Json::Value root, first, second;
    first["id"] = random_id(true); first["name"] = "disk.qcow2"; first["folder"] = "/first";
    first["future"]["integer"] = Json::Int64(9007199254740993LL);
    first["future"]["nullable"] = Json::Value();
    second = first; second["id"] = random_id(true); second["folder"] = "/second";
    second["parent"] = first["id"];
    root["disks"] = Json::Value(Json::arrayValue); root["disks"].append(first); root["disks"].append(second);
    root["future_root"] = "保留 🌏";
    return root;
}
void structure_transition_validation() {
    Json::Value empty; empty["disks"] = Json::Value(Json::arrayValue);
    const auto valid = document();
    config::validate_disk_transition(empty, valid);
    check(config::valid_disk_paths(valid).size() == 2, "valid forest admits both paths");
    auto reject = [&](Json::Value next) {
        bool refused = false;
        try { config::validate_disk_transition(valid, next); } catch (const std::invalid_argument&) { refused = true; }
        check(refused, "invalid new registry structure rejected");
    };
    auto next = valid; next["disks"][0]["parent"] = random_id(true); reject(next);
    next = valid; next["disks"][0]["parent"] = next["disks"][0]["id"]; reject(next);
    next = valid; next["disks"][0]["parent"] = next["disks"][1]["id"]; reject(next);
    next = valid; next["disks"][1]["folder"] = "/first/"; reject(next);
    for (const auto& folder : {"relative", "/images/../elsewhere", "/images/./sub"}) {
        next = valid; next["disks"][0]["folder"] = folder; reject(next);
    }
    next = valid; next["disks"][0]["name"] = "../image"; reject(next);
    next = valid; next["disks"][0]["folder"] = std::string("/a\0b", 4); reject(next);
    next = valid; next["disks"].removeIndex(0, nullptr); reject(next);
}
void historical_structure_repair() {
    auto historical = document(); historical["disks"][0]["parent"] = "broken";
    auto next = historical; next["root_extension"] = "unrelated";
    config::validate_disk_transition(historical, next);
    check(config::valid_disk_paths(historical).empty(), "broken ancestor excludes descendant from new VM references");
    auto reject = [&](Json::Value changed) {
        bool refused = false;
        try { config::validate_disk_transition(historical, changed); } catch (const std::invalid_argument&) { refused = true; }
        check(refused, "historical invalid rows cannot be edited or extended without repair");
    };
    next = historical; next["disks"][0]["future"]["integer"] = 1; reject(next);
    next = historical; auto child = next["disks"][1]; child["id"] = random_id(true); child["folder"] = "/third";
    next["disks"].append(child); reject(next);
    next = historical; next["disks"][0].removeMember("parent");
    config::validate_disk_transition(historical, next);
    check(config::valid_disk_paths(next).size() == 2, "repair re-enables the complete chain");
    auto cycle = document(); cycle["disks"][0]["parent"] = cycle["disks"][1]["id"];
    config::validate_disk_transition(cycle, cycle);
    check(config::valid_disk_paths(cycle).empty(), "historical cycle stays readable but cannot accept new references");
}
void long_structure_chain() {
    Json::Value empty, chain; empty["disks"] = Json::Value(Json::arrayValue); chain = empty;
    for (int i = 0; i < 4096; ++i) {
        Json::Value row; row["id"] = random_id(true); row["folder"] = "/images"; row["name"] = std::to_string(i);
        if (i) row["parent"] = chain["disks"][i - 1]["id"];
        chain["disks"].append(row);
    }
    config::validate_disk_transition(empty, chain);
    check(config::valid_disk_paths(chain).size() == 4096, "long chain uses no recursion");
    chain["disks"][0]["parent"] = chain["disks"][4095]["id"];
    check(config::valid_disk_paths(chain).empty(), "long cycle resolves as invalid without recursion");
}
void roundtrip_restart_and_ownership() {
    Temporary temp;
    temp.raw("image.qcow2", "not an actual image");
    std::string old_revision;
    auto wanted = document();
    {
        DiskConfigService service(temp.directory.get(), getuid());
        auto initial = service.snapshot(admin);
        check(!initial->persisted && initial->document["disks"].empty(), "empty registry is not a saved document");
        auto saved = service.replace(admin, initial->revision, wanted);
        old_revision = saved->revision;
        check(saved->persisted && !saved->recovered && !saved->durability_uncertain, "registry save is durable");
        check(config::parse_json(*saved->encoded) == wanted, "unknown fields, parents, duplicate names and int64 preserved");
        auto copy = saved->document; copy["disks"].clear();
        check(service.snapshot(admin)->document == wanted, "snapshot caller mutation is detached");
        check(service.replace(admin, saved->revision, wanted)->revision == saved->revision, "durable noop retains revision");
        bool refused = false;
        try { config::require_legacy_disk_config(temp.directory.get(), getuid()); } catch (...) { refused = true; }
        check(refused, "service claims persistent disk ownership");
    }
    DiskConfigService reopened(temp.directory.get(), getuid());
    auto base = reopened.snapshot(admin);
    check(base->document == wanted && base->revision != old_revision && base->durability_uncertain, "reopen changes revision and requires durability confirmation");
    error(ErrorCode::conflict, [&] { reopened.replace(admin, old_revision, wanted); });
    auto empty = wanted; empty["disks"].clear();
    reopened.replace(admin, base->revision, empty);
    check(faccessat(temp.directory.get(), "image.qcow2", F_OK, 0) == 0, "registry removal never unlinks images");
}
void validation_and_admission() {
    Temporary temp;
    int validations = 0;
    bool reject = false;
    auto gate = std::make_shared<ConfigurationGate>();
    DiskConfigService service(temp.directory.get(), getuid(), {}, gate, [&](const Json::Value&, const Json::Value&) -> std::unique_ptr<ConfigurationCommit> {
        ++validations;
        if (reject) throw ServiceError(ErrorCode::conflict, "participant refused");
        return nullptr;
    });
    auto initial = service.snapshot(admin);
    auto wanted = document();
    error(ErrorCode::unauthenticated, [&] { service.snapshot({}); });
    error(ErrorCode::permission_denied, [&] { service.replace(owner, initial->revision, wanted); });
    error(ErrorCode::invalid_argument, [&] { service.replace(admin, initial->revision, Json::Value(Json::objectValue)); });
    auto invalid = wanted; invalid["disks"][1]["id"] = invalid["disks"][0]["id"];
    error(ErrorCode::conflict, [&] { service.replace(admin, initial->revision, invalid); });
    invalid = wanted; invalid["disks"][0]["name"] = 7;
    error(ErrorCode::invalid_argument, [&] { service.replace(admin, initial->revision, invalid); });
    reject = true;
    error(ErrorCode::conflict, [&] { service.replace(admin, initial->revision, wanted); });
    check(validations == 1 && !service.snapshot(admin)->persisted && faccessat(temp.directory.get(), "disks.json", F_OK, 0) != 0,
        "participant rejection precedes filesystem changes");
    reject = false;
    auto saved = service.replace(admin, initial->revision, wanted);
    { auto transaction = gate->transaction(); transaction.require_recovery(); }
    error(ErrorCode::unavailable, [&] { service.snapshot(admin); });
    error(ErrorCode::unavailable, [&] { service.replace(admin, saved->revision, wanted); });
    check(saved->document == wanted, "previous immutable view survives gate fault");
    { auto transaction = gate->transaction(); transaction.recovered(); }
    check(service.snapshot(admin)->revision == saved->revision, "gate recovery does not rewrite registry");
}
void commit_failure_and_recovery() {
    Temporary temp;
    std::string fault;
    int leases = 0, commits = 0;
    struct Participant final : ConfigurationCommit {
        int& leases; int& commits;
        Participant(int& live, int& applied) : leases(live), commits(applied) { ++leases; }
        ~Participant() override { --leases; }
        void commit() noexcept override { ++commits; }
    };
    DiskConfigService service(temp.directory.get(), getuid(), [&](const char* stage) {
        check(leases == 1, "participant lease covers every persistence boundary");
        if (fault == stage) throw std::runtime_error("injected disk registry write failure");
    }, {}, [&](const Json::Value&, const Json::Value&) { return std::make_unique<Participant>(leases, commits); });
    auto base = service.snapshot(admin);
    auto wanted = document();
    fault = "before_install";
    error(ErrorCode::io_error, [&] { service.replace(admin, base->revision, wanted); });
    check(leases == 0 && commits == 0, "uninstalled participant aborts and releases lease");
    check(service.snapshot(admin)->revision == base->revision && !service.snapshot(admin)->persisted, "pre-install failure retains old revision");
    fault = "installed";
    error(ErrorCode::commit_uncertain, [&] { service.replace(admin, base->revision, wanted); });
    auto uncertain = service.snapshot(admin);
    check(leases == 0 && commits == 1, "installed uncertain outcome commits participant exactly once");
    check(uncertain->document == wanted && uncertain->durability_uncertain && uncertain->revision != base->revision,
        "post-install failure exposes changed uncertain revision");
    check(config::JsonFile(temp.directory.get(), "disks.json", getuid()).load()->value == wanted, "uncertain snapshot matches installed primary");
    fault.clear();
    auto confirmed = service.replace(admin, uncertain->revision, wanted);
    check(leases == 0 && commits == 2, "confirmed rewrite drains participant lease");
    check(!confirmed->durability_uncertain && confirmed->revision != uncertain->revision, "uncertain noop syncs again");
    temp.raw("disks.json", "{broken");
    DiskConfigService recovered(temp.directory.get(), getuid());
    check(recovered.snapshot(admin)->recovered && recovered.snapshot(admin)->document == wanted, "corrupt primary recovers backup without discarding extensions");
}
void concurrent_writers_and_drain() {
    Temporary temp;
    auto gate = std::make_shared<ConfigurationGate>();
    Gate entered, release;
    std::atomic<bool> pause{false};
    DiskConfigService service(temp.directory.get(), getuid(), [&](const char* stage) {
        if (pause && std::string_view(stage) == "before_install") { entered.release(); release.wait(); }
    }, gate);
    auto initial = service.snapshot(admin);
    std::atomic<int> won{0}, conflicted{0};
    std::vector<std::future<void>> writers;
    for (int i = 0; i < 12; ++i) writers.emplace_back(std::async(std::launch::async, [&, i] {
        auto value = document(); value["writer"] = i;
        try { service.replace(admin, initial->revision, value); ++won; }
        catch (const ServiceError& error) { check(error.code() == ErrorCode::conflict, "writer only conflicts"); ++conflicted; }
    }));
    for (auto& writer : writers) writer.get();
    check(won == 1 && conflicted == 11, "one revision admits one writer");
    auto before = service.snapshot(admin); auto changed = before->document; changed["drain"] = true;
    pause = true;
    auto write = std::async(std::launch::async, [&] { service.replace(admin, before->revision, changed); });
    entered.wait();
    std::atomic<bool> acquired{false};
    auto transaction = std::async(std::launch::async, [&] { auto exclusive = gate->transaction(); acquired = true; });
    bool draining = false;
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (!draining && std::chrono::steady_clock::now() < deadline) {
        try { service.snapshot(admin); }
        catch (const ServiceError& error) { draining = error.code() == ErrorCode::unavailable; }
        std::this_thread::yield();
    }
    const bool premature = acquired;
    release.release(); write.get(); transaction.get();
    check(draining && !premature && acquired && service.snapshot(admin)->document == changed, "exclusive transaction drains complete registry commit");
}
void full_capacity_and_semantic_corruption() {
    Temporary temp;
    DiskConfigService service(temp.directory.get(), getuid());
    auto wanted = document(); wanted["blob"] = "";
    wanted["blob"] = std::string(DiskConfigService::max_bytes - config::encode_json(wanted).size(), 'x');
    auto saved = service.replace(admin, service.snapshot(admin)->revision, wanted);
    check(saved->encoded->size() == DiskConfigService::max_bytes && saved->document == wanted, "full eight MiB registry retained");
    auto oversized = wanted; oversized["blob"] = oversized["blob"].asString() + 'x';
    error(ErrorCode::resource_exhausted, [&] { service.replace(admin, saved->revision, oversized); });
    check(service.snapshot(admin)->revision == saved->revision, "oversize does not advance revision");
    temp.raw("disks.json", "{\"disks\":false}");
    error(ErrorCode::invalid_argument, [&] { DiskConfigService invalid(temp.directory.get(), getuid()); });
}
void snapshot_publication_and_recovery() {
    Temporary temp;
    auto gate = std::make_shared<ConfigurationGate>();
    TaskService tasks({}, [] { return TaskService::Clock::now(); }, {}, gate);
    std::string fault;
    DiskConfigService service(temp.directory.get(), getuid(), [&](const char* stage) {
        if (fault == stage) throw std::runtime_error("injected disk snapshot fault");
    }, gate, {}, &tasks);
    auto initial = service.snapshot(admin);
    auto held = tasks.disk_config_snapshot(admin);
    auto subscription = tasks.subscribe(admin, held.cursor), hidden = tasks.subscribe(owner, held.cursor);
    error(ErrorCode::unauthenticated, [&] { tasks.disk_config_snapshot({}); });
    error(ErrorCode::permission_denied, [&] { tasks.disk_config_snapshot(owner); });
    auto wanted = document(); wanted["blob"] = "";
    wanted["blob"] = std::string(DiskConfigService::max_bytes - config::encode_json(wanted).size(), 'x');
    auto saved = service.replace(admin, initial->revision, wanted);
    Json::Value metadata;
    check(wire::parse(read_document(tasks, admin, held, metadata)) == initial->document && metadata["revision"] == initial->revision,
        "held disk view remains fixed across commit");
    tasks.release_snapshot(admin, held.id);
    auto events = tasks.poll(admin, subscription);
    check(events.events.size() == 1 && wire::parse(events.events[0].encoded)["kind"] == "disk.config.invalidated",
        "disk commit publishes bounded invalidation");
    check(tasks.poll(owner, hidden).events.empty(), "disk events are administrator only");
    auto page = tasks.disk_config_snapshot(admin, 128u << 10);
    check(read_document(tasks, admin, page, metadata) == *saved->encoded && metadata["revision"] == saved->revision,
        "full eight MiB document reconstructs with fixed version");
    tasks.release_snapshot(admin, page.id);
    wanted.removeMember("blob"); wanted["changed"] = true;
    fault = "before_install";
    error(ErrorCode::io_error, [&] { service.replace(admin, saved->revision, wanted); });
    check(tasks.poll(admin, subscription).events.empty(), "rejected disk write emits no invalidation");
    fault = "installed";
    error(ErrorCode::commit_uncertain, [&] { service.replace(admin, saved->revision, wanted); });
    check(tasks.poll(admin, subscription).events.size() == 1, "installed disk failure invalidates readers");
    page = tasks.disk_config_snapshot(admin);
    check(wire::parse(read_document(tasks, admin, page, metadata)) == wanted && metadata["durability_uncertain"] == true,
        "uncertain metadata and document publish together");
    { auto exclusive = gate->transaction(); exclusive.require_recovery(); }
    error(ErrorCode::unavailable, [&] { tasks.disk_config_snapshot(admin); });
    check(tasks.snapshot_page(admin, page.id, 0).id == page.id, "old fixed disk view survives recovery fault");
    tasks.release_snapshot(admin, page.id);
    { auto exclusive = gate->transaction(); exclusive.recovered(); }
    fault.clear();
    saved = service.replace(admin, service.snapshot(admin)->revision, wanted);
    tasks.poll(admin, subscription);
    service.replace(admin, saved->revision, wanted);
    check(tasks.poll(admin, subscription).events.empty(), "durable disk noop does not invalidate");
}
void disk_read_adapter_and_binding() {
    Temporary temp;
    TaskService tasks;
    auto gate = std::make_shared<ConfigurationGate>();
    bool refused = false;
    try { DiskConfigService mismatch(temp.directory.get(), getuid(), {}, gate, {}, &tasks); }
    catch (const std::invalid_argument&) { refused = true; }
    check(refused && faccessat(temp.directory.get(), "disks.config-owner", F_OK, 0) != 0, "gate mismatch rejected before claim");
    DiskConfigService service(temp.directory.get(), getuid(), {}, {}, {}, &tasks);
    SystemService system([] { return true; }, [] { return "test"; }, "test", tasks.epoch());
    RequestDispatcher dispatcher(system, tasks);
    ClientSession session; session.caller.authorized = true;
    check(!dispatcher.execute(session, "capabilities", {}).isMember("disk_config_snapshot"), "unbound daemon advertises no disk API");
    dispatcher.set_disk_config(&service);
    auto caps = dispatcher.execute(session, "capabilities", {});
    check(caps["service_api_minor"] == 23 && caps["disk_config_snapshot"] == "base64-json-chunks-v1"
        && caps["disk_config_upload"] == "revisioned-chunks-v1", "disk adapter advertises revisioned registry transport");
    ClientSession unauthenticated;
    check(dispatcher.execute(unauthenticated, "disk_config_snapshot", {})["error"]["code"] == "UNAUTHENTICATED", "disk read requires authentication");
    auto status = dispatcher.execute(session, "disk_config_status", {});
    check(status["count"] == 0 && status["revision"] == service.snapshot(admin)->revision, "status describes disk registry version");
    auto page = dispatcher.execute(session, "disk_config_snapshot", {});
    check(page["success"] == true && page["items"][0]["revision"] == status["revision"], "adapter uses versioned fixed document");
    Json::Value release; release["snapshot_id"] = page["snapshot_id"];
    check(dispatcher.execute(session, "resource_snapshot_release", release)["success"] == true, "disk snapshot uses shared release command");
    Json::Value begin; begin["revision"] = status["revision"]; begin["bytes"] = 12;
    auto bad = begin; bad["typo"] = true;
    check(dispatcher.background("disk_config_upload_commit"), "disk upload commit runs on workers");
    check(dispatcher.execute_background(admin, "disk_config_upload_begin", bad)["error"]["code"] == "INVALID_ARGUMENT", "strict disk upload fields");
    check(dispatcher.execute_background({}, "disk_config_upload_begin", begin)["error"]["code"] == "UNAUTHENTICATED", "upload authorization");
    auto upload = dispatcher.execute_background(admin, "disk_config_upload_begin", begin);
    check(upload["success"] == true, "disk upload begin");
    dispatcher.set_disk_config(&service); // Idempotent binding retains the shared manager.
    Json::Value chunk; chunk["upload_id"] = upload["upload_id"]; chunk["offset"] = 0; chunk["data"] = "eyJkaXNrcyI6W119";
    check(dispatcher.execute_background(admin, "disk_config_upload_append", chunk)["received"] == 12, "disk upload strict base64 adapter");
    Json::Value commit; commit["upload_id"] = upload["upload_id"];
    check(dispatcher.execute_background(admin, "disk_config_upload_commit", commit)["persisted"] == true, "disk upload acknowledgement reports durable version");
    check(dispatcher.execute_background(admin, "disk_config_upload_commit", commit)["error"]["code"] == "NOT_FOUND", "disk upload consumed once");
    TaskService different;
    RequestDispatcher wrong(system, different);
    refused = false;
    try { wrong.set_disk_config(&service); } catch (const std::invalid_argument&) { refused = true; }
    check(refused, "adapter rejects events from another service");
}
void disk_upload_capacity_and_domains() {
    Temporary temp;
    DiskConfigService disks(temp.directory.get(), getuid());
    VmConfigService vms(temp.directory.get(), getuid());
    NetworkConfigService networks(temp.directory.get(), getuid());
    ConfigUploads::Clock::time_point now{};
    ConfigUploads uploads(&vms, &networks, [&] { return now; }, {}, &disks);
    auto base = disks.snapshot(admin);
    auto wanted = document(); wanted["blob"] = "";
    wanted["blob"] = std::string(DiskConfigService::max_bytes - config::encode_json(wanted).size(), 'x');
    const auto bytes = config::encode_json(wanted);
    auto disk = uploads.begin_disk(admin, base->revision, bytes.size());
    auto vm = uploads.begin(admin, vms.snapshot(admin)->revision, VmConfigService::max_bytes);
    error(ErrorCode::resource_exhausted, [&] { uploads.begin_network(admin, 8u << 20); });
    auto network = uploads.begin_network(admin, 2);
    auto fourth = uploads.begin_disk(admin, base->revision, 2);
    error(ErrorCode::resource_exhausted, [&] { uploads.begin_disk(admin, base->revision, 2); });
    error(ErrorCode::not_found, [&] { uploads.append_network(admin, disk, 0, "{}"); });
    error(ErrorCode::permission_denied, [&] { uploads.abort_disk({"another-admin", true, true, true}, disk); });
    uploads.abort(admin, vm); uploads.abort_network(admin, network); uploads.abort_disk(admin, fourth);
    for (size_t offset = 0; offset < bytes.size(); offset += ConfigUploads::chunk_bytes) {
        auto chunk = std::string_view(bytes).substr(offset, ConfigUploads::chunk_bytes);
        const auto received = uploads.append_disk(admin, disk, offset, chunk);
        check(uploads.append_disk(admin, disk, offset, chunk) == received, "disk duplicate chunk is idempotent");
    }
    auto saved = uploads.commit_disk(admin, disk);
    check(saved->document == wanted, "full eight MiB disk upload uses shared staging");
    error(ErrorCode::not_found, [&] { uploads.commit_disk(admin, disk); });
    disk = uploads.begin_disk(admin, saved->revision, 2);
    now += ConfigUploads::lifetime;
    error(ErrorCode::not_found, [&] { uploads.append_disk(admin, disk, 0, "{}"); });
}
void disk_upload_conflicts_and_failures() {
    Temporary temp;
    std::string fault;
    DiskConfigService disks(temp.directory.get(), getuid(), [&](const char* stage) {
        if (fault == stage) throw std::runtime_error("disk upload fault");
    });
    ConfigUploads uploads(nullptr, nullptr, [] { return ConfigUploads::Clock::now(); }, {}, &disks);
    auto stage = [&](const std::string& revision, const std::string& bytes) {
        auto id = uploads.begin_disk(admin, revision, bytes.size());
        uploads.append_disk(admin, id, 0, bytes); return id;
    };
    auto wanted = document(); auto base = disks.snapshot(admin);
    auto stale = stage(base->revision, config::encode_json(wanted));
    base = disks.replace(admin, base->revision, wanted);
    error(ErrorCode::conflict, [&] { uploads.commit_disk(admin, stale); });
    error(ErrorCode::not_found, [&] { uploads.commit_disk(admin, stale); });
    auto invalid = stage(base->revision, "{\"disks\":[],\"disks\":[]}");
    error(ErrorCode::invalid_argument, [&] { uploads.commit_disk(admin, invalid); });
    check(disks.snapshot(admin)->revision == base->revision, "invalid upload does not publish");
    for (const auto* boundary : {"before_install", "installed"}) {
        wanted["fault"] = boundary; fault = boundary;
        auto id = stage(base->revision, config::encode_json(wanted));
        const bool installed = fault == "installed";
        error(installed ? ErrorCode::commit_uncertain : ErrorCode::io_error, [&] { uploads.commit_disk(admin, id); });
        error(ErrorCode::not_found, [&] { uploads.commit_disk(admin, id); });
        check((disks.snapshot(admin)->revision != base->revision) == installed, "upload preserves correct installed outcome");
    }
}
}
int main() {
    return run({{"disk_registry_roundtrip_restart_ownership", roundtrip_restart_and_ownership},
        {"disk_structure_transition_validation", structure_transition_validation},
        {"disk_historical_structure_repair", historical_structure_repair},
        {"disk_structure_long_chain_cycle", long_structure_chain},
        {"disk_registry_validation_participants_gate", validation_and_admission},
        {"disk_registry_commit_failure_backup_recovery", commit_failure_and_recovery},
        {"disk_registry_twelve_writers_and_drain", concurrent_writers_and_drain},
        {"disk_registry_full_capacity_semantic_corruption", full_capacity_and_semantic_corruption},
        {"disk_registry_snapshot_events_recovery", snapshot_publication_and_recovery},
        {"disk_registry_read_adapter_binding", disk_read_adapter_and_binding},
        {"disk_upload_full_capacity_shared_domains", disk_upload_capacity_and_domains},
        {"disk_upload_conflict_strict_parse_failures", disk_upload_conflicts_and_failures}});
}
