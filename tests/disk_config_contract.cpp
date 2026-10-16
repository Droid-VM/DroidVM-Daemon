// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "common/identity.h"
#include "services/disk_config.h"
#include "store/vm_ownership.h"
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
}
int main() {
    return run({{"disk_registry_roundtrip_restart_ownership", roundtrip_restart_and_ownership},
        {"disk_registry_validation_participants_gate", validation_and_admission},
        {"disk_registry_commit_failure_backup_recovery", commit_failure_and_recovery},
        {"disk_registry_twelve_writers_and_drain", concurrent_writers_and_drain},
        {"disk_registry_full_capacity_semantic_corruption", full_capacity_and_semantic_corruption}});
}
