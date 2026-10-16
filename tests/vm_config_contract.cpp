// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "snapshot_document.h"
#include "common/identity.h"
#include "services/vm_config.h"
#include "services/vm_config_upload.h"
#include "store/vm_config.h"
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
    std::string path = "/data/local/tmp/droidvm-vm-config-" + random_id(false);
    Fd directory;
    Temporary() {
        check(mkdir(path.c_str(), 0700) == 0, "create isolated directory");
        directory = Fd(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        check(directory.get() >= 0, "open isolated directory");
    }
    ~Temporary() {
        if (auto* scan = opendir(path.c_str())) {
            while (auto* entry = readdir(scan))
                if (std::string_view(entry->d_name) != "." && std::string_view(entry->d_name) != "..")
                    unlinkat(directory.get(), entry->d_name, 0);
            closedir(scan);
        }
        rmdir(path.c_str());
    }
    void raw(const char* name, std::string_view bytes) {
        Fd file(openat(directory.get(), name, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600));
        check(file.get() >= 0 && write(file.get(), bytes.data(), bytes.size()) == static_cast<ssize_t>(bytes.size()), "write fixture");
    }
};
Json::Value vm(std::string name) {
    Json::Value value;
    value["id"] = random_id(true);
    value["name"] = std::move(name);
    value["usb"] = true;
    value["opaque"]["integer"] = Json::Int64(9007199254740993LL);
    value["opaque"]["null"] = Json::Value();
    return value;
}
Json::Value document(Json::Value row) {
    Json::Value result;
    result["vms"] = Json::Value(Json::arrayValue);
    result["vms"].append(std::move(row));
    result["future_root"] = "保留🌏";
    return result;
}
std::string stage(VmConfigUploads& uploads, const std::string& revision, const std::string& bytes) {
    auto id = uploads.begin(admin, revision, bytes.size());
    for (size_t offset = 0; offset < bytes.size(); offset += VmConfigUploads::chunk_bytes) {
        auto chunk = std::string_view(bytes).substr(offset, VmConfigUploads::chunk_bytes);
        check(uploads.append(admin, id, offset, chunk) == offset + chunk.size(), "upload accepts contiguous bounded chunks");
    }
    return id;
}
std::string stage_network(ConfigUploads& uploads, const std::string& bytes) {
    auto id = uploads.begin_network(admin, bytes.size());
    for (size_t offset = 0; offset < bytes.size(); offset += ConfigUploads::chunk_bytes) {
        auto chunk = std::string_view(bytes).substr(offset, ConfigUploads::chunk_bytes);
        check(uploads.append_network(admin, id, offset, chunk) == offset + chunk.size(), "network chunk accepted");
    }
    return id;
}
Json::Value imported_network() {
    Json::Value value;
    value["id"] = random_id(true); value["name"] = "imported";
    value["schema"] = 2; value["bridge_name"] = "brtest";
    return value;
}
void shared_upload_limits_and_domains() {
    Temporary temp;
    VmConfigService vms(temp.directory.get(), getuid());
    NetworkConfigService networks(temp.directory.get(), getuid());
    ConfigUploads::Clock::time_point now{};
    ConfigUploads uploads(&vms, &networks, [&] { return now; });
    const auto revision = vms.snapshot(admin)->revision;
    auto network = uploads.begin_network(admin, NetworkConfigService::max_import_bytes);
    error(ErrorCode::resource_exhausted, [&] { uploads.begin(admin, revision, VmConfigService::max_bytes); });
    error(ErrorCode::not_found, [&] { uploads.abort(admin, network); });
    error(ErrorCode::not_found, [&] { uploads.append(admin, network, 0, "{}"); });
    error(ErrorCode::not_found, [&] { uploads.commit(admin, network); });
    error(ErrorCode::permission_denied, [&] { uploads.abort_network({"another-admin", true, true, true}, network); });
    uploads.abort_network(admin, network);
    auto vm = uploads.begin(admin, revision, 2);
    error(ErrorCode::not_found, [&] { uploads.abort_network(admin, vm); });
    for (size_t i = 1; i < ConfigUploads::max_uploads; ++i) uploads.begin_network(admin, 2);
    error(ErrorCode::resource_exhausted, [&] { uploads.begin(admin, revision, 2); });
    now += ConfigUploads::lifetime;
    network = uploads.begin_network(admin, 2);
    error(ErrorCode::not_found, [&] { uploads.append(admin, vm, 0, "{}"); });
    uploads.append_network(admin, network, 0, "{}");
    check(uploads.append_network(admin, network, 0, "{}") == 2, "network repeated chunk is idempotent");
    error(ErrorCode::conflict, [&] { uploads.append_network(admin, network, 0, "[]"); });
    error(ErrorCode::invalid_argument, [&] { uploads.commit_network(admin, network); });
    error(ErrorCode::not_found, [&] { uploads.commit_network(admin, network); });
}
void network_upload_full_capacity_and_conflict() {
    Temporary temp;
    VmConfigService vms(temp.directory.get(), getuid());
    NetworkConfigService networks(temp.directory.get(), getuid());
    ConfigUploads uploads(&vms, &networks);
    auto value = imported_network();
    Json::Value document, operation; operation["expected"] = Json::Value(); operation["config"] = value;
    document["operations"].append(operation);
    auto bytes = wire::stringify(document);
    bytes.resize(NetworkConfigService::max_import_bytes, ' ');
    const auto upload = stage_network(uploads, bytes);
    auto result = uploads.commit_network(admin, upload);
    check(result.size() == 1 && result[0] == value["id"] && networks.get(admin, value["id"].asString()) == value,
        "maximum network upload commits through atomic service");
    error(ErrorCode::not_found, [&] { uploads.commit_network(admin, upload); });
    document["operations"][0]["expected"] = value;
    document["operations"][0]["config"]["name"] = "stale";
    const auto stale = stage_network(uploads, wire::stringify(document));
    value["name"] = "concurrent"; networks.update(admin, value);
    error(ErrorCode::conflict, [&] { uploads.commit_network(admin, stale); });
    check(networks.get(admin, value["id"].asString())["name"] == "concurrent", "staged import cannot overwrite new target");
    const auto vm = uploads.begin(admin, vms.snapshot(admin)->revision, VmConfigService::max_bytes);
    uploads.abort(admin, vm);
}
void network_upload_inflight_reservation() {
    Temporary temp;
    Gate reached, proceed;
    NetworkConfigService networks(temp.directory.get(), getuid(), [&](const char* stage) {
        if (std::string_view(stage) == "before_install") { reached.release(); proceed.wait(); }
    });
    VmConfigService vms(temp.directory.get(), getuid());
    ConfigUploads::Clock::time_point now{};
    ConfigUploads uploads(&vms, &networks, [&] { return now; });
    Json::Value document, operation; operation["expected"] = Json::Value(); operation["config"] = imported_network();
    document["operations"].append(operation);
    const auto id = stage_network(uploads, wire::stringify(document));
    auto commit = std::async(std::launch::async, [&] { return uploads.commit_network(admin, id); });
    reached.wait();
    now += ConfigUploads::lifetime;
    error(ErrorCode::conflict, [&] { uploads.abort_network(admin, id); });
    error(ErrorCode::conflict, [&] { uploads.append_network(admin, id, 0, "{}"); });
    const auto revision = vms.snapshot(admin)->revision;
    for (size_t i = 1; i < ConfigUploads::max_uploads; ++i) uploads.begin(admin, revision, 2);
    error(ErrorCode::resource_exhausted, [&] { uploads.begin_network(admin, 2); });
    proceed.release();
    check(commit.get().size() == 1, "inflight import retains shared slot through publication");
}
void ownership_gate() {
    Temporary temp;
    config::require_legacy_vm_config(temp.directory.get(), getuid());
    {
        Fd legacy(openat(temp.directory.get(), "vms.config-owner", O_RDWR | O_CLOEXEC));
        struct flock lock{}; lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET;
        check(fcntl(legacy.get(), F_SETLK, &lock) == 0, "take Java-compatible POSIX write lock");
        bool refused = false;
        try { config::claim_vm_config(temp.directory.get(), getuid()); } catch (const std::exception&) { refused = true; }
        check(refused, "native transition excludes legacy write in progress");
        struct stat info{};
        check(fstat(legacy.get(), &info) == 0 && info.st_size == 0, "busy transition never installs ownership");
    }
    config::claim_vm_config(temp.directory.get(), getuid());
    config::claim_vm_config(temp.directory.get(), getuid());
    bool refused = false;
    try { config::require_legacy_vm_config(temp.directory.get(), getuid()); } catch (const std::exception&) { refused = true; }
    check(refused, "persistent owner refuses legacy even after lock release");
    {
        Fd file(openat(temp.directory.get(), "vms.config-owner", O_RDWR | O_TRUNC | O_CLOEXEC));
        check(write(file.get(), "native-", 7) == 7, "inject interrupted marker");
    }
    config::claim_vm_config(temp.directory.get(), getuid());
    {
        Fd file(openat(temp.directory.get(), "vms.config-owner", O_RDWR | O_CLOEXEC));
        char value[10];
        check(read(file.get(), value, 10) == 10 && std::string_view(value, 10) == "native-v1\n", "recover interrupted ownership marker");
        check(pwrite(file.get(), "unknown", 7, 0) == 7, "inject unknown owner");
    }
    refused = false;
    try { config::claim_vm_config(temp.directory.get(), getuid()); } catch (const std::exception&) { refused = true; }
    check(refused, "unknown marker refuses takeover");
    Temporary links;
    check(symlinkat("target", links.directory.get(), "vms.config-owner") == 0, "create unsafe gate link");
    refused = false;
    try { config::claim_vm_config(links.directory.get(), getuid()); } catch (const std::exception&) { refused = true; }
    check(refused && faccessat(links.directory.get(), "target", F_OK, 0) != 0, "gate never follows symlink");
}
void migration_roundtrip_and_revision() {
    Temporary temp;
    config::JsonFile disk(temp.directory.get(), "vms.json", getuid());
    auto original = document(vm("legacy"));
    disk.save(original);
    VmConfigService service(temp.directory.get(), getuid());
    auto initial = service.snapshot(admin);
    check(initial->document["vms"][0] == config::migrate_vm(original["vms"][0]), "reuse VM migration");
    check(initial->document["future_root"] == original["future_root"], "root extension retained");
    check(disk.load()->value == original, "loading migration never rewrites file");
    check(initial->persisted && initial->durability_uncertain, "reopened durability needs confirmation");
    auto edited = initial->document;
    edited["vms"][0]["memory_mb"] = 512.0;
    auto saved = service.replace(admin, initial->revision, edited);
    check(saved->revision != initial->revision && !saved->durability_uncertain, "save rotates revision after durability confirmation");
    check(disk.load()->value == saved->document, "disk and memory agree including unknown fields");
    check(saved->document["vms"][0]["memory_mb"].type() == Json::intValue, "memory projection uses JSONObject-compatible persisted number types");
    check(service.replace(admin, saved->revision, saved->document) == saved, "durable no-op retains revision and view");
    struct stat info{};
    check(fstatat(temp.directory.get(), "vms.json", &info, 0) == 0 && (info.st_mode & 0777) == 0600 && info.st_uid == getuid(), "App-readable private ownership");
    VmConfigService restart(temp.directory.get(), getuid());
    check(restart.snapshot(admin)->revision != saved->revision, "restart invalidates revisions");
    error(ErrorCode::conflict, [&] { restart.replace(admin, saved->revision, saved->document); });
}
void empty_permissions_and_validation() {
    Temporary temp;
    unsigned writes = 0;
    VmConfigService service(temp.directory.get(), getuid(), [&](const char* stage) { if (std::string_view(stage) == "before_write") ++writes; });
    auto empty = service.snapshot(admin);
    check(!empty->persisted && empty->document["vms"].empty(), "missing inventory starts empty without writing");
    error(ErrorCode::unauthenticated, [&] { service.snapshot({}); });
    error(ErrorCode::permission_denied, [&] { service.snapshot(owner); });
    error(ErrorCode::unauthenticated, [&] { service.replace({}, empty->revision, {}); });
    error(ErrorCode::permission_denied, [&] { service.replace(owner, empty->revision, {}); });
    error(ErrorCode::invalid_argument, [&] { service.replace(admin, "", {}); });
    error(ErrorCode::invalid_argument, [&] { service.replace(admin, empty->revision, Json::Value()); });
    error(ErrorCode::invalid_argument, [&] { service.replace(admin, empty->revision, Json::Value(Json::objectValue)); });
    auto malformed = empty->document; malformed["vms"] = Json::Value();
    error(ErrorCode::invalid_argument, [&] { service.replace(admin, empty->revision, malformed); });
    auto missing_name = vm("bad"); missing_name.removeMember("name");
    error(ErrorCode::invalid_argument, [&] { service.replace(admin, empty->revision, document(missing_name)); });
    auto duplicate = document(vm("same")); duplicate["vms"].append(duplicate["vms"][0]);
    error(ErrorCode::conflict, [&] { service.replace(admin, empty->revision, duplicate); });
    duplicate["vms"][1]["id"] = random_id(true);
    error(ErrorCode::conflict, [&] { service.replace(admin, empty->revision, duplicate); });
    check(writes == 0 && service.snapshot(admin) == empty, "rejected edits do not touch disk or revision");
    auto saved = service.replace(admin, empty->revision, empty->document);
    check(writes == 1 && saved->persisted && saved->revision != empty->revision, "explicit empty save creates inventory");
}
void twelve_writers_and_stale_noop() {
    Temporary temp;
    VmConfigService service(temp.directory.get(), getuid());
    auto initial = service.snapshot(admin);
    std::atomic<int> success{0}, conflict{0}, failure{0};
    std::vector<std::thread> writers;
    for (int i = 0; i < 12; ++i) writers.emplace_back([&, i] {
        try { service.replace(admin, initial->revision, document(vm("writer " + std::to_string(i)))); ++success; }
        catch (const ServiceError& error) { if (error.code() == ErrorCode::conflict) ++conflict; else ++failure; }
        catch (...) { ++failure; }
    });
    for (auto& writer : writers) writer.join();
    check(success == 1 && conflict == 11 && failure == 0, "exactly one writer wins shared base revision");
    auto current = service.snapshot(admin);
    error(ErrorCode::conflict, [&] { service.replace(admin, initial->revision, current->document); });
    check(service.snapshot(admin) == current && initial->document["vms"].empty(), "stale no-op rejected and held snapshot unchanged");
}
void failure_visibility_and_retry() {
    Temporary temp;
    std::string fail_stage;
    bool block = false;
    Gate saving, proceed;
    VmConfigService service(temp.directory.get(), getuid(), [&](const char* stage) {
        if (fail_stage == stage) throw std::runtime_error("injected failure");
        if (block && std::string_view(stage) == "before_install") { saving.release(); proceed.wait(); }
    });
    auto empty = service.snapshot(admin);
    auto initial = service.replace(admin, empty->revision, document(vm("initial")));
    auto edit = initial->document; edit["vms"][0]["name"] = "updated";
    fail_stage = "before_install";
    error(ErrorCode::io_error, [&] { service.replace(admin, initial->revision, edit); });
    check(service.snapshot(admin) == initial, "pre-install error preserves snapshot and token");
    fail_stage.clear(); block = true;
    auto writer = std::async(std::launch::async, [&] { return service.replace(admin, initial->revision, edit); });
    saving.wait();
    auto reader = std::async(std::launch::async, [&] { return service.snapshot(admin); });
    bool ready = reader.wait_for(500ms) == std::future_status::ready;
    proceed.release(); auto installed = writer.get(); block = false;
    check(ready && reader.get() == initial, "readers do not wait for disk IO");
    edit["vms"][0]["name"] = "uncertain"; fail_stage = "installed";
    error(ErrorCode::commit_uncertain, [&] { service.replace(admin, installed->revision, edit); });
    auto uncertain = service.snapshot(admin);
    check(uncertain->document == edit && uncertain->durability_uncertain && uncertain->revision != installed->revision,
        "post-rename failure publishes installed data with new revision");
    error(ErrorCode::conflict, [&] { service.replace(admin, installed->revision, edit); });
    fail_stage.clear();
    auto confirmed = service.replace(admin, uncertain->revision, uncertain->document);
    check(!confirmed->durability_uncertain && confirmed->revision != uncertain->revision, "unchanged retry confirms durability");
    VmConfigService reopened(temp.directory.get(), getuid());
    check(reopened.snapshot(admin)->document == confirmed->document, "restart agrees with committed state");
}
void recovery_and_corruption() {
    Temporary temp;
    config::JsonFile disk(temp.directory.get(), "vms.json", getuid());
    const auto original = document(vm("backup"));
    disk.save(original); disk.save(document(vm("primary")));
    temp.raw("vms.json", "{broken");
    VmConfigService service(temp.directory.get(), getuid());
    auto recovered = service.snapshot(admin);
    check(recovered->recovered && recovered->document["vms"][0]["name"] == "backup", "recover previous inventory");
    auto repaired = service.replace(admin, recovered->revision, recovered->document);
    check(!repaired->recovered && !repaired->durability_uncertain, "repair flags cleared only after durable save");
    check(faccessat(temp.directory.get(), "vms.json.corrupt", F_OK, 0) == 0, "corrupt primary retained as evidence");
    Temporary invalid;
    invalid.raw("vms.json", "{\"vms\":[{\"name\":\"missing id\"}]}");
    error(ErrorCode::invalid_argument, [&] { VmConfigService denied(invalid.directory.get(), getuid()); });
    check(faccessat(invalid.directory.get(), "vms.json.bak", F_OK, 0) != 0, "semantically invalid file not replaced by empty inventory");
    for (const auto* text : {"{\"vms\":[],\"vms\":[]}", "{/* comment */\"vms\":[]}"}) {
        invalid.raw("vms.json", text);
        bool refused = false;
        try { VmConfigService denied(invalid.directory.get(), getuid()); }
        catch (const std::exception&) { refused = true; }
        check(refused, "VM inventory retains duplicate-key/comment rejection");
        check(faccessat(invalid.directory.get(), "vms.json.bak", F_OK, 0) != 0, "invalid syntax never writes an empty backup");
    }
}
void capacity_before_side_effects() {
    Temporary temp;
    unsigned writes = 0;
    VmConfigService service(temp.directory.get(), getuid(), [&](const char* stage) { if (std::string_view(stage) == "before_write") ++writes; });
    auto initial = service.snapshot(admin);
    auto oversized = document(vm("oversized"));
    oversized["vms"][0]["opaque"]["large"] = std::string(VmConfigService::max_bytes, 'x');
    error(ErrorCode::resource_exhausted, [&] { service.replace(admin, initial->revision, oversized); });
    check(writes == 0 && service.snapshot(admin) == initial, "capacity rejection precedes side effects");
    // Do not inherit the network store's smaller file/count limits for VMs.
    oversized["vms"][0]["opaque"]["large"] = std::string((8u << 20) + 1, 'x');
    auto saved = service.replace(admin, initial->revision, oversized);
    VmConfigService reopened(temp.directory.get(), getuid());
    check(reopened.snapshot(admin)->document == saved->document, "legacy VM file capacity above 8 MiB survives restart");
    Json::Value small(Json::arrayValue), create;
    create["op"] = "create"; create["config"] = vm("small additional VM"); small.append(create);
    saved = service.apply(admin, saved->revision, small);
    check(saved->document["vms"].size() == 2 && saved->document["vms"][0] == reopened.snapshot(admin)->document["vms"][0],
        "small batch edits inventory larger than a transport frame without resending large VM");
    auto many = initial->document;
    for (int i = 0; i < 1025; ++i) many["vms"].append(vm("vm " + std::to_string(i)));
    auto populated = service.replace(admin, saved->revision, many);
    check(populated->document["vms"].size() == 1025, "network count quota is not imposed on VM inventory");
}
Json::Value operation(const char* kind, Json::Value value) {
    Json::Value result; result["op"] = kind;
    if (std::string_view(kind) == "delete") result["id"] = value["id"];
    else result["config"] = std::move(value);
    return result;
}
void atomic_batches() {
    Temporary temp;
    unsigned writes = 0;
    VmConfigService service(temp.directory.get(), getuid(), [&](const char* stage) { if (std::string_view(stage) == "before_write") ++writes; });
    auto empty = service.snapshot(admin);
    auto doc = document(vm("one")); doc["vms"].append(vm("two")); doc["vms"].append(vm("three"));
    auto initial = service.replace(admin, empty->revision, doc);
    auto one = initial->document["vms"][0], two = initial->document["vms"][1];
    one["name"] = "two"; two["name"] = "one";
    Json::Value edits(Json::arrayValue);
    edits.append(operation("replace", one)); edits.append(operation("replace", two));
    edits.append(operation("delete", initial->document["vms"][2]));
    auto added = vm("four"); edits.append(operation("create", added));
    auto saved = service.apply(admin, initial->revision, edits);
    check(writes == 2 && saved->document["vms"].size() == 3, "whole batch persists once");
    check(saved->document["future_root"] == initial->document["future_root"] && saved->document["vms"][0] == one && saved->document["vms"][1] == two,
        "atomic name swap preserves order and extensions");
    check(saved->document["vms"][2]["id"] == added["id"], "new VM appended after kept rows");
    error(ErrorCode::conflict, [&] { service.apply(admin, initial->revision, Json::Value(Json::arrayValue)); });
    check(service.apply(admin, saved->revision, Json::Value(Json::arrayValue)) == saved && writes == 2, "durable empty batch is a no-op");
    edits.clear(); edits.append(operation("replace", one)); edits.append(operation("delete", vm("missing")));
    error(ErrorCode::not_found, [&] { service.apply(admin, saved->revision, edits); });
    edits.clear(); edits.append(operation("create", vm("one")));
    error(ErrorCode::conflict, [&] { service.apply(admin, saved->revision, edits); });
    check(service.snapshot(admin) == saved && writes == 2, "invalid final state and late operation failure leave disk and view unchanged");
}
void batch_validation_and_permissions() {
    Temporary temp;
    VmConfigService service(temp.directory.get(), getuid());
    auto initial = service.snapshot(admin);
    error(ErrorCode::unauthenticated, [&] { service.apply({}, "", {}); });
    error(ErrorCode::permission_denied, [&] { service.apply(owner, "", {}); });
    error(ErrorCode::invalid_argument, [&] { service.apply(admin, initial->revision, Json::Value(Json::objectValue)); });
    Json::Value edits(Json::arrayValue);
    auto valid = operation("create", vm("one"));
    for (auto invalid : {Json::Value(), Json::Value("create"), Json::Value(Json::objectValue)}) {
        edits.clear(); edits.append(invalid);
        error(ErrorCode::invalid_argument, [&] { service.apply(admin, initial->revision, edits); });
    }
    for (const auto* field : {"op", "config"}) {
        auto invalid = valid; invalid.removeMember(field); edits.clear(); edits.append(invalid);
        error(ErrorCode::invalid_argument, [&] { service.apply(admin, initial->revision, edits); });
    }
    auto invalid = valid; invalid["op"] = "upsert"; edits.clear(); edits.append(invalid);
    error(ErrorCode::invalid_argument, [&] { service.apply(admin, initial->revision, edits); });
    invalid = valid; invalid["extra"] = true; edits[0] = invalid;
    error(ErrorCode::invalid_argument, [&] { service.apply(admin, initial->revision, edits); });
    invalid = valid; invalid["config"].removeMember("id"); edits[0] = invalid;
    error(ErrorCode::invalid_argument, [&] { service.apply(admin, initial->revision, edits); });
    edits[0] = valid; edits.append(valid);
    error(ErrorCode::invalid_argument, [&] { service.apply(admin, initial->revision, edits); });
    check(service.snapshot(admin) == initial && !initial->persisted, "invalid batches never initialize file");
}
void snapshots_events_and_failure() {
    Temporary temp;
    TaskService tasks;
    std::string fail;
    VmConfigService service(temp.directory.get(), getuid(), [&](const char* stage) {
        if (fail == stage) throw std::runtime_error("injected failure");
    }, {}, &tasks);
    auto page = tasks.vm_config_snapshot(admin);
    check(page.cursor.epoch == tasks.epoch() && page.cursor.sequence == 1, "VM snapshot uses shared task epoch and sequence");
    auto subscription = tasks.subscribe(admin, page.cursor);
    auto hidden = tasks.subscribe(owner, page.cursor);
    error(ErrorCode::permission_denied, [&] { tasks.vm_config_snapshot(owner); });
    error(ErrorCode::permission_denied, [&] { tasks.snapshot_page(owner, page.id, 0); });
    auto initial = service.snapshot(admin);
    auto doc = document(vm("large 🌏")); doc["vms"][0]["opaque"]["text"] = std::string(150000, 'x');
    auto saved = service.replace(admin, initial->revision, doc);
    Json::Value header;
    check(wire::parse(read_document(tasks, admin, page, header)) == initial->document && header["revision"] == initial->revision, "held document snapshot remains old after commit");
    tasks.release_snapshot(admin, page.id);
    auto events = tasks.poll(admin, subscription);
    check(events.events.size() == 1 && wire::parse(events.events[0].encoded)["kind"] == "vm.config.invalidated", "commit emits invalidation event");
    check(tasks.poll(owner, hidden).events.empty(), "configuration events are administrator only");
    page = tasks.vm_config_snapshot(admin, 128u << 10);
    check(read_document(tasks, admin, page, header) == *saved->encoded && header["revision"] == saved->revision, "multi-page document reconstructs exact persisted JSON");
    tasks.release_snapshot(admin, page.id);
    fail = "before_install"; doc = saved->document; doc["vms"][0]["name"] = "changed";
    error(ErrorCode::io_error, [&] { service.replace(admin, saved->revision, doc); });
    check(tasks.poll(admin, subscription).events.empty(), "pre-install failure publishes no event");
    fail = "installed";
    error(ErrorCode::commit_uncertain, [&] { service.replace(admin, saved->revision, doc); });
    check(tasks.poll(admin, subscription).events.size() == 1, "installed failure publishes invalidation");
    page = tasks.vm_config_snapshot(admin);
    read_document(tasks, admin, page, header);
    check(header["durability_uncertain"].asBool() && header["revision"] == service.snapshot(admin)->revision, "uncertain snapshot metadata follows installed version");
    tasks.release_snapshot(admin, page.id);
    fail.clear();
    auto confirmed = service.replace(admin, service.snapshot(admin)->revision, doc);
    tasks.poll(admin, subscription);
    service.replace(admin, confirmed->revision, confirmed->document);
    check(tasks.poll(admin, subscription).events.empty(), "durable no-op produces no invalidation");
}
void full_capacity_document_snapshot() {
    Temporary temp;
    TaskService tasks;
    VmConfigService service(temp.directory.get(), getuid(), {}, {}, &tasks);
    auto initial = service.snapshot(admin);
    auto seed = document(vm("full capacity")); seed["padding"] = "";
    auto normalized = service.replace(admin, initial->revision, seed);
    seed = normalized->document;
    seed["padding"] = std::string(VmConfigService::max_bytes - normalized->encoded->size(), 'x');
    VmConfigUploads uploads(service);
    const auto encoded = config::encode_json(seed, VmConfigService::max_bytes);
    auto upload = stage(uploads, normalized->revision, encoded);
    check(service.snapshot(admin) == normalized, "full capacity staging does not publish configuration");
    auto full = uploads.commit(admin, upload);
    check(full->encoded->size() == VmConfigService::max_bytes, "exact 16 MiB fixture");
    auto page = tasks.vm_config_snapshot(admin);
    Json::Value header;
    check(read_document(tasks, admin, page, header) == *full->encoded, "full capacity document crosses frame boundaries losslessly");
    error(ErrorCode::resource_exhausted, [&] { tasks.vm_config_snapshot(admin); });
    tasks.release_snapshot(admin, page.id);
    auto fresh = tasks.vm_config_snapshot(admin);
    tasks.release_snapshot(admin, fresh.id);
    error(ErrorCode::snapshot_expired, [&] { tasks.snapshot_page(admin, fresh.id, 0); });
}
void upload_limits_scope_and_offsets() {
    Temporary temp;
    VmConfigService service(temp.directory.get(), getuid());
    auto revision = service.snapshot(admin)->revision;
    VmConfigUploads::Clock::time_point now{};
    VmConfigUploads uploads(service, [&] { return now; });
    error(ErrorCode::unauthenticated, [&] { uploads.begin({}, revision, 1); });
    error(ErrorCode::permission_denied, [&] { uploads.begin(owner, revision, 1); });
    error(ErrorCode::invalid_argument, [&] { uploads.begin(admin, revision, 0); });
    error(ErrorCode::invalid_argument, [&] { uploads.begin(admin, revision, VmConfigService::max_bytes + 1); });
    auto id = uploads.begin(admin, revision, 6);
    const CallContext stranger{"stranger", true, true, true};
    error(ErrorCode::permission_denied, [&] { uploads.append(stranger, id, 0, "abc"); });
    error(ErrorCode::permission_denied, [&] { uploads.abort(stranger, id); });
    check(uploads.append(admin, id, 0, "abc") == 3 && uploads.append(admin, id, 0, "abc") == 3, "identical chunk replay is idempotent");
    error(ErrorCode::conflict, [&] { uploads.append(admin, id, 1, "bad"); });
    error(ErrorCode::invalid_argument, [&] { uploads.append(admin, id, 4, "x"); });
    error(ErrorCode::invalid_argument, [&] { uploads.append(admin, id, 3, "toolong"); });
    error(ErrorCode::invalid_argument, [&] { uploads.commit(admin, id); });
    uploads.abort(admin, id);
    error(ErrorCode::not_found, [&] { uploads.commit(admin, id); });
    auto large = uploads.begin(admin, revision, VmConfigService::max_bytes);
    error(ErrorCode::resource_exhausted, [&] { uploads.begin(admin, revision, VmConfigService::max_bytes); });
    error(ErrorCode::invalid_argument, [&] { uploads.append(admin, large, 0, std::string(VmConfigUploads::chunk_bytes + 1, 'x')); });
    uploads.abort(admin, large);
    std::vector<std::string> ids;
    for (size_t i = 0; i < VmConfigUploads::max_uploads; ++i) ids.push_back(uploads.begin(admin, revision, 1));
    error(ErrorCode::resource_exhausted, [&] { uploads.begin(admin, revision, 1); });
    now += VmConfigUploads::lifetime;
    error(ErrorCode::not_found, [&] { uploads.append(admin, ids[0], 0, "x"); });
    uploads.abort(admin, uploads.begin(admin, revision, VmConfigService::max_bytes));
    check(!service.snapshot(admin)->persisted, "staging, quota failures and expiry never write config");
}
void upload_strict_parse_and_stale_revision() {
    Temporary temp;
    VmConfigService service(temp.directory.get(), getuid());
    VmConfigUploads uploads(service);
    auto initial = service.snapshot(admin);
    for (const auto& bytes : {std::string("{\"vms\":[],\"vms\":[]}"), std::string("{/*comment*/\"vms\":[]}"), std::string("[]"),
            std::string("{\"vms\":[]} trailing"), std::string("{\"vms\":[]}\0", 11), std::string("{}")}) {
        auto id = stage(uploads, initial->revision, bytes);
        error(ErrorCode::invalid_argument, [&] { uploads.commit(admin, id); });
        error(ErrorCode::not_found, [&] { uploads.commit(admin, id); });
    }
    auto id = stage(uploads, initial->revision, "{\"vms\":[]}");
    auto committed = service.replace(admin, initial->revision, document(vm("winner")));
    error(ErrorCode::conflict, [&] { uploads.commit(admin, id); });
    error(ErrorCode::not_found, [&] { uploads.commit(admin, id); });
    error(ErrorCode::conflict, [&] { uploads.begin(admin, initial->revision, 1); });
    check(service.snapshot(admin) == committed, "stale upload cannot overwrite winning edit");
}
void upload_commit_faults_and_inflight_budget() {
    Temporary temp;
    std::string failure;
    Gate saving, proceed;
    bool block = false;
    VmConfigService service(temp.directory.get(), getuid(), [&](const char* point) {
        if (failure == point) throw std::runtime_error("injected failure");
        if (block && std::string_view(point) == "before_install") { saving.release(); proceed.wait(); }
    });
    VmConfigUploads::Clock::time_point now{};
    VmConfigUploads uploads(service, [&] { return now; });
    auto initial = service.snapshot(admin);
    const auto bytes = wire::stringify(document(vm("upload")));
    auto id = stage(uploads, initial->revision, bytes);
    failure = "before_install";
    error(ErrorCode::io_error, [&] { uploads.commit(admin, id); });
    check(service.snapshot(admin) == initial, "upload pre-install failure preserves snapshot");
    error(ErrorCode::not_found, [&] { uploads.commit(admin, id); });
    id = stage(uploads, initial->revision, bytes); failure = "installed";
    error(ErrorCode::commit_uncertain, [&] { uploads.commit(admin, id); });
    auto uncertain = service.snapshot(admin);
    check(uncertain->durability_uncertain, "upload installed failure exposes uncertainty");
    error(ErrorCode::not_found, [&] { uploads.commit(admin, id); });
    failure.clear(); block = true;
    id = stage(uploads, uncertain->revision, bytes);
    auto commit = std::async(std::launch::async, [&] { return uploads.commit(admin, id); });
    saving.wait();
    struct Release { Gate& gate; ~Release() { gate.release(); } } release{proceed};
    now += VmConfigUploads::lifetime;
    error(ErrorCode::conflict, [&] { uploads.abort(admin, id); });
    error(ErrorCode::conflict, [&] { uploads.append(admin, id, 0, "x"); });
    error(ErrorCode::conflict, [&] { uploads.commit(admin, id); });
    for (size_t i = 1; i < VmConfigUploads::max_uploads; ++i) uploads.begin(admin, uncertain->revision, 1);
    error(ErrorCode::resource_exhausted, [&] { uploads.begin(admin, uncertain->revision, 1); });
    proceed.release();
    check(!commit.get()->durability_uncertain, "in-flight expiry cannot interrupt commit or release its reservation");
}
void strict_base64_chunks() {
    check(wire::decode_base64("Zg==", 1) == "f" && wire::decode_base64("Zm8=", 2) == "fo" && wire::decode_base64("Zm9v", 3) == "foo", "canonical base64 padding");
    check(wire::decode_base64("AP+A", 3) == std::string("\0\xff\x80", 3), "base64 binary bytes");
    for (auto text : {"Zg", "Zg=", " Zg==", "Zg==\n", "Zh==", "Zm9=", "=m9v", "Zg==Zg==", "Zg=A", "!!!!"}) {
        bool rejected = false;
        try { wire::decode_base64(text, 100); } catch (const std::invalid_argument&) { rejected = true; }
        check(rejected, "noncanonical base64 is rejected");
    }
    bool bounded = false;
    try { wire::decode_base64("Zm9v", 2); } catch (const std::length_error&) { bounded = true; }
    check(bounded, "base64 decoded output respects budget");
}
}
int main(int argc, char** argv) {
    if (argc == 4 && std::string_view(argv[1]) == "--ownership") {
        try {
            Fd directory(open(argv[3], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
            struct stat info{};
            check(directory.get() >= 0 && fstat(directory.get(), &info) == 0, "open isolated ownership directory");
            if (std::string_view(argv[2]) == "claim") config::claim_vm_config(directory.get(), info.st_uid);
            else if (std::string_view(argv[2]) == "legacy") config::require_legacy_vm_config(directory.get(), info.st_uid);
            else throw std::runtime_error("invalid ownership probe mode");
            return 0;
        } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    }
    return run({{"ownership_transition", ownership_gate}, {"migration_roundtrip_revision", migration_roundtrip_and_revision},
        {"empty_permissions_validation", empty_permissions_and_validation},
        {"twelve_writers_stale_noop", twelve_writers_and_stale_noop},
        {"failure_visibility_retry", failure_visibility_and_retry},
        {"recovery_semantic_corruption", recovery_and_corruption},
        {"capacity_before_side_effects", capacity_before_side_effects},
        {"atomic_batches", atomic_batches}, {"batch_validation_permissions", batch_validation_and_permissions},
        {"snapshots_events_failure", snapshots_events_and_failure}, {"full_capacity_snapshot", full_capacity_document_snapshot},
        {"upload_limits_scope_offsets", upload_limits_scope_and_offsets}, {"upload_strict_parse_stale_revision", upload_strict_parse_and_stale_revision},
        {"upload_commit_faults_inflight_budget", upload_commit_faults_and_inflight_budget}, {"strict_base64_chunks", strict_base64_chunks},
        {"shared_upload_limits_domains", shared_upload_limits_and_domains},
        {"network_upload_full_capacity_conflict", network_upload_full_capacity_and_conflict},
        {"network_upload_inflight_reservation", network_upload_inflight_reservation}});
}
