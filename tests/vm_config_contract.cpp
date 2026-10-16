// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "common/identity.h"
#include "services/vm_config.h"
#include "store/vm_config.h"
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
}
int main() {
    return run({{"migration_roundtrip_revision", migration_roundtrip_and_revision},
        {"empty_permissions_validation", empty_permissions_and_validation},
        {"twelve_writers_stale_noop", twelve_writers_and_stale_noop},
        {"failure_visibility_retry", failure_visibility_and_retry},
        {"recovery_semantic_corruption", recovery_and_corruption},
        {"capacity_before_side_effects", capacity_before_side_effects},
        {"atomic_batches", atomic_batches}, {"batch_validation_permissions", batch_validation_and_permissions}});
}
