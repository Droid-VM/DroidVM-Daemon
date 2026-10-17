// SPDX-License-Identifier: GPL-3.0-or-later
// vm_export/vm_import building blocks: tar, compression, the .vmpkg layout,
// volumes, manifests and the plan helpers, including corrupt input.
#include "pkg/plan.h"
#include "pkg/writer.h"
#include "pkg/service.h"
#include "pkg/disk_operation.h"
#include "services/legacy_events.h"
#include "services/vm.h"
#include "services/network_config.h"
#include "services/configuration.h"
#include "runtime/child.h"
#include "vm/qemu_command.h"
#include "store/network_config.h"
#include "common/identity.h"
#include "common/wire.h"
#include <cstring>
#include <dirent.h>
#include <optional>
#include <fcntl.h>
#include <functional>
#include <iostream>
#include <map>
#include <random>
#include <sys/stat.h>
#include <unistd.h>
#include <chrono>
#include <thread>

using namespace droidvm;
using namespace droidvm::pkg;
namespace {
void check(bool value, const std::string& detail) { if (!value) throw std::runtime_error(detail); }
void service_access() {
    TaskService tasks;
    PkgContext context;
    context.tasks = &tasks;
    PkgService packages(context);
    for (const auto& caller : {CallContext{}, CallContext{"reader", true, true, false}, CallContext{"admin", true, false, true}}) {
        for (bool importing : {false, true}) {
            bool denied = false;
            try {
                if (importing) packages.vm_import(caller, Json::Value());
                else packages.vm_export(caller, Json::Value());
            } catch (const ServiceError& error) {
                denied = error.code() == (caller.authenticated ? ErrorCode::permission_denied : ErrorCode::unauthenticated);
            }
            check(denied, "package authorization precedes path/configuration access");
        }
    }
}
void service_queue_capacity() {
    using namespace std::chrono_literals;
    LegacyEvents events;
    std::atomic<bool> started{false};
    TaskLimits limits;
    limits.workers = 1;
    limits.background_workers = 1;
    TaskService tasks(limits);
    const CallContext caller{"package-owner", true, true, true};
    tasks.submit(caller, {"hold", "", 4, true, true}, [&](TaskControl& control) {
        started.store(true);
        while (!control.cancellation_requested()) std::this_thread::sleep_for(1ms);
        return TaskCompletion::cancelled();
    });
    const auto deadline = TaskService::Clock::now() + 2s;
    while (!started && TaskService::Clock::now() < deadline) std::this_thread::yield();
    check(started, "background worker occupied");
    PkgContext context;
    context.tasks = &tasks;
    context.events = &events;
    PkgService packages(context);
    Json::Value request;
    request["src_path"] = "/not-opened.vmpkg";
    request["target_dir"] = "/not-created";
    for (int pass = 0; pass < 3; ++pass) {
        std::vector<TaskRef> refs;
        for (size_t i = 0; i < PkgService::max_tasks; ++i) {
            auto response = packages.vm_import(caller, request);
            refs.push_back({response["epoch"].asString(), response["task_id"].asString()});
            check(tasks.get(caller, refs.back()).state == TaskState::queued, "package admitted without opening input");
        }
        bool rejected = false;
        try { packages.vm_import(caller, request); }
        catch (const RequestError& error) { rejected = std::string(error.what()) == "too many package tasks are running"; }
        check(rejected, "eight active package slots are bounded");
        if (pass < 2) {
            for (const auto& ref : refs) check(tasks.cancel(caller, ref).state == TaskState::cancelled, "queued cancellation releases package slot");
        } else {
            packages.shutdown();
            tasks.shutdown();
            for (const auto& ref : refs) check(tasks.get(caller, ref).state == TaskState::cancelled, "shutdown discards queued package");
        }
    }
    check(events.drain().size() == 3 * PkgService::max_tasks, "legacy terminal notification for every discarded package");
}
template<class F> void fails(const std::string& expected, F&& fn) {
    try { fn(); } catch (const std::exception& error) {
        check(std::string(error.what()) == expected, "expected '" + expected + "', got '" + error.what() + "'");
        return;
    }
    throw std::runtime_error("expected failure: " + expected);
}
template<class F> void fails_any(F&& fn, const char* detail) {
    try { fn(); } catch (const std::exception&) { return; }
    throw std::runtime_error(std::string("expected failure: ") + detail);
}
struct Temporary {
    std::string path = "/data/local/tmp/droidvm-pkg-contract-" + random_id(false);
    Temporary() { check(mkdir(path.c_str(), 0700) == 0, "create test directory"); }
    ~Temporary() { delete_tree(path); }
    std::string at(const std::string& name) const { return path + "/" + name; }
};
std::string bytes_of(const std::string& path) {
    FileSource in(path);
    std::string out, buffer(65536, '\0');
    while (const auto count = in.read(buffer.data(), buffer.size())) out.append(buffer.data(), count);
    return out;
}
void put(const std::string& path, std::string_view bytes) {
    FileSink out(path);
    out.append(bytes);
    out.close();
}
std::string sample(size_t size, uint32_t seed, bool compressible) {
    std::mt19937 random(seed);
    std::string out(size, '\0');
    for (size_t i = 0; i < size; ++i) out[i] = compressible ? static_cast<char>("droidvm-package "[(i / 7) % 16]) : static_cast<char>(random());
    return out;
}
std::string read_all(Source& in) {
    std::string out, buffer(7919, '\0');
    while (const auto count = in.read(buffer.data(), buffer.size())) out.append(buffer.data(), count);
    return out;
}
std::string encode(const std::string& data, Compression compression) {
    StringSink out;
    auto encoder = compress(out, compression);
    // Uneven writes exercise the encoders' buffering.
    for (size_t offset = 0; offset < data.size();) {
        const auto chunk = std::min<size_t>(data.size() - offset, 1 + (offset * 31) % 100003);
        encoder->write(data.data() + offset, chunk);
        offset += chunk;
    }
    encoder->finish();
    return out.value;
}
std::string decode(const std::string& data, Compression compression) {
    MemorySource in(data);
    auto decoder = decompress(in, compression);
    return read_all(*decoder);
}
struct Entry { std::string name; int64_t size; std::string data; };
std::vector<Entry> untar(const std::string& archive) {
    MemorySource in(archive);
    std::vector<Entry> entries;
    TarReader(in).for_each([&](const std::string& name, int, int64_t size, Source& content) {
        entries.push_back({name, size, read_all(content)});
    });
    return entries;
}

void tar_round_trip() {
    StringSink out;
    TarWriter tar(out);
    const auto big = sample(70000, 1, false);
    tar.entry("manifest.json", "{}");
    tar.entry("empty.img", "");
    tar.entry("block.img", std::string(512, 'b'));
    tar.entry("big.qcow2", static_cast<int64_t>(big.size()), [&](Sink& sink) { sink.write(big.data(), 1000); sink.write(big.data() + 1000, big.size() - 1000); });
    tar.close();
    check(out.value.size() % 512 == 0 && out.value.size() == 512 * 145, "tar layout size");
    // ustar header fields as TarWriter writes them.
    check(std::memcmp(out.value.data() + 257, "ustar\0", 6) == 0 && std::memcmp(out.value.data() + 100, "0000644\0", 8) == 0 &&
          std::memcmp(out.value.data() + 124, "00000000002\0", 12) == 0 && out.value[156] == '0', "ustar header fields");
    unsigned sum = 0;
    for (size_t i = 0; i < 512; ++i) sum += i >= 148 && i < 156 ? ' ' : static_cast<unsigned char>(out.value[i]);
    char text[16];
    std::snprintf(text, sizeof(text), "%o ", sum);
    check(std::string(out.value.data() + 148) == text, "checksum is octal plus space");
    const auto entries = untar(out.value);
    check(entries.size() == 4 && entries[0].data == "{}" && entries[1].data.empty() && entries[2].data == std::string(512, 'b') &&
          entries[3].data == big && entries[3].name == "big.qcow2", "tar entries read back");
}
void tar_edges() {
    // A name over 100 units: a regular ./@LongLink entry, then the name cut to 100 bytes.
    StringSink out;
    TarWriter tar(out);
    const std::string name(120, 'n');
    tar.entry(name, "x");
    tar.close();
    auto entries = untar(out.value);
    check(entries.size() == 2 && entries[0].name == "./@LongLink" && entries[0].data == name && entries[1].name == name.substr(0, 100), "long names");
    // GNU 'L' entries rename the next one; other types are skipped.
    auto block = [](const std::string& entry, char type, uint64_t size, bool base256) {
        std::string header(512, '\0');
        std::memcpy(header.data(), entry.data(), std::min<size_t>(entry.size(), 100));
        if (base256) { header[124] = static_cast<char>(0x80); for (int i = 135; i >= 125; --i) { header[i] = static_cast<char>(size & 0xff); size >>= 8; } }
        else { char digits[16]; std::snprintf(digits, sizeof(digits), "%011llo", static_cast<unsigned long long>(size)); std::memcpy(header.data() + 124, digits, 11); }
        header[156] = type;
        return header;
    };
    std::string archive = block("././@LongLink", 'L', 9, false) + std::string("long-name") + std::string(503, '\0') +
        block("short", '0', 3, true) + "abc" + std::string(509, '\0') + block("dir", '5', 0, false) + block("tail", 0, 1, false) + "z" +
        std::string(511, '\0') + std::string(1024, '\0');
    entries = untar(archive);
    check(entries.size() == 2 && entries[0].name == "long-name" && entries[0].data == "abc" && entries[1].name == "tail", "L entries, base-256, skipped types");
    // A stream that just ends counts as the end of the archive.
    check(untar("").empty(), "empty stream");
    fails("unexpected end of tar header", [&] { untar(std::string(100, 'x')); });
    fails("unexpected end of tar entry", [&] { untar(block("cut", '0', 600, false) + std::string(10, 'y')); });
    StringSink sink;
    TarWriter writer(sink);
    fails("entry overwrote its declared size", [&] { writer.entry("a", 1, [](Sink& o) { o.write("ab", 2); }); });
    StringSink other;
    TarWriter second(other);
    fails("entry b: short write (1 of 3 bytes)", [&] { second.entry("b", 3, [](Sink& o) { o.write("a", 1); }); });
    second.close();
    fails("TarWriter closed", [&] { second.entry("c", ""); });
}
void compression_round_trips() {
    for (const auto compression : {Compression::none, Compression::gzip, Compression::xz, Compression::zstd}) {
        for (const auto& data : {std::string(), sample(1, 2, false), sample(3u << 20, 3, true), sample(1u << 20, 4, false)}) {
            const auto packed = encode(data, compression);
            check(decode(packed, compression) == data, std::string("round trip ") + compression_name(compression));
            if (compression != Compression::none && data.size() > 100) check(packed != data, "encoded");
        }
    }
    // Formats as written: gzip magic, XZ header with CRC64 (check id 4), a zstd frame.
    check(encode("x", Compression::gzip).substr(0, 3) == "\x1f\x8b\x08", "gzip header");
    const auto xz = encode("x", Compression::xz);
    check(std::memcmp(xz.data(), "\xfd" "7zXZ\0", 6) == 0, "xz magic");
    check(xz[7] == 4, "xz check is CRC64");
    check(std::memcmp(encode("x", Compression::zstd).data(), "\x28\xb5\x2f\xfd", 4) == 0, "zstd magic");
    // Concatenated members, streams and frames read as one stream.
    for (const auto compression : {Compression::gzip, Compression::xz, Compression::zstd})
        check(decode(encode("first-", compression) + encode("second", compression), compression) == "first-second",
              std::string("concatenated ") + compression_name(compression));
}
void compression_corruption() {
    const auto data = sample(200000, 5, true);
    fails("Not in GZIP format", [&] { decode("plain text", Compression::gzip); });
    fails("Input is not in the XZ format", [&] { decode("plain text, long enough", Compression::xz); });
    fails("Unknown frame descriptor", [&] { decode("plain text, long enough", Compression::zstd); });
    for (const auto compression : {Compression::gzip, Compression::xz, Compression::zstd}) {
        const auto packed = encode(data, compression);
        fails_any([&] { decode(packed.substr(0, packed.size() / 2), compression); }, "truncated");
        auto flipped = packed;
        flipped[flipped.size() / 2] ^= 0x55;
        flipped[flipped.size() - 6] ^= 0x55;
        fails_any([&] { if (decode(flipped, compression) != data) throw std::runtime_error("silent corruption"); }, "corrupt");
    }
    const auto gz = encode(data, Compression::gzip);
    fails("Unexpected end of ZLIB input stream", [&] { decode(gz.substr(0, gz.size() - 4), Compression::gzip); });
    const auto zst = encode(data, Compression::zstd);
    fails("Read error or truncated source", [&] { decode(zst.substr(0, zst.size() - 3), Compression::zstd); });
}
void header_contract() {
    const auto header = Header::build(2, 31, 1234, Compression::xz, 0x0102030405060708ll, 7);
    check(std::memcmp(header.data(), "VMPKG\0", 6) == 0 && header[6] == 2 && header[8] == 31 && static_cast<unsigned char>(header[10]) == (1234 & 0xff) &&
          header[12] == 2 && header[14] == 7 && header[16] == 8 && header[23] == 1, "header layout");
    const auto parsed = Header::parse(header.data());
    check(parsed.manifest_version == 2 && parsed.app_version_code == 31 && parsed.manifest_size == 1234 && parsed.compression == 2 &&
          parsed.volume_count == 7 && parsed.data_size == 0x0102030405060708ll, "header parse");
    auto bad = header;
    bad[5] = 'x';
    fails("invalid package header", [&] { Header::parse(bad.data()); });
    fails("unsupported vmpkg manifest version: 3", [&] { Header::parse(Header::build(3, 0, 1, Compression::none, 0, 0).data()); });
    fails("unsupported vmpkg manifest version: 0", [&] { Header::parse(Header::build(0, 0, 1, Compression::none, 0, 0).data()); });
    bad = Header::build(1, 0, 1, Compression::none, 0, 0); bad[12] = 9;
    fails("unsupported vmpkg compression: 9", [&] { Header::parse(bad.data()); });
    fails("empty vmpkg manifest", [&] { Header::parse(Header::build(1, 0, 0, Compression::none, 0, 0).data()); });
    bad = Header::build(1, 0, 1, Compression::none, 0, 0); bad[23] = static_cast<char>(0x80);
    fails("vmpkg data size is too large", [&] { Header::parse(bad.data()); });
    fails("uint16 out of range: 70000", [&] { Header::build(1, 70000, 1, Compression::none, 0, 0); });
    check(align_up(24) == 4096 && align_up(4096) == 4096 && align_up_strict(4096) == 8192 && align_up_strict(4097) == 8192, "alignment");
}
Manifest fixture_manifest() {
    Manifest manifest;
    manifest.created_at = 1700000000000;
    manifest.app_version = "1.0";
    manifest.app_version_code = 7;
    manifest.app_build_type = "debug";
    manifest.compression = Compression::gzip;
    manifest.vm["name"] = "vm \"one\"/\xe2\x80\xa8";
    manifest.vm["memory_mb"] = 512;
    DiskEntry disk;
    disk.ref = {1, "/data/disk.qcow2", false, "VIRTIO"};
    disk.name = "disk.qcow2";
    disk.format = "QCOW2";
    disk.size = 10;
    disk.archive_path = "disk.qcow2";
    manifest.disks.push_back(disk);
    BootFile boot;
    boot.archive_path = boot.name = "vmlinuz";
    boot.path = "/data/vmlinuz";
    boot.kind = "kernel";
    boot.size = 3;
    manifest.boots.push_back(boot);
    return manifest;
}
void manifest_contract() {
    auto manifest = fixture_manifest();
    check(manifest.resolve_version() == 1, "base version without chains");
    const auto text = manifest_text(manifest);
    check(text.starts_with("{\n    \"app_build_type\": \"debug\",") && text.find("\"compression\": \"GZIP\"") != std::string::npos &&
          text.find("\"format\": \"qcow2\"") != std::string::npos && text.find("\\/\\u2028") != std::string::npos &&
          text.find("\"bus\": \"VIRTIO\"") != std::string::npos && text.find("\"networks\": []") != std::string::npos, "org.json indent-4 text");
    auto parsed = Manifest::parse(text);
    check(parsed.app_version_code == 7 && parsed.compression == Compression::gzip && parsed.disks.size() == 1 && parsed.disks[0].format == "QCOW2" &&
          parsed.disks[0].ref.index == 1 && parsed.disks[0].attached && parsed.boots[0].kind == "kernel" && config::string(parsed.vm, "name") == config::string(manifest.vm, "name") &&
          parsed.vm.isMember("screens"), "manifest parse migrates the VM");
    manifest.disks[0].attached = false;
    check(manifest.resolve_version() == 2, "detached file needs version 2");
    manifest.disks[0].attached = true;
    manifest.disks[0].backing_archive = "base.img";
    check(manifest.resolve_version() == 2 && manifest.disks[0].json()["backing_archive"] == "base.img", "backing link needs version 2");
    manifest.disks[0].target = "/x/y/placed.qcow2";
    check(manifest.disks[0].json()["path"] == "/x/y/placed.qcow2" && manifest.disks[0].json()["name"] == "placed.qcow2", "placed entries report their target");
    // Defaults and coercions of older or odd manifests.
    const auto old = DiskEntry::parse(wire::parse(R"({"archive_path":"a","bus":"scsi","format":"weird","size":"12"})"));
    check(old.name == "disk.img" && old.format == "RAW" && old.ref.bus == "SCSI" && old.size == 12 && old.attached && old.ref.index == 0, "DiskEntry defaults");
    fails("vmpkg manifest is not valid UTF-8", [] { Manifest::parse("{\"vm\":{}, \"x\":\"\xc3\x28\"}"); });
    fails("No value for vm", [] { Manifest::parse(R"({"disks":[],"boots":[],"networks":[]})"); });
    fails("No value for disks", [] { Manifest::parse(R"({"vm":{}})"); });
    fails("Value at vm cannot be converted to JSONObject", [] { Manifest::parse(R"({"vm":[]})"); });
    fails("object is not json", [] { Manifest::parse(R"({"vm":{},"disks":[1],"boots":[],"networks":[]})"); });
    fails("Unsupported network config schema (expected 2)", [] { Manifest::parse(R"({"vm":{},"disks":[],"boots":[],"networks":[{"schema":1}]})"); });
    fails_any([] { Manifest::parse("not json"); }, "not json");
    check(disk_format_of("a.QCOW2") == "QCOW2" && disk_format_of("a.img") == "RAW" && disk_format_of("noext") == "RAW" && disk_format_of("x.iso") == "ISO", "DiskFormat");
}
// One package written by the production writer, read back by PackageInput.
void write_fixture(const std::string& dest, Compression compression, int64_t volume_size, const std::vector<std::pair<std::string, std::string>>& files,
                   int* volumes = nullptr) {
    auto manifest = fixture_manifest();
    manifest.compression = compression;
    manifest.disks.clear();
    manifest.boots.clear();
    for (const auto& [name, data] : files) {
        DiskEntry disk;
        disk.name = disk.archive_path = name;
        disk.size = static_cast<int64_t>(data.size());
        manifest.disks.push_back(disk);
    }
    PackageSpec spec;
    spec.dest = dest;
    spec.volume_size = volume_size;
    spec.compression = compression;
    spec.app_version_code = 7;
    const auto count = write_package(spec, manifest_text(manifest), [&](TarWriter& tar) {
        for (const auto& [name, data] : files) tar.entry(name, data);
    });
    if (volumes) *volumes = count;
}
std::vector<Entry> read_package(Source& raw, int64_t data_size = -1) {
    auto input = PackageInput::open(raw, data_size);
    std::vector<Entry> entries;
    TarReader(input->data()).for_each([&](const std::string& name, int, int64_t size, Source& content) { entries.push_back({name, size, read_all(content)}); });
    drain(input->data());
    input->validate_data_consumed();
    return entries;
}
std::vector<Entry> read_path(const std::string& path) {
    FileSource in(path);
    return read_package(in);
}
void joint_import(const std::string& fault) {
    using namespace std::chrono_literals;
    Temporary dir;
    const CallContext caller{"package-owner", true, true, true};
    Fd directory(open(dir.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    auto gate = std::make_shared<ConfigurationGate>();
    vm::RuntimeContext runtime;
    runtime.cache_dir = dir.path; runtime.data_dir = dir.path; runtime.owner = getuid(); runtime.configuration_gate = gate;
    runtime.shutting_down = [] { return false; };
    VmService vms(runtime);
    TaskLimits limits;
    limits.background_workers = 1;
    TaskService tasks(limits, [] { return TaskService::Clock::now(); }, {}, gate);
    bool armed = false, injected = false;
    ConfigurationService configuration(directory.get(), getuid(), gate, vms, tasks,
        [&](const char* stage, size_t) {
            if (armed && !injected && fault == stage) {
                injected = true;
                throw std::runtime_error("joint import injection");
            }
        }, true);
    auto before = configuration.disks()->snapshot(caller);
    auto disk_document = before->document;
    disk_document["extension"] = Json::Int64(9007199254740993LL);
    configuration.disks()->replace(caller, before->revision, disk_document);
    auto manifest = fixture_manifest();
    manifest.vm["name"] = "joint-import";
    manifest.vm["networks"] = Json::Value(Json::arrayValue);
    manifest.disks.clear(); manifest.boots.clear(); manifest.networks.clear();
    manifest.compression = Compression::none;
    DiskEntry disk;
    disk.name = disk.archive_path = "disk.img"; disk.format = "RAW"; disk.size = 7;
    disk.attached = true;
    manifest.disks.push_back(disk);
    PackageSpec spec;
    spec.dest = dir.at("source.vmpkg"); spec.compression = Compression::none;
    spec.app_version_code = manifest.app_version_code;
    write_package(spec, manifest_text(manifest), [](TarWriter& tar) { tar.entry("disk.img", "payload"); });
    LegacyEvents events;
    PkgContext context;
    context.vms = &vms; context.networks = &configuration.networks(); context.tasks = &tasks;
    context.events = &events; context.data_dir = dir.path; context.configuration = &configuration;
    PkgService packages(context);
    Json::Value request;
    request["src_path"] = spec.dest; request["target_dir"] = dir.at("output");
    armed = true;
    const auto response = packages.vm_import(caller, request);
    const TaskRef ref{response["epoch"].asString(), response["task_id"].asString()};
    const auto deadline = TaskService::Clock::now() + 5s;
    auto task = tasks.get(caller, ref);
    while (!task_terminal(task.state) && TaskService::Clock::now() < deadline) {
        std::this_thread::sleep_for(1ms); task = tasks.get(caller, ref);
    }
    check(task_terminal(task.state), "joint import bounded completion");
    const bool installed = fault != "before_decision";
    if (fault.empty()) check(task.state == TaskState::succeeded, "joint import succeeds");
    else {
        check(task.state == TaskState::failed && task.error ==
            (installed ? ErrorCode::commit_uncertain : ErrorCode::io_error), "joint import retains failure semantics");
        configuration.recover(caller);
    }
    const auto vm_view = configuration.vms().snapshot(caller);
    const auto disk_view = configuration.disks()->snapshot(caller);
    check(vm_view->document["vms"].size() == (installed ? 1u : 0u) &&
          disk_view->document["disks"].size() == (installed ? 1u : 0u), "both import registries agree");
    check(disk_view->document["extension"] == disk_document["extension"], "disk root extension retained");
    check(exists(dir.at("output/joint-import/disk.img")) == installed, "only rejected joint import deletes extracted image");
    if (installed) {
        const auto& row = disk_view->document["disks"][0];
        check(vm_view->document["vms"][0]["disks"][0]["path"] == path_join(row["folder"].asString(), row["name"].asString()),
              "persisted VM references registered imported image");
        check(bytes_of(dir.at("output/joint-import/disk.img")) == "payload", "joint import preserves image bytes");
    }
    if (fault.empty()) {
        // Exercise the coordinator's real worker binding without starting any VMM.
        const auto image = dir.at("output/joint-import/disk.img");
        check(make_dirs(dir.at("usr/bin")), "create isolated image tool directory");
        put(dir.at("usr/bin/qemu-img"), "#!/system/bin/sh\n"
            "case \"$3\" in /proc/self/fd/*) ;; *) exit 21;; esac\n"
            "[ \"$(cat \"$3\")\" = payload ] || exit 22\n"
            "printf '%s' '{\"format\":\"raw\"}'\n");
        check(chmod(dir.at("usr/bin/qemu-img").c_str(), 0700) == 0, "enable export inspection tool");
        Json::Value export_request;
        export_request["vm_id"] = vm_view->document["vms"][0]["id"];
        export_request["dest_path"] = dir.at("export.vmpkg");
        export_request["compression"] = "NONE";
        {
            auto writer = configuration.disk_files()->acquire({{image, true}});
            bool conflict = false;
            try { packages.vm_export(caller, export_request); }
            catch (const ServiceError& error) { conflict = error.code() == ErrorCode::conflict; }
            check(conflict && !exists(dir.at("export.vmpkg")), "export refuses leased writer before destination access");
        }
        const auto exported = packages.vm_export(caller, export_request);
        const TaskRef exported_ref{exported["epoch"].asString(), exported["task_id"].asString()};
        auto export_task = tasks.get(caller, exported_ref);
        const auto export_deadline = TaskService::Clock::now() + 5s;
        while (!task_terminal(export_task.state) && TaskService::Clock::now() < export_deadline) {
            std::this_thread::sleep_for(1ms); export_task = tasks.get(caller, exported_ref);
        }
        check(export_task.state == TaskState::succeeded, "coordinated export completes from retained inputs");
        const auto exported_entries = read_path(dir.at("export.vmpkg"));
        check(exported_entries.size() == 2 && exported_entries[1].data == "payload", "export preserves leased image bytes");
        { auto writer = configuration.disk_files()->acquire({{image, true}}); writer->verify(); }
        put(dir.at("usr/bin/qemu-img"), "#!/system/bin/sh\n"
            "case \"$3\" in /proc/self/fd/*) ;; *) exit 21;; esac\n"
            "[ \"$(cat \"$3\")\" = payload ] || exit 22\n"
            "printf inspected > '" + dir.at("inspected") + "'\n"
            "printf '%s' '{\"format\":\"qcow2\",\"backing-filename\":\"" + image + "\"}'\n");
        check(chmod(dir.at("usr/bin/qemu-img").c_str(), 0700) == 0, "enable isolated image tool");
        auto instance = vms.runtime(caller, vm_view->document["vms"][0]["id"].asString());
        check(instance->start(), "valid registry enters image-validation worker");
        const auto end = TaskService::Clock::now() + 3s;
        while (instance->state() != vm::State::stopped && TaskService::Clock::now() < end) std::this_thread::sleep_for(1ms);
        check(instance->state() == vm::State::stopped && exists(dir.at("inspected")),
            "unregistered backing stops worker before boot or VMM creation");
        auto available = configuration.disk_files()->acquire({{image, true}});
        available->verify();
    }
    tasks.shutdown();
}

void persistent_import(const std::string& fault) {
    using namespace std::chrono_literals;
    Temporary dir;
    const CallContext caller{"package-owner", true, true, true};
    Fd directory(open(dir.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    check(directory.get() >= 0, "open isolated configuration directory");
    vm::RuntimeContext runtime_context;
    runtime_context.cache_dir = dir.path;
    runtime_context.owner = getuid();
    runtime_context.shutting_down = [] { return true; }; // Never admit a VMM.
    VmService vms(runtime_context);
    bool armed = false;
    VmConfigService configs(directory.get(), getuid(), [&](const char* stage) {
        if (armed && fault == stage) throw std::runtime_error("injected persistence failure");
    }, [&](const Json::Value& document) {
        if (armed && fault == "unknown") throw std::runtime_error("unknown registration failure");
        return vms.prepare_config(document);
    });
    auto initial = configs.snapshot(caller);
    auto document = initial->document;
    document["extension"] = "preserve";
    configs.replace(caller, initial->revision, document);
    bool raced = false;
    NetworkConfigService networks(directory.get(), getuid(), [&](const char* stage) {
        if (fault == "conflict" && std::string_view(stage) == "installed") {
            auto prior = configs.snapshot(caller);
            auto changed = prior->document;
            changed["concurrent_edit"] = true;
            configs.replace(caller, prior->revision, std::move(changed));
            raced = true;
        }
    });
    auto manifest = fixture_manifest();
    manifest.vm["name"] = "imported";
    manifest.vm["networks"] = wire::parse(R"([{"pkg_network_ref":"net0","mac_address":"02:00:00:00:00:01","dhcp4_lease":{"enabled":true,"offset":70}}])");
    manifest.disks.clear();
    manifest.boots.clear();
    manifest.compression = Compression::none;
    DiskEntry disk;
    disk.name = disk.archive_path = "disk.img";
    disk.format = "RAW";
    disk.size = 7;
    disk.ref.index = 0;
    manifest.disks.push_back(disk);
    manifest.networks.push_back(wire::parse(R"({"schema":2,"id":"00000000-0000-4000-8000-000000000001","name":"import-net","bridge_name":"brimport","uplink_mode":"l3","l3":{"vlans":[{"vlan_id":0,"ipv4":{"cidr":"10.0.0.1/24","dhcp":{"enabled":true}}}]},"pkg_network_ref":"net0"})"));
    PackageSpec spec;
    spec.dest = dir.at("source.vmpkg");
    spec.compression = Compression::none;
    spec.app_version_code = manifest.app_version_code;
    write_package(spec, manifest_text(manifest), [](TarWriter& tar) { tar.entry("disk.img", "payload"); });
    LegacyEvents events;
    TaskLimits limits;
    limits.background_workers = 1;
    TaskService tasks(limits);
    PkgContext context;
    context.vms = &vms; context.vm_config = &configs; context.networks = &networks;
    context.events = &events; context.tasks = &tasks; context.data_dir = dir.path;
    PkgService packages(context);
    Json::Value request;
    request["src_path"] = spec.dest;
    request["target_dir"] = dir.at("output");
    armed = true;
    auto run = [&] {
        const auto response = packages.vm_import(caller, request);
        const TaskRef ref{response["epoch"].asString(), response["task_id"].asString()};
        const auto deadline = TaskService::Clock::now() + 5s;
        auto task = tasks.get(caller, ref);
        while (!task_terminal(task.state) && TaskService::Clock::now() < deadline) {
            std::this_thread::sleep_for(1ms);
            task = tasks.get(caller, ref);
        }
        check(task_terminal(task.state), "import finishes within bounded deadline");
        return task;
    };
    auto task = run();
    const bool installed = fault.empty() || fault == "installed";
    const bool retained = installed || fault == "unknown";
    auto view = configs.snapshot(caller);
    check(view->document["vms"].size() == (installed ? 1u : 0u), "registration snapshot matches commit outcome");
    check(vms.list(caller).size() == (installed ? 1u : 0u), "runtime inventory follows persistence");
    check(view->document["extension"] == "preserve", "import preserves root extension");
    check(exists(dir.at("output/imported/disk.img")) == retained, "only rejected registration cleans imported files");
    if (retained) check(bytes_of(dir.at("output/imported/disk.img")) == "payload", "retained disk contents intact");
    if (fault.empty()) {
        check(task.state == TaskState::succeeded && vms.exists(caller, task.result["vm_id"].asString()), "success exposes persistent VM");
        const auto first_nic = view->document["vms"][0]["networks"][0];
        check(first_nic["dhcp4_lease"]["enabled"].asBool() && first_nic["dhcp4_lease"]["offset"] == 70, "initial import persists lease");
        Json::Value join;
        join["ref"] = "net0"; join["action"] = "join"; join["network_id"] = first_nic["network_id"];
        request["network_plan"] = Json::Value(Json::arrayValue);
        request["network_plan"].append(std::move(join));
        task = run();
        check(task.state == TaskState::succeeded, "second import succeeds without legacy create");
        view = configs.snapshot(caller);
        check(view->document["vms"].size() == 2 && view->document["vms"][1]["name"] == "imported (1)", "name planned from persistent snapshot");
        check(view->document["vms"][1]["networks"][0]["dhcp4_lease"]["offset"] == 71, "lease planning respects persisted VM reservation");
    } else {
        const auto expected = fault == "installed" ? ErrorCode::commit_uncertain : fault == "conflict" ? ErrorCode::conflict :
            fault == "unknown" ? ErrorCode::internal : ErrorCode::io_error;
        check(task.state == TaskState::failed && task.error == expected, "task preserves registration failure code");
        if (fault == "conflict") check(raced && view->document["concurrent_edit"].asBool(), "planning revision detects concurrent commit");
        if (fault == "installed") check(view->durability_uncertain, "installed failure remains explicitly uncertain");
        if (retained) {
            bool reported = false;
            for (const auto& frame : events.drain()) {
                const auto data = wire::parse(std::string_view(frame).substr(4))["data"];
                if (data["phase"] == "error" && data["retained_directory"] == dir.at("output/imported")) reported = true;
            }
            check(reported, "failure notification identifies retained import directory");
        }
    }
    packages.shutdown();
    tasks.shutdown();
    // A new service reads the real persisted document, not an in-memory task result.
    VmConfigService reopened(directory.get(), getuid());
    check(reopened.snapshot(caller)->document == view->document, "reopen preserves imported configuration or concurrent edit");
}
void single_file_packages() {
    Temporary dir;
    const auto disk = sample(300000, 6, true), noise = sample(5000, 7, false);
    for (const auto compression : {Compression::none, Compression::gzip, Compression::xz, Compression::zstd}) {
        const auto path = dir.at(std::string("single-") + compression_name(compression) + ".vmpkg");
        write_fixture(path, compression, 0, {{"disk.img", disk}, {"noise.bin", noise}});
        const auto bytes = bytes_of(path);
        const auto header = Header::parse(bytes.data());
        const auto start = align_up_strict(4096 + static_cast<uint64_t>(header.manifest_size));
        check(bytes.size() % 4096 == 0 && header.volume_count == 0 && header.compression == static_cast<int>(compression) &&
              bytes.size() == align_up(start + static_cast<uint64_t>(header.data_size)), "single-file layout");
        const auto entries = read_path(path);
        check(entries.size() == 3 && entries[0].name == "manifest.json" && entries[0].data == bytes.substr(4096, static_cast<size_t>(header.manifest_size)) &&
              entries[1].data == disk && entries[2].data == noise, "single-file round trip");
        // Corruptions PackageInput must refuse.
        auto damaged = bytes;
        damaged[100] = 1;
        fails("vmpkg padding is not zero-filled", [&] { MemorySource in(damaged); read_package(in); });
        damaged = bytes + std::string(4096, '\0');
        fails("unexpected bytes after vmpkg package", [&] { MemorySource in(damaged); read_package(in); });
        damaged = bytes;
        damaged[static_cast<size_t>(start + static_cast<uint64_t>(header.data_size))] = 9;
        if (header.data_size % 4096) fails("vmpkg padding is not zero-filled", [&] { MemorySource in(damaged); read_package(in); });
        fails("unexpected end of vmpkg", [&] { MemorySource in(bytes.substr(0, 20)); read_package(in); });
        fails("unexpected end of vmpkg", [&] { MemorySource in(bytes.substr(0, 4100)); read_package(in); });
        damaged = bytes;
        damaged[12] = static_cast<char>((static_cast<int>(compression) + 1) % 4);
        fails("vmpkg compression mismatch", [&] { MemorySource in(damaged); read_package(in); });
        damaged = bytes;
        damaged[8] = 8;
        fails("vmpkg app_version_code mismatch", [&] { MemorySource in(damaged); read_package(in); });
        // A data_size beyond the tar: the stream ends early or the region is short.
        damaged = bytes;
        damaged[16] = static_cast<char>(static_cast<unsigned char>(damaged[16]) + 1);
        // One padding byte more: NONE and GZIP readers stop at the tar/member end and take it
        // as data, as the legacy streams do; XZ and zstd see trailing garbage.
        if (compression == Compression::none || compression == Compression::gzip) { MemorySource in(damaged); read_package(in); }
        else fails_any([&] { MemorySource in(damaged); read_package(in); }, (std::string("data_size off by one ") + compression_name(compression)).c_str());
        damaged = bytes;
        damaged[16] = static_cast<char>(static_cast<unsigned char>(damaged[16]) - 1);
        if (compression != Compression::none) fails_any([&] { MemorySource in(damaged); read_package(in); }, "data_size one short");
        if (compression != Compression::none) {
            damaged = bytes;
            damaged[static_cast<size_t>(start) + static_cast<size_t>(header.data_size) / 2] ^= 0x5a;
            // zstd frames carry no checksum (zstd-jni's default too): the bytes still differ.
            fails_any([&] {
                MemorySource in(damaged);
                const auto read = read_package(in);
                if (read.size() != 3 || read[1].data != disk || read[2].data != noise) throw std::runtime_error("silent");
            }, (std::string("corrupt data ") + compression_name(compression)).c_str());
        }
    }
}
void split_packages() {
    Temporary dir;
    const auto disk = sample(2500000, 8, false);
    const auto base = dir.at("split.vmpkg");
    int volumes = 0;
    // A stale higher-numbered sub-volume from an earlier export is removed.
    put(volume_name(base, 9), "stale");
    put(volume_name(base, 10), "stale");
    write_fixture(base, Compression::none, 1u << 20, {{"disk.img", disk}}, &volumes);
    check(volumes == 3 && exists(volume_name(base, 3)) && !exists(volume_name(base, 4)) && file_length(volume_name(base, 1)) == 1 << 20, "three sub-volumes");
    check(exists(volume_name(base, 9)), "stale removal stops at the first gap, as the legacy loop");
    unlink(volume_name(base, 9).c_str());
    unlink(volume_name(base, 10).c_str());
    const auto master = bytes_of(base);
    const auto header = Header::parse(master.data());
    check(header.volume_count == 3 && header.data_size > 2500000, "master header");
    const auto data_start = align_up_strict(4096 + static_cast<uint64_t>(header.manifest_size));
    const auto index = master.substr(data_start);
    check(index.starts_with("{\"magic\":\"VMPV\",\"version\":1,\"data_size\":" + std::to_string(header.data_size) + ",\"volumes\":[{\"index\":1,\"size\":1048576,\"crc32\":"),
          "compact volume index");
    check(is_sub_volume(volume_name(base, 2)) && master_of(volume_name(base, 2)) == base && !is_sub_volume(base) && master_of(base) == base, "sub-volume names");
    auto set = VolumeSet::discover(base);
    check(set.count() == 3 && set.data_size() == header.data_size, "discover");
    auto logical = set.open_logical();
    auto entries = read_package(*logical, set.data_size());
    check(entries.size() == 2 && entries[1].data == disk, "split round trip");
    // The same set, read as one stream, equals a single-file package of that data.
    const auto chunk = bytes_of(volume_name(base, 2));
    put(volume_name(base, 2), chunk.substr(0, chunk.size() - 1));
    fails("sub-volume 2 size mismatch: on-disk 1048575, expected 1048576", [&] { VolumeSet::discover(base); });
    auto flipped = chunk;
    flipped[1000] ^= 1;
    put(volume_name(base, 2), flipped);
    fails("sub-volume 2 checksum mismatch", [&] { auto s = VolumeSet::discover(base); auto l = s.open_logical(); read_package(*l, s.data_size()); });
    put(volume_name(base, 2), chunk);
    unlink(volume_name(base, 3).c_str());
    fails("missing sub-volume 3 (split.vmpkg.003)", [&] { VolumeSet::discover(base); });
    put(dir.at("plain.vmpkg"), std::string(5000, '\0'));
    fails("invalid package header", [&] { VolumeSet::discover(dir.at("plain.vmpkg")); });
    write_fixture(dir.at("single.vmpkg"), Compression::zstd, 0, {{"a", "b"}});
    fails("not a multi-volume package", [&] { VolumeSet::discover(dir.at("single.vmpkg")); });
    fails("unexpected master size: 0", [&] { VolumeSet::discover(dir.at("missing.vmpkg")); });
    put(dir.at("cut.vmpkg"), master.substr(0, 5000));
    fails("truncated master", [&] { VolumeSet::discover(dir.at("cut.vmpkg")); });
    put(dir.at("idx.vmpkg"), master.substr(0, data_start) + "{\"magic\":\"VMPV\",\"version\":2}");
    fails("unsupported volume version: 2", [&] { VolumeSet::discover(dir.at("idx.vmpkg")); });
    put(dir.at("idx.vmpkg"), master.substr(0, data_start) + "{\"version\":1}");
    fails("missing volume index magic", [&] { VolumeSet::discover(dir.at("idx.vmpkg")); });
    put(dir.at("idx.vmpkg"), master.substr(0, data_start) + "{\"magic\":\"VMPV\",\"version\":1,\"volumes\":[]}");
    fails("volume index has no volumes", [&] { VolumeSet::discover(dir.at("idx.vmpkg")); });
    put(dir.at("idx.vmpkg"), master.substr(0, data_start) + "garbage");
    fails("failed to parse volume index", [&] { VolumeSet::discover(dir.at("idx.vmpkg")); });
    put(dir.at("idx.vmpkg"), master.substr(0, data_start) + "{\"magic\":\"VMPV\",\"version\":1,\"volumes\":[{\"index\":1,\"size\":1,\"crc32\":0}]}");
    fails("volume count mismatch: header 3, index 1", [&] { VolumeSet::discover(dir.at("idx.vmpkg")); });
    // Too many volumes fails and leaves no sub-volume behind.
    PackageSpec spec;
    spec.dest = dir.at("many.vmpkg");
    spec.volume_size = 1;
    spec.compression = Compression::none;
    fails("too many volumes (> 999); use a larger volume size", [&] {
        write_package(spec, manifest_text(fixture_manifest()), [](TarWriter&) {});
    });
    check(!exists(volume_name(spec.dest, 1)) && !exists(spec.dest), "failed split cleans up");
}
void chain_plan() {
    std::map<std::string, std::string> parents{{"/a/top.qcow2", "/b/base.qcow2"}, {"/c/top.qcow2", "/b/base.qcow2"}, {"/b/base.qcow2", "/b/root.img"}};
    auto lookup = [&](const std::string& path) -> std::optional<std::string> {
        auto found = parents.find(path);
        if (found == parents.end()) return std::nullopt;
        return found->second;
    };
    std::vector<DiskRef> tops{{0, "/a/top.qcow2", false, "VIRTIO"}, {1, "/c/top.qcow2", true, "SCSI"}, {2, "/b/root.img", false, "VIRTIO"},
                              {3, "/a/top.qcow2", false, "VIRTIO"}, {4, "", false, "VIRTIO"}};
    const auto plan = plan_disks(tops, lookup);
    check(plan.size() == 5, "plan size");
    check(plan[0].archive_path == "top.qcow2" && plan[0].backing_archive == "base.qcow2" && plan[0].attachment->index == 0, "first top");
    check(plan[1].archive_path == "base.qcow2" && plan[1].backing_archive == "root.img" && !plan[1].attachment, "shared base");
    check(plan[2].archive_path == "root.img" && plan[2].backing_archive.empty() && plan[2].attachment && plan[2].attachment->index == 2, "base that is a disk too");
    check(plan[3].archive_path == "top_1.qcow2" && plan[3].backing_archive == "base.qcow2" && plan[3].attachment->bus == "SCSI", "colliding names");
    check(plan[4].archive_path == "top_2.qcow2" && plan[4].path == "/a/top.qcow2" && plan[4].attachment->index == 3, "same file in two slots");
    const auto entry = disk_entry(plan[1]);
    check(entry.ref.index == -1 && entry.ref.readonly && !entry.attached && entry.format == "QCOW2" && entry.name == "base.qcow2", "backing entry");
    parents["/b/root.img"] = "/a/top.qcow2";
    fails("backing chain of top.qcow2 loops at /a/top.qcow2", [&] { plan_disks({{0, "/a/top.qcow2", false, "VIRTIO"}}, lookup); });
    std::map<std::string, std::string> deep;
    for (int i = 0; i < 70; ++i) deep["/d/" + std::to_string(i)] = "/d/" + std::to_string(i + 1);
    fails("backing chain of 0 is deeper than 64 images", [&] {
        plan_disks({{0, "/d/0", false, "VIRTIO"}}, [&](const std::string& p) -> std::optional<std::string> { return deep.at(p); });
    });
}
void network_plan() {
    const auto existing = wire::parse(R"([{"id":"a","name":"lan","bridge_name":"brlan"},{"id":"b","name":"lan_1","bridge_name":"brverylongna"}])");
    NetworkImportPlan plan(existing);
    auto packaged = wire::parse(R"({"schema":2,"id":"x","name":"lan","bridge_name":"brlan","pkg_network_ref":"net0"})");
    const auto first = plan.prepare_create(packaged);
    check(!first.isMember("pkg_network_ref") && first["id"].asString().size() == 36 && first["name"] == "lan_2" && first["bridge_name"] == "brlan1", "prepare_create renames");
    const auto second = plan.adopt(wire::parse(R"({"id":"a","name":" ","bridge_name":"brverylongna"})"));
    check(second["id"].asString() != "a" && second["name"] == "network" && second["bridge_name"] == "brverylongn1", "adopt: taken id, blank name, capped bridge");
    const auto third = plan.adopt(wire::parse(R"({"id":"fresh","name":"network"})"));
    check(third["id"] == "fresh" && third["name"] == "network_1" && !third.isMember("bridge_name"), "claims names it handed out");
    const auto parsed = parse_network_plan(wire::parse(R"([{"ref":"net0","action":"join","network_id":"a"},{"ref":"","action":"skip"},5,
        {"ref":"net1","action":"bogus","config":{"schema":1}},{"ref":"net2","action":"skip"},{"ref":"net3","config":{"schema":2,"name":"n"}}])"));
    check(parsed.size() == 3 && parsed[0].action == NetworkAction::join && parsed[0].network_id == "a" && parsed[1].action == NetworkAction::skip &&
          parsed[2].action == NetworkAction::create && parsed[2].config && find_ref(parsed, "net3") == &parsed[2] && !find_ref(parsed, "net1"), "plan parse drops bad entries");
}
void lease_offsets() {
    const auto vlan = wire::parse(R"({"vlan_id":0,"ipv4":{"cidr":"10.0.0.1/24","dhcp":{"enabled":true}},"ipv6":{"source":"dhcp_pd","dhcp":{"enabled":true}}})");
    std::set<int64_t> used{64, 65};
    check(resolve_offset(64, used, vlan, Family::ipv4) == 66 && resolve_offset(70, used, vlan, Family::ipv4) == 70, "next free offset");
    check(resolve_offset(130, used, vlan, Family::ipv4) == 193 && resolve_offset(400, used, vlan, Family::ipv4) == 66, "dynamic pool skipped, out of range restarts");
    check(resolve_offset(254, {}, vlan, Family::ipv4) == 254 && resolve_offset(254, {254}, vlan, Family::ipv4) == 64, "wraps past the top");
    check(resolve_offset(1000, {}, vlan, Family::ipv6) == 1000, "PD prefix has a /64 of room");
    const auto small = wire::parse(R"({"ipv4":{"cidr":"10.0.0.1/27","dhcp":{"enabled":true,"offset_start":1,"offset_end":30}}})");
    check(resolve_offset(64, {}, small, Family::ipv4) == -1, "VLAN too small");
    check(vlan_dhcp_enabled(vlan, Family::ipv4) && vlan_dhcp_enabled(vlan, Family::ipv6) && !vlan_dhcp_enabled(wire::parse("{}"), Family::ipv4), "DHCP served");
    const auto network = wire::parse(R"({"id":"00000000-0000-4000-8000-000000000001","schema":2,"name":"n","bridge_name":"brn","uplink_mode":"l3","l3":{"vlans":[{"vlan_id":0,"ipv4":{"cidr":"10.0.0.1/24","dhcp":{"enabled":true}}}]}})");
    const auto vm = wire::parse(R"({"networks":[{"network_id":"00000000-0000-4000-8000-000000000001","dhcp4_lease":{"enabled":true,"offset":80}},
        {"network_id":"00000000-0000-4000-8000-000000000001","dhcp4_lease":{"enabled":false,"offset":81}},{"network_id":"n2","dhcp4_lease":{"enabled":true,"offset":82}},
        {"network_id":"00000000-0000-4000-8000-000000000001","dhcp4_lease":{"enabled":true,"offset":83}}]})");
    std::set<int64_t> found;
    add_offsets(found, vm, network, network["l3"]["vlans"][0], Family::ipv4, &vm["networks"][3]);
    check(found == std::set<int64_t>{80}, "offsets held on the VLAN, the resolving NIC excluded");
    const auto mac = random_mac();
    check(mac.size() == 17 && mac.starts_with("02:"), "random MAC");
}
void json_contract() {
    const auto value = wire::parse(R"({"b":[1,{"x":null}],"a":"q\"/\n","e":[],"o":{},"d":1.5,"w":2.0})");
    check(java_json(value) == R"({"a":"q\"\/\n","b":[1,{"x":null}],"d":1.5,"e":[],"o":{},"w":2})", "compact");
    check(java_json(value, 4) == "{\n    \"a\": \"q\\\"\\/\\n\",\n    \"b\": [\n        1,\n        {\n            \"x\": null\n        }\n    ],\n"
                                 "    \"d\": 1.5,\n    \"e\": [],\n    \"o\": {},\n    \"w\": 2\n}", "indent 4");
    const auto request = wire::parse(R"({"s":5,"n":null,"l":"12.9","i":4294967297,"b":"TRUE","d":-3.7,"o":{"k":1}})");
    check(opt_string(request, "s") == "5" && opt_string(request, "n") == "null" && opt_string(request, "missing", "fb") == "fb" &&
          opt_string(request, "o") == "{\"k\":1}", "optString");
    check(opt_long(request, "l") == 12 && opt_long(request, "d") == -3 && opt_long(request, "b", 9) == 9 && opt_int(request, "i") == 1, "optLong/optInt");
    check(opt_bool(request, "b") && !opt_bool(request, "s") && opt_enum(request, "b", "NONE", {"TRUE"}) == "TRUE", "optBoolean/optEnum");
    check(safe_file_name(" a/b:c ", "f") == "a_b_c" && safe_file_name("..", "f") == "f" && pkg::basename("/x/y/") == "y" && pkg::dirname("/x/y") == "/x", "file names");
    check(java_length("\xf0\x9f\x8c\x8f" "a") == 3 && java_path("//a//b/") == "/a/b" && file_name("/a/b//") == "b", "Java strings and paths");
    check(valid_utf8("\xe4\xb8\xad") && !valid_utf8("\xed\xa0\x80") && !valid_utf8("\xc0\x80") && !valid_utf8("\xe4\xb8"), "UTF-8 validation");
}
void file_helpers() {
    Temporary dir;
    check(make_dirs(dir.at("x/y/z")) && !make_dirs(dir.at("x/y/z")) && is_file(dir.at("x")) == false, "mkdirs");
    put(dir.at("x/y/z/f"), "data");
    check(canonical_path(dir.at("x/./y/../y/z/f")) == canonical_path(dir.at("x/y/z/f")) && canonical_path(dir.at("x/missing/../q")).ends_with("/x/q"),
          "canonical paths");
    check(symlink(dir.at("x/y").c_str(), dir.at("link").c_str()) == 0 && canonical_path(dir.at("link/z/f")) == canonical_path(dir.at("x/y/z/f")), "symlinks resolve");
    fails(dir.at("nope") + ": open failed: ENOENT (No such file or directory)", [&] { FileSource in(dir.at("nope")); });
    delete_tree(dir.at("x"));
    check(!exists(dir.at("x")), "delete tree");
}
void exclusive_import_files() {
    Temporary dir;
    auto reject = [&](const std::string& path) {
        bool rejected = false;
        try { FileSink out(path, FileSink::Mode::create_new); out.append("overwrite"); out.close(); }
        catch (const Error&) { rejected = true; }
        check(rejected, "exclusive extraction rejects occupied path");
    };
    {
        FileSink out(dir.at("new"), FileSink::Mode::create_new);
        out.append("original"); out.close();
    }
    reject(dir.at("new"));
    check(bytes_of(dir.at("new")) == "original", "existing image not truncated");
    check(symlink(dir.at("new").c_str(), dir.at("alias").c_str()) == 0, "create image alias");
    reject(dir.at("alias"));
    check(bytes_of(dir.at("new")) == "original", "symlink target not truncated");
    check(symlink(dir.at("missing").c_str(), dir.at("dangling").c_str()) == 0, "create dangling alias");
    reject(dir.at("dangling"));
    check(!exists(dir.at("missing")), "dangling symlink target not created");
}
void cleanup_boundaries() {
    Temporary dir;
    check(make_dirs(dir.at("outside")) && make_dirs(dir.at("owned/nested")), "prepare cleanup trees");
    put(dir.at("outside/keep"), "keep"); put(dir.at("owned/nested/remove"), "remove");
    check(symlink(dir.at("outside").c_str(), dir.at("owned/link").c_str()) == 0, "create external directory alias");
    delete_tree(dir.at("owned"));
    check(!exists(dir.at("owned")) && bytes_of(dir.at("outside/keep")) == "keep", "cleanup never follows descendant symlink");
    check(symlink(dir.at("outside").c_str(), dir.at("root-link").c_str()) == 0, "create cleanup root alias");
    delete_tree(dir.at("root-link"));
    check(bytes_of(dir.at("outside/keep")) == "keep", "cleanup unlinks root symlink only");
    delete_tree(dir.at("already-missing"));
    bool rejected = false;
    try { delete_tree(dir.at("outside/keep/not-a-directory")); }
    catch (const Error&) { rejected = true; }
    check(rejected, "invalid cleanup parent reports failure instead of success");
    rejected = false;
    try { delete_tree(dir.at("outside/..")); }
    catch (const Error&) { rejected = true; }
    check(rejected && bytes_of(dir.at("outside/keep")) == "keep", "parent traversal cleanup root rejected");
}
void owned_import_directory() {
    Temporary dir;
    CreatedDirectory first(dir.path, "import");
    CreatedDirectory second(dir.path, "import");
    check(first.path() == dir.at("import") && second.path() == dir.at("import_1"), "mkdir chooses distinct names atomically");
    {
        FileSink out(first.fd(), "image"); out.append("original"); out.close();
    }
    check(rename(first.path().c_str(), dir.at("moved").c_str()) == 0, "move owned directory");
    check(make_dirs(first.path()), "install replacement directory");
    put(first.path() + "/keep", "replacement");
    bool rejected = false;
    try { first.remove(); } catch (const Error&) { rejected = true; }
    check(rejected && bytes_of(first.path() + "/keep") == "replacement" &&
          bytes_of(dir.at("moved/image")) == "original", "cleanup refuses substituted root without touching either tree");
    {
        FileSink out(first.fd(), "anchored"); out.append("fd target"); out.close();
    }
    check(bytes_of(dir.at("moved/anchored")) == "fd target" && !exists(first.path() + "/anchored"),
          "file creation follows retained directory handle instead of replacement path");
    rejected = false;
    try { FileSink out(first.fd(), "../escape"); } catch (const Error&) { rejected = true; }
    check(rejected && !exists(dir.at("escape")), "anchored extraction rejects traversal");
    delete_tree(first.path());
    check(rename(dir.at("moved").c_str(), first.path().c_str()) == 0, "restore original directory");
    first.verify(); first.remove(); first.remove(); second.remove();
    check(!exists(dir.at("import")) && !exists(dir.at("import_1")), "owned cleanup succeeds and repeated removal is idempotent");
}
void replaced_import_parent() {
    Temporary dir;
    check(make_dirs(dir.at("parent")), "create import parent");
    CreatedDirectory owned(dir.at("parent"), "import");
    { FileSink out(owned.fd(), "image"); out.append("original"); out.close(); }
    check(rename(dir.at("parent").c_str(), dir.at("old-parent").c_str()) == 0 &&
          make_dirs(dir.at("parent/import")), "replace import parent path");
    put(dir.at("parent/import/keep"), "replacement");
    bool rejected = false;
    try { owned.remove(); } catch (const Error&) { rejected = true; }
    check(rejected && bytes_of(dir.at("old-parent/import/image")) == "original" &&
          bytes_of(dir.at("parent/import/keep")) == "replacement", "replacement parent leaves both trees intact");
    delete_tree(dir.at("parent"));
    check(rename(dir.at("old-parent").c_str(), dir.at("parent").c_str()) == 0, "restore original parent");
    owned.remove();
}
void retained_import_files() {
    Temporary dir;
    CreatedDirectory owned(dir.path, "import");
    std::unique_ptr<RetainedFile> retained;
    {
        FileSink out(owned.fd(), "disk");
        retained = std::make_unique<RetainedFile>(out.fd(), owned.fd(), owned.path(), "disk");
        out.append("image"); out.close();
    }
    // qemu-img rebase edits the same inode after extraction closes its stream.
    {
        Fd file(open((owned.path() + "/disk").c_str(), O_WRONLY | O_CLOEXEC));
        check(file.get() >= 0 && pwrite(file.get(), "header", 6, 0) == 6, "simulate in-place header update");
    }
    retained->sync(); owned.sync();
    check(bytes_of(owned.path() + "/disk") == "header", "retained handle survives stream close and syncs header changes");
    check(rename((owned.path() + "/disk").c_str(), (owned.path() + "/original").c_str()) == 0, "move extracted image");
    put(owned.path() + "/disk", "replacement");
    bool rejected = false;
    try { retained->sync(); } catch (const Error&) { rejected = true; }
    check(rejected && bytes_of(owned.path() + "/original") == "header" &&
          bytes_of(owned.path() + "/disk") == "replacement", "file replacement refuses sync without modifying either inode");
    check(unlink((owned.path() + "/disk").c_str()) == 0 &&
          rename((owned.path() + "/original").c_str(), (owned.path() + "/disk").c_str()) == 0, "restore imported image");
    check(link((owned.path() + "/disk").c_str(), dir.at("alias").c_str()) == 0, "add external hardlink");
    rejected = false;
    try { retained->verify(); } catch (const Error&) { rejected = true; }
    check(rejected, "unexpected hardlink rejects file ownership confirmation");
    check(unlink(dir.at("alias").c_str()) == 0, "remove external hardlink");
    retained->sync(); owned.remove();
}
void import_sync_failure() {
    Temporary dir;
    check(make_dirs(dir.at("new/parent"), true), "durable recursive directory creation");
    CreatedDirectory owned(dir.at("new/parent"), "import");
    { FileSink out(owned.fd(), "disk"); out.append("image"); out.close(); }
    // A real descriptor that can be identified but cannot be fsynced: propagation
    // must reject durability rather than treating stat success as a durable file.
    Fd path(openat(owned.fd(), "disk", O_PATH | O_CLOEXEC));
    check(path.get() >= 0, "open path-only descriptor");
    RetainedFile file(path.get(), owned.fd(), owned.path(), "disk");
    bool rejected = false;
    try { file.sync(); } catch (const Error&) { rejected = true; }
    check(rejected && bytes_of(owned.path() + "/disk") == "image", "fsync failure propagates without altering file");
    owned.remove();
}
void retained_rebase(const std::string& mode) {
    Temporary dir;
    CreatedDirectory owned(dir.path, "import");
    std::unique_ptr<RetainedFile> overlay, backing;
    for (const auto* name : {"overlay", "base"}) {
        FileSink out(owned.fd(), name); out.append(name); out.flush();
        auto file = std::make_unique<RetainedFile>(out.fd(), owned.fd(), owned.path(), name);
        if (std::string_view(name) == "overlay") overlay = std::move(file); else backing = std::move(file);
        out.close();
    }
    // A local helper checks descriptor inheritance and emulates header rewriting;
    // it does not substitute for the separate real qemu-img device acceptance.
    std::string script = "#!/system/bin/sh\nif [ \"$1\" = info ]; then\n"
        "case \"$3\" in /proc/self/fd/*) ;; *) exit 21;; esac\n"
        "[ \"$(cat \"$3\")\" = base ] || exit 22\n";
    script += mode == "bad-format" ? "printf '%s' '{\"format\":null}'\n" : "printf '%s' '{\"format\":\"raw\"}'\n";
    script += "exit 0\nfi\n[ \"$1\" = rebase ] && [ \"$2\" = -u ] && [ \"$3\" = -b ] && "
        "[ \"$5\" = -F ] && [ \"$6\" = raw ] || exit 23\n"
        "case \"$7\" in /proc/self/fd/*) ;; *) exit 24;; esac\n";
    if (mode == "replacement")
        script += "mv '" + overlay->path() + "' '" + owned.path() + "/moved' || exit 25\n"
            "printf replacement > '" + overlay->path() + "'\n";
    script += "printf '%s' \"$4\" > \"$7\"\n";
    put(dir.at("image-helper"), script);
    check(chmod(dir.at("image-helper").c_str(), 0700) == 0, "prepare isolated image helper");
    bool failed = false;
    try { Images(dir.at("image-helper")).rebase(*overlay, *backing); }
    catch (const std::exception&) { failed = true; }
    if (mode.empty()) {
        check(!failed && bytes_of(overlay->path()) == backing->path(), "helper modifies retained overlay and stores stable backing path");
        overlay->sync(); backing->sync();
    } else if (mode == "bad-format") {
        check(failed && bytes_of(overlay->path()) == "overlay", "invalid format never reaches rebase or falls back to qcow2");
    } else {
        check(failed && bytes_of(overlay->path()) == "replacement" &&
              bytes_of(owned.path() + "/moved") == backing->path(), "path substitution cannot redirect helper writes and fails post-check");
    }
    check((fcntl(overlay->fd(), F_GETFD) & FD_CLOEXEC) != 0 && (fcntl(backing->fd(), F_GETFD) & FD_CLOEXEC) != 0,
          "child inheritance never clears parent close-on-exec flags");
}
void leased_image_inspection(const std::string& mode) {
    Temporary dir;
    put(dir.at("overlay"), "original"); put(dir.at("base.raw"), "base"); put(dir.at("other.raw"), "other");
    config::DiskFileLeases pool;
    auto lease = pool.acquire({{dir.at("overlay"), false}, {dir.at("base.raw"), false}, {dir.at("other.raw"), false}});
    const int fd = lease->read_fd(dir.at("overlay"));
    std::string script = "#!/system/bin/sh\n[ \"$1\" = info ] && [ \"$2\" = --output=json ] || exit 20\n"
        "case \"$3\" in /proc/self/fd/*) ;; *) exit 21;; esac\n"
        "[ \"$(cat \"$3\")\" = original ] || exit 22\n";
    if (mode == "replacement") {
        script += "mv '" + dir.at("overlay") + "' '" + dir.at("moved") + "' || exit 23\n"
            "printf replacement > '" + dir.at("overlay") + "'\n"
            "[ \"$(cat \"$3\")\" = original ] || exit 24\n";
    }
    if (mode == "failure") script += "exit 25\n";
    else if (mode == "external-data") script += "printf '%s' '{\"format\":\"qcow2\",\"format-specific\":{\"data\":{\"data-file\":\"unleased.raw\"}}}'\n";
    else if (mode == "malformed") script += "printf '%s' '{\"format\":\"qcow2\",\"backing-filename\":5}'\n";
    else script += "printf '%s' '{\"format\":\"qcow2\",\"backing-filename\":\"base.raw\","
        "\"full-backing-filename\":\"/proc/self/fd/base.raw\"}'\n";
    put(dir.at("image-helper"), script);
    check(chmod(dir.at("image-helper").c_str(), 0700) == 0, "prepare leased image helper");
    std::optional<std::string> parent;
    bool failed = false;
    try { parent = Images(dir.at("image-helper")).backing_of(*lease, dir.at("overlay")); }
    catch (const std::exception&) { failed = true; }
    if (mode.empty()) {
        check(!failed && parent == dir.at("base.raw"), "relative backing uses original image directory, not descriptor directory");
        Images images(dir.at("image-helper"));
        const auto inspected = images.validate_backing(*lease, dir.at("overlay"), dir.at("base.raw"));
        check(inspected.format == "qcow2" && inspected.parent == dir.at("base.raw"), "inspection retains actual format and registered parent");
        fails_any([&] { images.validate_backing(*lease, dir.at("overlay"), std::nullopt); }, "unregistered actual backing rejected");
        fails_any([&] { images.validate_backing(*lease, dir.at("overlay"), dir.at("other.raw")); }, "different registered parent inode rejected");
        put(dir.at("image-helper"), "#!/system/bin/sh\nprintf '%s' '{\"format\":\"raw\"}'\n");
        images.validate_backing(*lease, dir.at("overlay"), std::nullopt);
        fails_any([&] { images.validate_backing(*lease, dir.at("overlay"), dir.at("base.raw")); }, "missing declared backing rejected");
    }
    else check(failed, "failed inspection or replaced path must not become a base image");
    if (mode == "replacement") check(bytes_of(dir.at("moved")) == "original" &&
        bytes_of(dir.at("overlay")) == "replacement", "descriptor inspection does not follow a substituted path");
    check((fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0,
        "parent descriptor remains close-on-exec");
}
void real_qemu_disk_graph(const std::string& image_tool, const std::string& system_tool) {
    Temporary dir;
    const auto base = dir.at("base.raw"), overlay = dir.at("overlay.qcow2");
    put(base, std::string(1u << 20, 'A'));
    ChildOptions create;
    create.argv = {image_tool, "create", "-f", "qcow2", "-F", "raw", "-b", base, overlay};
    auto result = Child(create).communicate({}, std::chrono::seconds(10), 65536);
    check(result.exit_code == 0 && !result.timed_out && !result.truncated, "create real qcow2 backing fixture");
    config::DiskFileLeases pool;
    auto lease = pool.acquire({{base, false}, {overlay, true}});
    auto base_fd = lease->open_file(base), overlay_fd = lease->open_file(overlay, true);
    const auto graph = vm::qemu_disk_graph({{base, {base_fd.get(), "raw", {}, true}},
        {overlay, {overlay_fd.get(), "qcow2", base, false}}});
    check(rename(base.c_str(), dir.at("old-base").c_str()) == 0 &&
        rename(overlay.c_str(), dir.at("old-overlay").c_str()) == 0, "replace both original paths before QEMU exec");
    put(base, "replacement base"); put(overlay, "replacement overlay");
    ChildOptions launch;
    launch.argv = {system_tool, "-machine", "none", "-accel", "tcg", "-nodefaults", "-display", "none", "-S", "-qmp", "stdio"};
    launch.argv.insert(launch.argv.end(), graph.argv.begin(), graph.argv.end());
    launch.preserve_fds = graph.preserve_fds;
    Json::Value read;
    read["execute"] = "human-monitor-command"; read["id"] = 3;
    read["arguments"]["command-line"] = "qemu-io " + graph.nodes.at(overlay) + " \"read -P 65 0 512\"";
    result = Child(launch).communicate("{\"execute\":\"qmp_capabilities\",\"id\":1}\n"
        "{\"execute\":\"query-named-block-nodes\",\"id\":2}\n" + wire::stringify(read) +
        "\n{\"execute\":\"quit\",\"id\":4}\n",
        std::chrono::seconds(10), 1u << 20);
    check(result.exit_code == 0 && !result.timed_out && !result.truncated, "real QEMU opens retained full graph without booting a guest");
    bool queried = false, read_original = false;
    std::string read_output;
    size_t offset = 0;
    while (offset < result.output.size()) {
        auto end = result.output.find('\n', offset);
        if (end == std::string::npos) end = result.output.size();
        const auto line = result.output.substr(offset, end - offset); offset = end + 1;
        if (line.empty()) continue;
        // qemu-io may write directly to stdout instead of the HMP capture buffer.
        if (line.front() != '{') { read_output += line + "\n"; continue; }
        Json::Value reply;
        try { reply = parse_object(line); }
        catch (const std::exception&) { throw std::runtime_error("Unexpected QMP output: " + line); }
        check(!reply.isMember("error"), "QMP commands succeed");
        if (reply["id"] == 3) {
            check(reply["return"].isString(), "HMP read completes with a string response");
            read_output += reply["return"].asString();
            read_original = true;
        }
        if (reply["id"] != 2) continue;
        std::map<std::string, Json::Value> nodes;
        for (const auto& node : reply["return"]) nodes.emplace(node["node-name"].asString(), node);
        check(nodes.contains(graph.nodes.at(base)) && nodes.contains(graph.nodes.at(overlay)) &&
            nodes.at(graph.nodes.at(base))["drv"] == "raw" && nodes.at(graph.nodes.at(overlay))["drv"] == "qcow2",
            "QMP reports the explicit retained nodes with their actual drivers");
        queried = true;
    }
    check(read_output.find("read 512/512 bytes") != std::string::npos &&
          read_output.find("Pattern verification failed") == std::string::npos,
          "reading through overlay reaches the original retained backing bytes");
    check(queried && read_original && bytes_of(base) == "replacement base" && bytes_of(overlay) == "replacement overlay",
        "QEMU graph succeeds without modifying replacement paths");
}
void real_retained_rebase(const std::string& tool) {
    Temporary dir;
    CreatedDirectory owned(dir.path, "import");
    std::vector<std::unique_ptr<RetainedFile>> files;
    for (const auto* name : {"old.raw", "new.raw", "overlay.qcow2"}) {
        FileSink out(owned.fd(), name);
        if (std::string_view(name) != "overlay.qcow2") out.append(std::string(1u << 20, '\0'));
        out.flush();
        files.push_back(std::make_unique<RetainedFile>(out.fd(), owned.fd(), owned.path(), name));
        out.close();
    }
    const auto overlay_path = "/proc/self/fd/" + std::to_string(files[2]->fd());
    ChildOptions create;
    create.argv = {tool, "create", "-f", "qcow2", "-F", "raw", "-b", files[0]->path(), overlay_path};
    create.preserve_fds = {files[2]->fd()};
    auto result = Child(create).communicate({}, std::chrono::seconds(10));
    check(result.exit_code == 0 && !result.timed_out && !result.truncated, "real qemu creates overlay through retained descriptor");
    Images(tool).rebase(*files[2], *files[1]);
    for (const auto& file : files) file->sync();
    owned.sync();
    ChildOptions inspect;
    inspect.argv = {tool, "info", "--output=json", overlay_path};
    inspect.preserve_fds = {files[2]->fd()};
    result = Child(inspect).communicate({}, std::chrono::seconds(10));
    check(result.exit_code == 0 && !result.timed_out && !result.truncated, "real qemu reads rebased overlay");
    const auto info = parse_object(result.output);
    check(info["format"] == "qcow2" && info["backing-filename"] == files[1]->path() &&
          info["backing-filename-format"] == "raw", "real header stores new durable backing path and format");
    for (const auto& file : files) file->verify();
    ChildOptions relative;
    relative.argv = {tool, "rebase", "-u", "-b", "new.raw", "-F", "raw", overlay_path};
    relative.preserve_fds = {files[2]->fd()};
    result = Child(relative).communicate({}, std::chrono::seconds(10));
    check(result.exit_code == 0 && !result.timed_out && !result.truncated, "real qemu writes relative backing name");
    config::DiskFileLeases pool;
    auto lease = pool.acquire({{files[2]->path(), false}, {files[1]->path(), false}});
    check(Images(tool).backing_of(*lease, files[2]->path()) == files[1]->path(),
        "real qemu inspection resolves relative backing from leased original path");
    Images(tool).validate_backing(*lease, files[2]->path(), files[1]->path());
}

// Coordinated in-place disk operations. data_dir empty = fake tool in the fixture.
struct DiskOps {
    Temporary dir;
    const CallContext caller{"disk-owner", true, true, true};
    std::string data_dir;
    Fd directory;
    std::shared_ptr<ConfigurationGate> gate;
    vm::RuntimeContext runtime;
    std::unique_ptr<VmService> vms;
    std::unique_ptr<TaskService> tasks;
    std::unique_ptr<ConfigurationService> configuration;
    std::unique_ptr<DiskOperationService> operations;
    std::function<void(const char*)> fault;
    explicit DiskOps(const std::string& tool = {}) {
        directory = Fd(open(dir.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        if (tool.empty()) {
            data_dir = dir.path;
            check(make_dirs(dir.at("usr/bin")), "create fake tool directory");
            // info: plain raw. convert: write a marker into the descriptor target.
            put(dir.at("usr/bin/qemu-img"), "#!/system/bin/sh\n"
                "echo \"$@\" >> " + dir.at("tool.log") + "\n"
                "case \"$1\" in\n"
                "info) real=$(readlink \"$3\"); if [ -e \"$real.backing\" ]; then printf '{\"format\":\"qcow2\",\"backing-filename\":\"%s\"}' \"$(cat \"$real.backing\")\"; else printf '%s' '{\"format\":\"raw\"}'; fi ;;\n"
                "commit|rebase) [ -e " + dir.at("fail") + " ] && exit 3; exit 0 ;;\n"
                "convert) [ -e " + dir.at("slow") + " ] && sleep 30; [ -e " + dir.at("fail") + " ] && exit 3\n"
                "  eval \"out=\\${$#}\"; printf converted > \"$out\" ;;\n"
                "create) [ -e " + dir.at("fail") + " ] && exit 3; eval \"out=\\${$(($# - 1))}\"; printf created > \"$out\" ;;\n"
                "resize) ;;\n"
                "*) exit 9 ;;\nesac\n");
            check(chmod(dir.at("usr/bin/qemu-img").c_str(), 0700) == 0, "enable fake image tool");
        } else data_dir = dirname(dirname(dirname(tool))); // <data>/usr/bin/qemu-img
        open_services();
    }
    ~DiskOps() { close_services(); }
    void open_services() {
        gate = std::make_shared<ConfigurationGate>();
        runtime.cache_dir = dir.path; runtime.data_dir = dir.path; runtime.owner = getuid(); runtime.configuration_gate = gate;
        runtime.shutting_down = [] { return false; };
        vms = std::make_unique<VmService>(runtime);
        TaskLimits limits;
        limits.background_workers = 2;
        tasks = std::make_unique<TaskService>(limits, [] { return TaskService::Clock::now(); }, EventLimits{}, gate);
        configuration = std::make_unique<ConfigurationService>(directory.get(), getuid(), gate, *vms, *tasks,
            config::ConfigTransaction::Observer{}, true);
        DiskOperationContext context;
        context.configuration = configuration.get(); context.directory = directory.get(); context.owner = getuid();
        context.data_dir = data_dir;
        context.fault = [this](const char* stage) { if (fault) fault(stage); };
        operations = std::make_unique<DiskOperationService>(context);
    }
    void close_services() {
        if (tasks) tasks->shutdown();
        operations.reset(); configuration.reset(); tasks.reset(); vms.reset();
    }
    // Simulated daemon death: no cleanup beyond what a crash would leave.
    void restart() { close_services(); open_services(); }
    std::string revision() { return configuration->disks()->snapshot(caller)->revision; }
    std::string add(const std::string& name, const std::optional<std::string>& parent = {}) {
        const auto before = configuration->disks()->snapshot(caller);
        auto document = before->document;
        Json::Value row;
        row["id"] = random_id(true); row["name"] = name; row["folder"] = dir.path;
        if (parent) row["parent"] = *parent;
        document["disks"].append(row);
        // Joint commit: families referenced by VMs reject registry-only edits.
        const auto vms = configuration->vms().snapshot(caller);
        configuration->replace_vm_disks(caller, vms->revision, before->revision, vms->document, document);
        return row["id"].asString();
    }
    // One VM per entry: {name, [[path, readonly]...]}.
    void set_vms(const std::vector<std::pair<std::string, std::vector<std::pair<std::string, bool>>>>& entries) {
        const auto vms = configuration->vms().snapshot(caller);
        const auto disks = configuration->disks()->snapshot(caller);
        auto document = vms->document;
        document["vms"] = Json::Value(Json::arrayValue);
        for (const auto& [name, slots] : entries) {
            Json::Value vm;
            vm["id"] = random_id(true); vm["name"] = name;
            vm["disks"] = Json::Value(Json::arrayValue);
            for (const auto& [path, readonly] : slots) {
                Json::Value slot; slot["path"] = path; slot["readonly"] = readonly; slot["bus"] = "virtio";
                vm["disks"].append(slot);
            }
            document["vms"].append(vm);
        }
        configuration->replace_vm_disks(caller, vms->revision, disks->revision, document, disks->document);
    }
    Json::Value slots(const std::string& name) {
        for (const auto& vm : configuration->vms().snapshot(caller)->document["vms"]) if (vm["name"] == name) return vm["disks"];
        return Json::Value();
    }
    Json::Value row(const std::string& id) {
        for (const auto& row : configuration->disks()->snapshot(caller)->document["disks"]) if (row["id"] == id) return row;
        return Json::Value();
    }
    Json::Value request(const std::string& id, const std::string& action) {
        Json::Value value;
        value["disk_revision"] = revision(); value["disk_id"] = id; value["action"] = action;
        return value;
    }
    TaskView run(const Json::Value& request) {
        using namespace std::chrono_literals;
        const auto response = operations->start(caller, request);
        const TaskRef ref{response["epoch"].asString(), response["task_id"].asString()};
        const auto deadline = TaskService::Clock::now() + 60s;
        auto task = tasks->get(caller, ref);
        while (!task_terminal(task.state) && TaskService::Clock::now() < deadline) {
            std::this_thread::sleep_for(2ms); task = tasks->get(caller, ref);
        }
        check(task_terminal(task.state), "disk operation bounded completion");
        return task;
    }
};
ErrorCode start_error(DiskOps& ops, const Json::Value& request, const CallContext* caller = nullptr) {
    try { ops.operations->start(caller ? *caller : ops.caller, request); }
    catch (const ServiceError& error) { return error.code(); }
    throw std::runtime_error("disk operation admission unexpectedly succeeded");
}
size_t temporaries(const std::string& path) {
    size_t count = 0;
    std::unique_ptr<DIR, decltype(&closedir)> listing(opendir(path.c_str()), &closedir);
    while (const auto* entry = listing ? readdir(listing.get()) : nullptr)
        if (std::string_view(entry->d_name).starts_with(".dvm-")) ++count;
    return count;
}
ino_t inode_of(const std::string& path) {
    struct stat info{};
    check(stat(path.c_str(), &info) == 0, "stat disk image");
    return info.st_ino;
}
void disk_operation_admission() {
    DiskOps ops;
    put(ops.dir.at("a.img"), "original"); put(ops.dir.at("b.img"), "base");
    const auto a = ops.add("a.img"), b = ops.add("b.img");
    const CallContext anonymous{};
    check(start_error(ops, ops.request(a, "convert"), &anonymous) == ErrorCode::unauthenticated,
        "disk operations require authentication");
    auto stale = ops.request(a, "convert"); stale["disk_revision"] = "stale";
    check(start_error(ops, stale) == ErrorCode::conflict, "stale disk revision rejected");
    check(start_error(ops, ops.request(random_id(true), "convert")) == ErrorCode::not_found, "unknown disk rejected");
    auto bad = ops.request(a, "resize");
    check(start_error(ops, bad) == ErrorCode::invalid_argument, "resize needs size");
    bad = ops.request(a, "convert"); bad["format"] = "vmdk";
    check(start_error(ops, bad) == ErrorCode::invalid_argument, "unsupported target format rejected");
    check(start_error(ops, ops.request(a, "flatten")) == ErrorCode::conflict, "standalone disk cannot flatten");
    {
        auto writer = ops.configuration->disk_files()->acquire({{ops.dir.at("a.img"), false}});
        check(start_error(ops, ops.request(a, "convert")) == ErrorCode::conflict, "running VM read lease blocks rewrite");
    }
    put(ops.dir.at("c.img"), "child");
    ops.add("c.img", b);
    check(start_error(ops, ops.request(b, "convert")) == ErrorCode::conflict, "disk with overlays cannot be rewritten");
    check(bytes_of(ops.dir.at("a.img")) == "original" && temporaries(ops.dir.path) == 0, "rejected admission changes nothing");
}
void disk_operation_journal() {
    DiskOps ops;
    put(ops.dir.at("a.img"), "original"); put(ops.dir.at("b.img"), "other");
    check(chmod(ops.dir.at("a.img").c_str(), 0640) == 0, "set source mode");
    const auto a = ops.add("a.img"), b = ops.add("b.img");
    // Registry edits racing the image rewrite: held row and new children fail, others pass.
    bool held_rejected = false, child_rejected = false, unrelated_saved = false;
    ops.fault = [&](const char* stage) {
        if (std::string_view(stage) != "converted") return;
        const auto before = ops.configuration->disks()->snapshot(ops.caller);
        auto renamed = before->document;
        for (auto& row : renamed["disks"]) if (row["id"] == a) row["name"] = "moved.img";
        try { ops.configuration->disks()->replace(ops.caller, before->revision, renamed); }
        catch (const ServiceError& error) { held_rejected = error.code() == ErrorCode::conflict; }
        auto child = before->document;
        Json::Value row; row["id"] = random_id(true); row["name"] = "x.img"; row["folder"] = ops.dir.path; row["parent"] = a;
        child["disks"].append(row);
        try { ops.configuration->disks()->replace(ops.caller, before->revision, child); }
        catch (const ServiceError& error) { child_rejected = error.code() == ErrorCode::conflict; }
        auto unrelated = before->document;
        for (auto& row : unrelated["disks"]) if (row["id"] == b) row["note"] = "edited";
        ops.configuration->disks()->replace(ops.caller, before->revision, unrelated);
        unrelated_saved = true;
    };
    const auto old_inode = inode_of(ops.dir.at("a.img"));
    auto task = ops.run(ops.request(a, "convert"));
    check(task.state == TaskState::succeeded && task.result["format"] == "raw", "convert succeeds");
    check(held_rejected && child_rejected && unrelated_saved, "reservation blocks only held rows and new children");
    struct stat info{};
    check(stat(ops.dir.at("a.img").c_str(), &info) == 0 && (info.st_mode & 07777) == 0640 && info.st_ino != old_inode,
        "replacement keeps mode under a new inode");
    check(bytes_of(ops.dir.at("a.img")) == "converted" && temporaries(ops.dir.path) == 0 && ops.operations->pending() == 0,
        "convert replaces image and clears journal");
    check(ops.row(a)["name"] == "a.img", "convert keeps the registry row");
    ops.fault = {};
    put(ops.dir.at("fail"), "");
    task = ops.run(ops.request(a, "convert"));
    check(task.state == TaskState::failed && task.error == ErrorCode::io_error, "tool failure reported");
    check(bytes_of(ops.dir.at("a.img")) == "converted" && temporaries(ops.dir.path) == 0 && ops.operations->pending() == 0,
        "tool failure removes the partial copy");
    check(unlink(ops.dir.at("fail").c_str()) == 0, "clear failure marker");
    put(ops.dir.at("slow"), "");
    {
        using namespace std::chrono_literals;
        const auto response = ops.operations->start(ops.caller, ops.request(a, "convert"));
        const TaskRef ref{response["epoch"].asString(), response["task_id"].asString()};
        const auto deadline = TaskService::Clock::now() + 10s;
        while (temporaries(ops.dir.path) == 0 && TaskService::Clock::now() < deadline) std::this_thread::sleep_for(2ms);
        std::this_thread::sleep_for(100ms);
        ops.tasks->cancel(ops.caller, ref);
        auto view = ops.tasks->get(ops.caller, ref);
        while (!task_terminal(view.state) && TaskService::Clock::now() < deadline) { std::this_thread::sleep_for(2ms); view = ops.tasks->get(ops.caller, ref); }
        check(view.state == TaskState::cancelled, "convert cancellation stops the tool");
    }
    check(bytes_of(ops.dir.at("a.img")) == "converted" && temporaries(ops.dir.path) == 0 && ops.operations->pending() == 0,
        "cancellation removes the partial copy");
    check(unlink(ops.dir.at("slow").c_str()) == 0, "clear slow marker");
    // Crash with a journaled partial copy: no new operation until replay removes it.
    put(ops.dir.at("a.img"), "original");
    ops.fault = [](const char* stage) { if (std::string_view(stage) == "prepared") throw std::runtime_error("crash"); };
    task = ops.run(ops.request(a, "convert"));
    check(task.state == TaskState::failed && temporaries(ops.dir.path) == 1 && ops.operations->pending() == 1, "crash leaves journaled copy");
    ops.fault = {};
    check(start_error(ops, ops.request(a, "convert")) == ErrorCode::unavailable, "unrecovered disk refuses new operation");
    ops.restart();
    check(temporaries(ops.dir.path) == 0 && ops.operations->pending() == 0 && bytes_of(ops.dir.at("a.img")) == "original",
        "restart removes only the partial copy");
    // Crash after replacement: the new image stays and replay only clears the record.
    ops.fault = [](const char* stage) { if (std::string_view(stage) == "replaced") throw std::runtime_error("crash"); };
    task = ops.run(ops.request(a, "convert"));
    check(task.state == TaskState::failed && ops.operations->pending() == 1, "post-rename crash keeps record");
    ops.fault = {};
    ops.restart();
    check(bytes_of(ops.dir.at("a.img")) == "converted" && temporaries(ops.dir.path) == 0 && ops.operations->pending() == 0,
        "replay keeps completed replacement");
    // A replaced temporary name is never deleted by replay.
    ops.fault = [](const char* stage) { if (std::string_view(stage) == "prepared") throw std::runtime_error("crash"); };
    task = ops.run(ops.request(a, "convert"));
    ops.fault = {};
    std::string temporary;
    {
        std::unique_ptr<DIR, decltype(&closedir)> listing(opendir(ops.dir.path.c_str()), &closedir);
        while (const auto* entry = readdir(listing.get())) if (std::string_view(entry->d_name).starts_with(".dvm-")) temporary = entry->d_name;
    }
    // Allocate the foreign inode before the journaled one is freed.
    put(ops.dir.at("foreign.tmp"), "foreign");
    check(!temporary.empty() && rename(ops.dir.at("foreign.tmp").c_str(), ops.dir.at(temporary).c_str()) == 0, "replace journaled copy");
    ops.restart();
    check(ops.operations->pending() == 1 && bytes_of(ops.dir.at(temporary)) == "foreign", "foreign file at temporary name is kept");
    check(unlink(ops.dir.at(temporary).c_str()) == 0, "remove foreign file");
    check(ops.operations->recover(ops.caller)["pending"].asUInt64() == 0, "administrator recovery clears resolved record");
    // Resize keeps the inode, passes an explicit no-backing node and the size.
    const auto kept = inode_of(ops.dir.at("a.img"));
    auto resize = ops.request(a, "resize"); resize["size"] = Json::Int64(1048576); resize["shrink"] = true;
    task = ops.run(resize);
    const auto log = bytes_of(ops.dir.at("tool.log"));
    check(task.state == TaskState::succeeded && inode_of(ops.dir.at("a.img")) == kept, "resize edits the leased inode in place");
    check(log.find("resize --shrink json:{\"driver\":\"raw\",\"file\":{\"driver\":\"file\",\"filename\":\"/proc/self/fd/") != std::string::npos
        && log.find("1048576") != std::string::npos, "resize uses retained descriptor and exact size");
}
void disk_operation_create() {
    DiskOps ops;
    put(ops.dir.at("a.img"), "original");
    const auto a = ops.add("a.img");
    auto create = [&](const std::string& name) {
        auto value = ops.request("", "create");
        value.removeMember("disk_id");
        value["folder"] = ops.dir.path; value["name"] = name; value["format"] = "raw"; value["size"] = Json::Int64(4096);
        return value;
    };
    auto task = ops.run(create("new.img"));
    const auto id = task.result["disk_id"].asString();
    struct stat info{}, folder{};
    check(task.state == TaskState::succeeded && ops.row(id)["name"] == "new.img" && !ops.row(id).isMember("parent")
        && bytes_of(ops.dir.at("new.img")) == "created", "create installs and registers a new image");
    check(stat(ops.dir.at("new.img").c_str(), &info) == 0 && stat(ops.dir.path.c_str(), &folder) == 0
        && info.st_uid == folder.st_uid && (info.st_mode & 07777) == 0644 && info.st_nlink == 1, "new image owned like its folder");
    check(start_error(ops, create("new.img")) == ErrorCode::conflict, "registered target path rejected");
    put(ops.dir.at("stray.img"), "stray");
    check(start_error(ops, create("stray.img")) == ErrorCode::conflict, "existing unregistered file is never overwritten");
    for (const auto* name : {"..", "a/b", ".dvm-x.tmp", ""})
        check(start_error(ops, create(name)) == ErrorCode::invalid_argument, "invalid new disk name rejected");
    auto bad = create("bad.img"); bad["folder"] = ops.dir.path + "/../x";
    check(start_error(ops, bad) == ErrorCode::invalid_argument, "non-normalized folder rejected");
    bad = create("bad.img"); bad["format"] = "iso";
    check(start_error(ops, bad) == ErrorCode::invalid_argument, "uncreatable format rejected");
    bad = create("bad.img"); bad["backing_id"] = a;
    check(start_error(ops, bad) == ErrorCode::invalid_argument, "raw image cannot have backing");
    auto overlay = create("overlay.qcow2"); overlay["format"] = "qcow2"; overlay["backing_id"] = a;
    task = ops.run(overlay);
    check(task.state == TaskState::succeeded && ops.row(task.result["disk_id"].asString())["parent"] == a
        && bytes_of(ops.dir.at("tool.log")).find("create -f qcow2 -b " + ops.dir.at("a.img") + " -F raw") != std::string::npos,
        "overlay create links registered backing by durable path");
    auto clone = ops.request(a, "clone"); clone["folder"] = ops.dir.path; clone["name"] = "copy.img";
    task = ops.run(clone);
    check(task.state == TaskState::succeeded && bytes_of(ops.dir.at("copy.img")) == "converted"
        && ops.row(task.result["disk_id"].asString())["name"] == "copy.img" && bytes_of(ops.dir.at("a.img")) == "original",
        "clone writes a new registered copy and leaves the source");
    // A file appearing at the target while the tool runs wins; nothing is replaced.
    ops.fault = [&](const char* stage) { if (std::string_view(stage) == "converted") put(ops.dir.at("race.img"), "foreign"); };
    task = ops.run(create("race.img"));
    check(task.state == TaskState::failed && task.error == ErrorCode::conflict && bytes_of(ops.dir.at("race.img")) == "foreign"
        && temporaries(ops.dir.path) == 0 && ops.operations->pending() == 0, "racing target file is kept");
    // Crash after installation but before registration rolls the file back.
    ops.fault = [](const char* stage) { if (std::string_view(stage) == "replaced") throw std::runtime_error("crash"); };
    task = ops.run(create("lost.img"));
    check(task.state == TaskState::failed && exists(ops.dir.at("lost.img")) && ops.operations->pending() == 1, "crash leaves unregistered image");
    ops.fault = {};
    check(start_error(ops, create("lost.img")) == ErrorCode::conflict, "pending target cannot be reused");
    ops.restart();
    check(!exists(ops.dir.at("lost.img")) && ops.operations->pending() == 0 && temporaries(ops.dir.path) == 0, "replay removes unregistered image");
    for (const auto& row : ops.configuration->disks()->snapshot(ops.caller)->document["disks"])
        check(row["name"] != "lost.img", "rolled-back image has no registry row");
    ops.fault = [](const char* stage) { if (std::string_view(stage) == "prepared") throw std::runtime_error("crash"); };
    task = ops.run(create("half.img"));
    ops.fault = {};
    check(temporaries(ops.dir.path) == 1 && !exists(ops.dir.at("half.img")), "crash before installation keeps only the temporary");
    ops.restart();
    check(temporaries(ops.dir.path) == 0 && ops.operations->pending() == 0, "replay removes the temporary");
    put(ops.dir.at("fail"), "");
    task = ops.run(create("failed.img"));
    check(task.state == TaskState::failed && !exists(ops.dir.at("failed.img")) && temporaries(ops.dir.path) == 0
        && ops.operations->pending() == 0, "tool failure leaves nothing behind");
}
void disk_slot_reattachment() {
    const auto b = random_id(true), o = random_id(true), c = random_id(true), x = random_id(true);
    auto row = [](const std::string& id, const std::string& name, const std::string& parent = {}) {
        Json::Value value; value["id"] = id; value["name"] = name; value["folder"] = "/d";
        if (!parent.empty()) value["parent"] = parent;
        return value;
    };
    Json::Value before; before["disks"].append(row(b, "b")); before["disks"].append(row(o, "o", b));
    before["disks"].append(row(c, "c", o)); before["disks"].append(row(x, "x"));
    auto slot = [](const std::string& path, bool readonly) {
        Json::Value value; value["path"] = path; value["readonly"] = readonly; value["bus"] = "virtio"; return value;
    };
    Json::Value vms;
    for (const auto& [name, path] : std::vector<std::pair<std::string, std::string>>{{"v1", "/d/o"}, {"v2", "/d/c"}, {"v3", "/d/x"}}) {
        Json::Value vm; vm["name"] = name; vm["disks"].append(slot(path, false)); vms["vms"].append(vm);
    }
    Json::Value merged; merged["disks"].append(row(b, "b")); merged["disks"].append(row(c, "c", b)); merged["disks"].append(row(x, "x"));
    auto after = config::reattach_disk_slots(vms, before, merged);
    check(after["vms"][0]["disks"][0] == slot("/d/b", true) && after["vms"][1]["disks"][0] == slot("/d/c", false)
        && after["vms"][2]["disks"][0] == slot("/d/x", false), "merge moves overlay slot to its base read-only");
    Json::Value pruned; pruned["disks"].append(row(b, "b")); pruned["disks"].append(row(x, "x"));
    after = config::reattach_disk_slots(vms, before, pruned);
    check(after["vms"][0]["disks"][0] == slot("/d/b", true) && after["vms"][1]["disks"][0] == slot("/d/b", true),
        "subtree delete climbs to the surviving base and shares it read-only");
    Json::Value lone; lone["disks"].append(row(b, "b")); lone["disks"].append(row(o, "o", b)); lone["disks"].append(row(c, "c", o));
    after = config::reattach_disk_slots(vms, before, lone);
    check(after["vms"][2]["disks"].size() == 0 && after["vms"][0]["disks"][0] == slot("/d/o", false),
        "slot without surviving ancestor is removed; unrelated families stay");
}
void disk_operation_tree() {
    DiskOps ops;
    put(ops.dir.at("b.img"), "base"); put(ops.dir.at("o.qcow2"), "overlay"); put(ops.dir.at("c.qcow2"), "child");
    put(ops.dir.at("o.qcow2.backing"), ops.dir.at("b.img")); put(ops.dir.at("c.qcow2.backing"), ops.dir.at("o.qcow2"));
    const auto b = ops.add("b.img"), o = ops.add("o.qcow2", b), c = ops.add("c.qcow2", o);
    ops.set_vms({{"merge", {{ops.dir.at("o.qcow2"), true}}}, {"leaf", {{ops.dir.at("c.qcow2"), true}}}});
    {
        auto reader = ops.configuration->disk_files()->acquire({{ops.dir.at("c.qcow2"), false}});
        check(start_error(ops, ops.request(o, "commit")) == ErrorCode::conflict, "running overlay child blocks merge");
    }
    check(start_error(ops, ops.request(b, "commit")) == ErrorCode::conflict, "standalone disk cannot merge");
    auto task = ops.run(ops.request(o, "commit"));
    const auto log = bytes_of(ops.dir.at("tool.log"));
    check(task.state == TaskState::succeeded && !exists(ops.dir.at("o.qcow2")) && ops.row(o).isNull()
        && ops.row(c)["parent"] == b && ops.slots("merge")[0]["path"] == ops.dir.at("b.img")
        && ops.slots("merge")[0]["readonly"] == true && ops.slots("leaf")[0]["path"] == ops.dir.at("c.qcow2"),
        "merge relinks children, moves slots and removes the overlay");
    check(log.find("commit -d json:") != std::string::npos
        && log.find("rebase -u -b " + ops.dir.at("b.img") + " -F raw /proc/self/fd/") != std::string::npos, "merge commands");
    put(ops.dir.at("c.qcow2.backing"), ops.dir.at("b.img"));
    // Two overlays on one parent: merging either would change the other's view.
    put(ops.dir.at("d.qcow2"), "sibling"); put(ops.dir.at("d.qcow2.backing"), ops.dir.at("b.img"));
    const auto d = ops.add("d.qcow2", b);
    check(start_error(ops, ops.request(c, "commit")) == ErrorCode::conflict, "parent with siblings cannot take a merge");
    // Crash after children were relinked: recovery completes registry and unlink.
    auto del = ops.request(d, "delete"); del["delete_files"] = true;
    task = ops.run(del);
    check(task.state == TaskState::succeeded && !exists(ops.dir.at("d.qcow2")) && ops.row(d).isNull(), "delete removes leaf and file");
    put(ops.dir.at("e.qcow2"), "grandchild"); put(ops.dir.at("e.qcow2.backing"), ops.dir.at("c.qcow2"));
    const auto e = ops.add("e.qcow2", c);
    ops.fault = [](const char* stage) { if (std::string_view(stage) == "rebased") throw std::runtime_error("crash"); };
    task = ops.run(ops.request(c, "commit"));
    check(task.state == TaskState::failed && ops.operations->pending() == 1 && ops.row(c).isObject(), "merge crash after relink keeps record");
    ops.fault = {};
    ops.restart();
    check(ops.operations->pending() == 0 && ops.row(c).isNull() && ops.row(e)["parent"] == b && !exists(ops.dir.at("c.qcow2"))
        && ops.slots("leaf")[0]["path"] == ops.dir.at("b.img") && ops.slots("leaf")[0]["readonly"] == true,
        "recovery finishes an interrupted merge");
    put(ops.dir.at("e.qcow2.backing"), ops.dir.at("b.img"));
    // Crash while the parent is being written: nothing relinked, overlay kept.
    ops.fault = [](const char* stage) { if (std::string_view(stage) == "committed") throw std::runtime_error("crash"); };
    task = ops.run(ops.request(e, "commit"));
    ops.fault = {};
    ops.restart();
    check(ops.operations->pending() == 0 && ops.row(e)["parent"] == b && exists(ops.dir.at("e.qcow2")), "interrupted copy keeps overlay");
    // Registry-only delete keeps files; subtree delete with files after a crash.
    task = ops.run(ops.request(e, "delete"));
    check(task.state == TaskState::succeeded && ops.row(e).isNull() && exists(ops.dir.at("e.qcow2")), "registry-only delete keeps file");
    put(ops.dir.at("f.qcow2"), "f"); put(ops.dir.at("f.qcow2.backing"), ops.dir.at("b.img"));
    const auto f = ops.add("f.qcow2", b);
    del = ops.request(b, "delete"); del["delete_files"] = true;
    ops.fault = [](const char* stage) { if (std::string_view(stage) == "registered") throw std::runtime_error("crash"); };
    task = ops.run(del);
    check(task.state == TaskState::failed && ops.row(b).isNull() && ops.row(f).isNull() && exists(ops.dir.at("f.qcow2")),
        "delete crash after registry keeps files journaled");
    ops.fault = {};
    ops.restart();
    check(ops.operations->pending() == 0 && !exists(ops.dir.at("b.img")) && !exists(ops.dir.at("f.qcow2"))
        && ops.slots("leaf").size() == 0 && ops.slots("merge").size() == 0, "recovery deletes the subtree files and slots");
}
Json::Value real_info(const std::string& tool, const std::string& path) {
    ChildOptions options;
    options.argv = {tool, "info", "--output=json", path};
    const auto result = Child(options).communicate({}, std::chrono::seconds(10));
    check(result.exit_code == 0 && !result.timed_out, "real qemu-img info");
    return parse_object(result.output);
}
std::string real_head(const std::string& tool, const std::string& path, const std::string& out) {
    ChildOptions options;
    options.argv = {tool, "convert", "-O", "raw", path, out};
    const auto result = Child(options).communicate({}, std::chrono::seconds(30));
    check(result.exit_code == 0 && !result.timed_out, "real qemu-img reads image view");
    return bytes_of(out).substr(0, 8);
}
void real_disk_operations(const std::string& tool) {
    DiskOps ops(tool);
    std::string base(1u << 20, '\0');
    base.replace(0, 8, "BASEDATA");
    put(ops.dir.at("base.raw"), base);
    ChildOptions create;
    create.argv = {tool, "create", "-f", "qcow2", "-F", "raw", "-b", ops.dir.at("base.raw"), ops.dir.at("ov.qcow2")};
    check(Child(create).communicate({}, std::chrono::seconds(10)).exit_code == 0, "create real overlay");
    const auto base_id = ops.add("base.raw"), overlay = ops.add("ov.qcow2", base_id);
    auto resize = ops.request(overlay, "resize"); resize["size"] = Json::Int64(2u << 20);
    auto task = ops.run(resize);
    auto info = real_info(tool, ops.dir.at("ov.qcow2"));
    check(task.state == TaskState::succeeded && info["virtual-size"].asInt64() == (2 << 20)
        && info["backing-filename"] == ops.dir.at("base.raw"), "real resize keeps overlay backing");
    auto convert = ops.request(overlay, "convert"); convert["compress"] = "zstd";
    task = ops.run(convert);
    info = real_info(tool, ops.dir.at("ov.qcow2"));
    check(task.state == TaskState::succeeded && info["backing-filename"] == ops.dir.at("base.raw")
        && info["format-specific"]["data"]["compression-type"] == "zstd", "real convert keeps durable backing");
    check(real_head(tool, ops.dir.at("ov.qcow2"), ops.dir.at("view1.raw")) == "BASEDATA", "converted overlay reads base");
    auto make = ops.request("", "create"); make.removeMember("disk_id");
    make["folder"] = ops.dir.path; make["name"] = "child.qcow2"; make["format"] = "qcow2";
    make["size"] = Json::Int64(1 << 20); make["backing_id"] = base_id;
    task = ops.run(make);
    info = real_info(tool, ops.dir.at("child.qcow2"));
    check(task.state == TaskState::succeeded && info["backing-filename"] == ops.dir.at("base.raw")
        && ops.row(task.result["disk_id"].asString())["parent"] == base_id
        && real_head(tool, ops.dir.at("child.qcow2"), ops.dir.at("view3.raw")) == "BASEDATA", "real overlay create");
    auto clone = ops.request(overlay, "clone"); clone["folder"] = ops.dir.path; clone["name"] = "clone.qcow2";
    task = ops.run(clone);
    info = real_info(tool, ops.dir.at("clone.qcow2"));
    check(task.state == TaskState::succeeded && info["format"] == "qcow2" && info["backing-filename"] == ops.dir.at("base.raw")
        && ops.row(task.result["disk_id"].asString())["parent"] == base_id
        && real_head(tool, ops.dir.at("clone.qcow2"), ops.dir.at("view4.raw")) == "BASEDATA", "real overlay clone keeps its parent");
    ops.fault = [](const char* stage) { if (std::string_view(stage) == "replaced") throw std::runtime_error("crash"); };
    task = ops.run(ops.request(overlay, "flatten"));
    check(task.state == TaskState::failed && ops.row(overlay).isMember("parent"), "flatten crash leaves registry link");
    ops.fault = {};
    ops.restart();
    info = real_info(tool, ops.dir.at("ov.qcow2"));
    check(ops.operations->pending() == 0 && !ops.row(overlay).isMember("parent") && !info.isMember("backing-filename"),
        "replay completes flatten registry update");
    check(rename(ops.dir.at("base.raw").c_str(), ops.dir.at("base.moved").c_str()) == 0, "move former base");
    check(real_head(tool, ops.dir.at("ov.qcow2"), ops.dir.at("view2.raw")) == "BASEDATA", "flattened image is standalone");
    // Merge a real overlay holding its own bytes, then delete the family with files.
    std::string upper(1u << 20, '\0'), lower(1u << 20, '\0');
    upper.replace(0, 8, "OVERDATA"); lower.replace(0, 8, "BASE2DAT");
    put(ops.dir.at("upper.raw"), upper); put(ops.dir.at("base2.raw"), lower);
    ChildOptions diff;
    diff.argv = {tool, "convert", "-O", "qcow2", "-B", ops.dir.at("base2.raw"), "-F", "raw", ops.dir.at("upper.raw"), ops.dir.at("ov2.qcow2")};
    check(Child(diff).communicate({}, std::chrono::seconds(30)).exit_code == 0, "create real differencing overlay");
    ChildOptions grand;
    grand.argv = {tool, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", ops.dir.at("ov2.qcow2"), ops.dir.at("child2.qcow2")};
    check(Child(grand).communicate({}, std::chrono::seconds(10)).exit_code == 0, "create real grandchild");
    const auto base2 = ops.add("base2.raw"), ov2 = ops.add("ov2.qcow2", base2), child2 = ops.add("child2.qcow2", ov2);
    task = ops.run(ops.request(ov2, "commit"));
    info = real_info(tool, ops.dir.at("child2.qcow2"));
    check(task.state == TaskState::succeeded && bytes_of(ops.dir.at("base2.raw")).substr(0, 8) == "OVERDATA"
        && info["backing-filename"] == ops.dir.at("base2.raw") && info["backing-filename-format"] == "raw"
        && real_head(tool, ops.dir.at("child2.qcow2"), ops.dir.at("view5.raw")) == "OVERDATA"
        && !exists(ops.dir.at("ov2.qcow2")) && ops.row(ov2).isNull() && ops.row(child2)["parent"] == base2,
        "real merge writes the overlay into its base and relinks the child");
    auto remove = ops.request(base2, "delete"); remove["delete_files"] = true;
    task = ops.run(remove);
    check(task.state == TaskState::succeeded && !exists(ops.dir.at("base2.raw")) && !exists(ops.dir.at("child2.qcow2"))
        && ops.row(base2).isNull() && ops.row(child2).isNull() && ops.operations->pending() == 0, "real subtree delete");
}
}

int main(int argc, char** argv) {
    using Test = std::pair<const char*, std::function<void()>>;
    std::vector<Test> tests{
        {"service authorization", service_access},
        {"service queue capacity and cancellation", service_queue_capacity},
        {"persistent import and repeated name", [] { persistent_import(""); }},
        {"joint import registers VM and disk", [] { joint_import(""); }},
        {"joint import rejects before decision", [] { joint_import("before_decision"); }},
        {"joint import retains decided files", [] { joint_import("participant_synced"); }},
        {"joint import recovers removed decision", [] { joint_import("decision_removed"); }},
        {"import rejects stale planning revision", [] { persistent_import("conflict"); }},
        {"import cleans pre-install failure", [] { persistent_import("before_install"); }},
        {"import retains uncertain commit files", [] { persistent_import("installed"); }},
        {"import retains unknown failure files", [] { persistent_import("unknown"); }},
        {"tar round trip", tar_round_trip}, {"tar edges", tar_edges}, {"compression round trips", compression_round_trips},
        {"compression corruption", compression_corruption}, {"header", header_contract}, {"manifest", manifest_contract},
        {"single-file packages", single_file_packages}, {"split packages", split_packages}, {"disk chain plan", chain_plan},
        {"network import plan", network_plan}, {"lease offsets", lease_offsets}, {"org.json behaviour", json_contract},
        {"file helpers", file_helpers}, {"exclusive imported files", exclusive_import_files},
        {"cleanup boundaries", cleanup_boundaries}, {"owned import directory", owned_import_directory},
        {"replaced import parent", replaced_import_parent}, {"retained import files", retained_import_files},
        {"import sync failure", import_sync_failure}, {"retained rebase", [] { retained_rebase(""); }},
        {"retained rebase rejects format", [] { retained_rebase("bad-format"); }},
        {"retained rebase resists replacement", [] { retained_rebase("replacement"); }},
        {"leased image relative backing", [] { leased_image_inspection(""); }},
        {"leased image inspection failure", [] { leased_image_inspection("failure"); }},
        {"leased image malformed metadata", [] { leased_image_inspection("malformed"); }},
        {"leased image external data rejected", [] { leased_image_inspection("external-data"); }},
        {"leased image replacement", [] { leased_image_inspection("replacement"); }},
        {"disk operation admission", disk_operation_admission}, {"disk operation journal", disk_operation_journal},
        {"disk operation create and clone", disk_operation_create}, {"disk slot reattachment", disk_slot_reattachment},
        {"disk operation merge and delete", disk_operation_tree}};
    if (argc == 3 && std::string_view(argv[1]) == "--qemu-img") {
        const std::string tool = argv[2];
        tests = {{"real qemu retained rebase", [tool] { real_retained_rebase(tool); }}};
    } else if (argc == 4 && std::string_view(argv[1]) == "--qemu-tools") {
        const std::string image_tool = argv[2], system_tool = argv[3];
        tests = {{"real QEMU retained block graph", [=] { real_qemu_disk_graph(image_tool, system_tool); }}};
    } else if (argc == 3 && std::string_view(argv[1]) == "--disk-ops") {
        const std::string tool = argv[2];
        tests = {{"real coordinated disk operations", [tool] { real_disk_operations(tool); }}};
    } else if (argc != 1) {
        std::cerr << "Usage: pkg-contract [--qemu-img /absolute/path/to/qemu-img | --qemu-tools /path/to/qemu-img /path/to/qemu-system | --disk-ops /path/to/qemu-img]\n";
        return 2;
    }
    Json::Value report;
    auto& checks = report["checks"] = Json::Value(Json::arrayValue);
    try {
        for (const auto& [name, test] : tests) {
            report["current"] = name;
            test();
            checks.append(name);
        }
        report.removeMember("current");
        report["passed"] = true;
    } catch (const std::exception& error) {
        report["passed"] = false;
        report["error"] = error.what();
    }
    std::cout << wire::stringify(report, true) << std::endl;
    return report["passed"].asBool() ? 0 : 1;
}
