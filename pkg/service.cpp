// SPDX-License-Identifier: GPL-3.0-or-later
#include "service.h"
#include "plan.h"
#include "writer.h"
#include "services/legacy_events.h"
#include "services/network_config.h"
#include "services/vm.h"
#include "store/network_config.h"
#include "store/vm_config.h"
#include "vm/boot_plan.h"
#include "vm/nic.h"
#include "build_metadata.h"
#include <algorithm>
#include <chrono>
#include <map>
#include <set>

namespace droidvm::pkg {
namespace {
using Clock = std::chrono::steady_clock;
constexpr auto progress_interval = std::chrono::milliseconds(500);
const CallContext internal{"vm-package", true, true, true};
void require_package_access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || !caller.manage_tasks || caller.principal.empty())
        throw ServiceError(ErrorCode::permission_denied, "Administrator permission required");
}

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
// BootConfig.child: the object at key, replacing anything else.
Json::Value& child(Json::Value& parent, const char* key) {
    if (!parent[key].isObject()) parent[key] = Json::Value(Json::objectValue);
    return parent[key];
}
// JSONArray.optInt(index, fallback).
int array_int(const Json::Value& value, int fallback) {
    Json::Value wrapper;
    wrapper["v"] = value;
    return opt_int(wrapper, "v", fallback);
}
void put_name(Json::Value& data, const Json::Value& vm) {
    const auto& name = config::member(vm, "name");
    if (name.isString()) data["vm_name"] = name;
}
std::string data_root(const PkgContext& context) {
    return context.data_dir.empty() ? std::string("/data/data/" DROIDVM_PACKAGE_NAME) : context.data_dir;
}
std::string optimized(const std::string& path, bool optimize) {
    constexpr std::string_view prefix = "/storage/emulated/";
    if (optimize && path.starts_with(prefix)) return "/data/media/" + path.substr(prefix.size());
    return path;
}
void check_stopping(const std::atomic<bool>& stopping) {
    if (stopping.load()) throw Error("the daemon is shutting down");
}
// VMExportUtils.scrubUnique
void scrub_unique(Json::Value& item) {
    if (item.isObject()) {
        for (const char* key : {"id", "vm_id", "uuid", "mac", "mac_address", "tap_name"}) item.removeMember(key);
        for (const auto& name : item.getMemberNames()) scrub_unique(item[name]);
    } else if (item.isArray()) {
        for (auto& element : item) scrub_unique(element);
    }
}
// VMExportUtils.sanitizeVM
Json::Value sanitize_vm(const Json::Value& vm) {
    auto copy = config::migrate_vm(vm);
    copy.removeMember("id");
    auto& nets = copy["networks"];
    if (nets.isNull()) { copy.removeMember("networks"); return copy; }
    if (!nets.isArray()) return copy;
    std::map<std::string, std::string> refs;
    int next = 0;
    for (auto& item : nets) {
        if (!item.isObject()) continue;
        const auto original = config::string(item, "network_id");
        if (!original.empty()) {
            auto found = refs.find(original);
            if (found == refs.end()) found = refs.emplace(original, "net" + std::to_string(next++)).first;
            item[network_ref_key] = found->second;
        }
        item.removeMember("network_id");
        item.removeMember("mac_address");
        item.removeMember("tap_name");
    }
    return copy;
}
// A manifest name used as one path component. Exported names always are one;
// anything that would leave the folder is reduced as safeFileName does.
std::string component(const std::string& name, const char* fallback) {
    if (name.empty() || name == "." || name == ".." || name.find('/') != std::string::npos || name.find('\0') != std::string::npos)
        return safe_file_name(name, fallback);
    return name;
}
std::string unique_file(const std::string& dir, const std::string& name) {
    const auto dot = name.rfind('.');
    const bool split = dot != std::string::npos && dot > 0;
    const auto stem = split ? name.substr(0, dot) : name;
    const auto ext = split ? name.substr(dot) : std::string();
    auto path = path_join(dir, name);
    for (int i = 1; exists(path); ++i) path = path_join(dir, stem + "_" + std::to_string(i) + ext);
    return path;
}

class ExportTask {
public:
    ExportTask(const PkgContext& context, std::shared_ptr<std::atomic<bool>> stopping, const Json::Value& request);
    const std::string& id() const { return id_; }
    TaskCompletion run(TaskControl& control);
    void cancelled(const TaskRef& ref) { id_ = ref.id; Json::Value data; data["message"] = "task cancelled"; emit(data, "error"); }
private:
    PkgContext context_;
    TaskControl* control_ = nullptr;
    uint64_t bytes_ = 0;
    std::shared_ptr<std::atomic<bool>> stopping_;
    std::string id_ = random_uuid(), vm_id_, dest_;
    int64_t volume_size_ = 0;
    bool optimize_ = true;
    Manifest manifest_;
    int total_ = 0, final_volumes_ = 0;
    const VolumeSplitSink* split_ = nullptr;
    void collect_disks(const Json::Value& vm, const std::set<int>& wanted);
    void collect_boots();
    void collect_networks(const Json::Value& source);
    void pack(TarWriter& tar);
    void write_file(TarWriter& tar, const std::string& item, const std::string& path, int done, int total);
    void emit(Json::Value data, const char* phase) const;
};
ExportTask::ExportTask(const PkgContext& context, std::shared_ptr<std::atomic<bool>> stopping, const Json::Value& request)
    : context_(context), stopping_(std::move(stopping)) {
    dest_ = opt_string(request, "dest_path");
    if (dest_.empty() || dest_.front() != '/') throw std::invalid_argument("missing dest_path");
    volume_size_ = opt_long(request, "volume_size", 0);
    // UUID.fromString then findById: both failures are plain exceptions.
    Json::Value vm;
    try { vm = context_.vms->get(internal, opt_string(request, "vm_id")); }
    catch (const ServiceError&) { throw std::invalid_argument("target vm not found"); }
    vm_id_ = config::uuid(vm);
    const auto& app = config::member(context_.vms->app_config(), "optimize_sdcard");
    optimize_ = app.isBool() ? app.asBool() : true;
    manifest_.created_at = now_ms();
    manifest_.app_version = DROIDVM_VERSION_NAME;
    manifest_.app_version_code = DROIDVM_VERSION_CODE;
    manifest_.app_build_type = DROIDVM_BUILD_TYPE;
    manifest_.vm = sanitize_vm(vm);
    manifest_.compression = compression_from_name(opt_enum(request, "compression", "ZSTD", compression_names));
    std::set<int> wanted;
    if (request.isMember("disks") && request["disks"].isArray())
        for (const auto& value : request["disks"]) wanted.insert(array_int(value, -1));
    // Walks the backing chains before the destination is touched; an Error
    // here is the RequestException text.
    collect_disks(vm, wanted);
    collect_boots();
    collect_networks(vm);
    manifest_.vm.removeMember("disks");
    manifest_.manifest_version = manifest_.resolve_version();
    total_ = static_cast<int>(manifest_.disks.size() + manifest_.boots.size());
}
void ExportTask::collect_disks(const Json::Value& vm, const std::set<int>& wanted) {
    std::vector<DiskRef> tops;
    const auto& disks = config::member(vm, "disks");
    if (disks.isArray()) for (Json::ArrayIndex i = 0; i < disks.size(); ++i) {
        const auto& item = disks[i];
        if (!item.isObject()) continue;
        if (!wanted.empty() && !wanted.contains(static_cast<int>(i))) continue;
        DiskRef ref{static_cast<int>(i), config::string(item, "path"), config::boolean(item, "readonly"),
                    config::java_enum(item, "bus", "VIRTIO", disk_buses)};
        if (ref.path.empty()) continue;
        ref.path = canonical_path(ref.path);
        tops.push_back(std::move(ref));
    }
    const Images images(path_join(data_root(context_), "usr/bin/qemu-img"), [stopping = stopping_] { return stopping->load(); });
    for (const auto& member : plan_disks(tops, [&](const std::string& path) { return images.backing_of(path); }))
        manifest_.disks.push_back(disk_entry(member));
}
void ExportTask::collect_boots() {
    const auto share = dirname(vm::edk2_firmware());
    const std::set<std::string> builtins{vm::builtin_kernel(), vm::builtin_initrd(), vm::edk2_firmware(), share + "/edk2-qemu.fd",
        "/apex/com.android.virt/etc/fs/microdroid_kernel", "/apex/com.android.virt/etc/microdroid_initrd_normal.img",
        "/apex/com.android.virt/etc/microdroid_initrd_debuggable.img"};
    std::set<std::string> seen;
    auto add = [&](const std::string& path, const char* kind) {
        if (path.empty() || builtins.contains(path) || !is_file(path)) return;
        BootFile file;
        file.path = path;
        file.kind = kind;
        file.name = file_name(path);
        file.archive_path = file.name;
        file.size = file_length(path);
        if (!seen.insert(file.archive_path).second) return;
        manifest_.boots.push_back(std::move(file));
    };
    // BootConfig.of creates the objects it reads, in the exported config too.
    auto& boot = child(manifest_.vm, "boot");
    if (config::java_enum(boot, "protocol", "UEFI", {"UEFI", "LINUX"}) == "UEFI") {
        add(config::string(child(boot, "uefi"), "firmware"), "uefi");
    } else if (config::java_enum(child(boot, "linux"), "source", "MANUAL", {"IMAGE", "MANUAL"}) == "MANUAL") {
        add(config::string(child(boot, "linux"), "kernel"), "kernel");
        add(config::string(child(boot, "linux"), "initrd"), "initrd");
    }
}
void ExportTask::collect_networks(const Json::Value& source) {
    const auto& sources = config::member(source, "networks");
    const auto& exported = config::member(manifest_.vm, "networks");
    if (!sources.isArray() || !exported.isArray()) return;
    std::set<std::string> seen;
    for (Json::ArrayIndex i = 0; i < sources.size() && i < exported.size(); ++i) {
        if (!sources[i].isObject() || !exported[i].isObject()) continue;
        const auto id = config::string(sources[i], "network_id");
        const auto ref = config::string(exported[i], network_ref_key);
        if (id.empty() || ref.empty() || !seen.insert(id).second) continue;
        Json::Value network;
        try { network = context_.networks->get(internal, id); }
        catch (const ServiceError&) {
            context_.log("WARN", "VMExportUtils: Network " + id + " is unknown here; leaving it out of the package");
            continue;
        }
        if (opt_int(network, "schema", 0) != 2) {
            context_.log("WARN", "VMExportUtils: Failed to export network " + id);
            continue;
        }
        scrub_unique(network);
        network[network_ref_key] = ref;
        manifest_.networks.push_back(std::move(network));
    }
}
TaskCompletion ExportTask::run(TaskControl& control) {
    control_ = &control;
    id_ = control.ref().id;
    Json::Value data;
    data["total"] = total_;
    try {
        // Existing exports overwrite the selected file and numbered volumes.
        // Cancellation must win before that irreversible operation starts.
        if (!control.enter_commit()) {
            cancelled(control.ref());
            return TaskCompletion::cancelled();
        }
        PackageSpec spec;
        spec.dest = dest_;
        spec.volume_size = volume_size_;
        spec.compression = manifest_.compression;
        spec.manifest_version = manifest_.manifest_version;
        spec.app_version_code = DROIDVM_VERSION_CODE;
        spec.splitting = [this](const VolumeSplitSink* volumes) { split_ = volumes; };
        final_volumes_ = write_package(spec, manifest_text(manifest_), [this](TarWriter& tar) { pack(tar); });
        data["done"] = total_;
        if (final_volumes_ > 0) { data["volume_index"] = final_volumes_; data["volume_total"] = final_volumes_; }
        emit(data, "done");
        return TaskCompletion::success(data);
    } catch (const std::exception& error) {
        context_.log("WARN", "VMExportTask: Export task " + id_ + " failed: " + error.what());
        data["done"] = 0;
        if (*error.what()) data["message"] = error.what();
        emit(data, "error");
        return TaskCompletion::failure(ErrorCode::io_error, error.what());
    }
}
void ExportTask::pack(TarWriter& tar) {
    Json::Value data;
    data["done"] = 0;
    if (!manifest_.disks.empty()) {
        const auto count = static_cast<int>(manifest_.disks.size());
        data["total"] = count;
        emit(data, "pack");
        for (int done = 0; done < count; ++done) {
            const auto& disk = manifest_.disks[static_cast<size_t>(done)];
            write_file(tar, disk.archive_path, disk.ref.path, done, count);
        }
    }
    if (!manifest_.boots.empty()) {
        const auto count = static_cast<int>(manifest_.boots.size());
        data["total"] = count;
        emit(data, "pack");
        for (int done = 0; done < count; ++done) {
            const auto& boot = manifest_.boots[static_cast<size_t>(done)];
            write_file(tar, boot.archive_path, boot.path, done, count);
        }
    }
}
void ExportTask::write_file(TarWriter& tar, const std::string& item, const std::string& path, int done, int total) {
    const auto read_path = optimized(path, optimize_);
    const auto size = file_length(read_path);
    Json::Value data;
    data["done"] = done;
    data["total"] = total;
    data["file"] = basename(path);
    data["bytes_done"] = 0;
    data["bytes_total"] = Json::Int64(size);
    emit(data, "pack");
    tar.entry(item, size, [&](Sink& out) {
        FileSource in(read_path);
        std::string buffer(buffer_size, '\0');
        int64_t written = 0;
        auto last = Clock::now();
        while (const auto count = in.read(buffer.data(), buffer.size())) {
            check_stopping(*stopping_);
            out.write(buffer.data(), count);
            bytes_ += count;
            written += static_cast<int64_t>(count);
            const auto now = Clock::now();
            if (now - last >= progress_interval) {
                data["bytes_done"] = Json::Int64(written);
                emit(data, "pack");
                last = now;
            }
        }
        data["bytes_done"] = Json::Int64(size);
        data["done"] = done + 1;
        emit(data, "pack");
    });
}
void ExportTask::emit(Json::Value data, const char* phase) const {
    if (control_) control_->progress({phase, "bytes", bytes_, {}});
    data["event"] = "vm_export_status";
    data["task_id"] = id_;
    data["phase"] = phase;
    data["vm_id"] = vm_id_;
    put_name(data, manifest_.vm);
    if (split_ && !data.isMember("volume_index")) data["volume_index"] = split_->current_index();
    try { context_.events->publish(data); } catch (const std::exception& error) {
        context_.log("WARN", "VMExportTask: Failed to emit export event for " + id_ + ": " + error.what());
    }
}

class ImportTask {
public:
    ImportTask(const PkgContext& context, std::shared_ptr<std::atomic<bool>> stopping, const Json::Value& request);
    const std::string& id() const { return id_; }
    TaskCompletion run(TaskControl& control);
    void cancelled(const TaskRef& ref) { id_ = ref.id; Json::Value data; data["message"] = "task cancelled"; emit(data, "error"); }
private:
    PkgContext context_;
    TaskControl* control_ = nullptr;
    uint64_t bytes_ = 0;
    void check_cancel() const {
        check_stopping(*stopping_);
        if (control_ && control_->cancellation_requested()) throw Error("task cancelled");
    }
    std::shared_ptr<std::atomic<bool>> stopping_;
    std::string id_ = random_uuid(), source_, target_;
    NetworkAction fallback_;
    std::vector<NetworkPlanEntry> plan_;
    std::string vm_dir_, vm_name_;
    bool registered_ = false;
    int total_ = 0, volume_total_ = 0;
    Manifest manifest_;
    Json::Value vm_;
    // Indices into manifest_: an entry placed twice is the same object, as in the Java lists.
    std::vector<size_t> disks_, boots_;
    Images images() const;
    void unpack();
    void extract(PackageInput& input);
    void on_entry(const std::string& name, int64_t size, Source& content);
    void copy(Source& in, const std::string& out, int64_t size, int done);
    void relink();
    void remap_disks();
    void remap_boots();
    Json::Value import_networks();
    void resolve_leases();
    void resolve_lease(Json::Value& nic, Family family);
    std::string unique_vm_name(const std::string& name) const;
    std::string create_vm_dir(const std::string& name) const;
    bool discard();
    void emit(Json::Value data, const char* phase) const;
};
ImportTask::ImportTask(const PkgContext& context, std::shared_ptr<std::atomic<bool>> stopping, const Json::Value& request)
    : context_(context), stopping_(std::move(stopping)) {
    source_ = opt_string(request, "src_path", "");
    if (source_.empty() || source_.front() != '/') throw std::invalid_argument("missing src_path");
    target_ = opt_string(request, "target_dir", "");
    if (target_.empty() || target_.front() != '/') throw std::invalid_argument("missing target_dir");
    target_ = java_path(target_);
    plan_ = parse_network_plan(request.isMember("network_plan") ? request["network_plan"] : Json::Value());
    // No plan: "skip" attaches nothing, anything else recreates every network.
    fallback_ = opt_string(request, "network_mode", "auto") == "skip" ? NetworkAction::skip : NetworkAction::create;
}
Images ImportTask::images() const {
    return Images(path_join(data_root(context_), "usr/bin/qemu-img"), [this] { return stopping_->load() || (control_ && control_->cancellation_requested()); });
}
TaskCompletion ImportTask::run(TaskControl& control) {
    control_ = &control;
    id_ = control.ref().id;
    Json::Value data;
    try {
        check_cancel();
        unpack();
        // Network creation and VM registration are observable shared state.
        // Finish cancellable extraction/cleanup before entering this commit.
        if (!control.enter_commit()) throw Error("task cancelled");
        auto networks = import_networks();
        resolve_leases();
        std::string id;
        try { id = context_.vms->create(internal, vm_); }
        catch (const ServiceError& error) {
            if (error.code() == ErrorCode::conflict) throw Error("failed to register VM");
            throw Error(error.what());
        }
        registered_ = true;
        data["done"] = total_;
        data["total"] = total_;
        data["vm_id"] = id;
        put_name(data, vm_);
        auto& disks = data["disks"] = Json::Value(Json::arrayValue);
        for (const auto index : disks_) disks.append(manifest_.disks[index].json());
        auto& boots = data["boots"] = Json::Value(Json::arrayValue);
        for (const auto index : boots_) boots.append(manifest_.boots[index].json());
        data["networks"] = std::move(networks);
        emit(data, "done");
        Json::Value result;
        result["vm_id"] = id;
        result["done"] = total_;
        result["total"] = total_;
        return TaskCompletion::success(std::move(result));
    } catch (const std::exception& error) {
        context_.log("WARN", "VMImportTask: Import task " + id_ + " failed: " + error.what());
        const bool cleaned = discard();
        data["done"] = 0;
        data["total"] = total_;
        if (*error.what()) data["message"] = error.what();
        emit(data, "error");
        if (!cleaned) return TaskCompletion::failure(ErrorCode::io_error, "Failed to clean up imported files");
        if (control.cancellation_requested()) return TaskCompletion::cancelled();
        return TaskCompletion::failure(ErrorCode::io_error, error.what());
    }
}
void ImportTask::unpack() {
    if (!exists(target_) && !make_dirs(target_)) throw Error("Cannot create target dir: " + target_);
    // Any picked path maps to its metadata master.
    const auto master = master_of(source_);
    int volumes;
    {
        FileSource in(master);
        char bytes[header_size];
        read_fully(in, bytes, sizeof(bytes));
        volumes = Header::parse(bytes).volume_count;
    }
    if (volumes > 0) {
        const auto set = VolumeSet::discover(master);
        volume_total_ = set.count();
        auto logical = set.open_logical();
        auto input = PackageInput::open(*logical, set.data_size());
        extract(*input);
    } else {
        FileSource in(master);
        auto input = PackageInput::open(in);
        extract(*input);
    }
    vm_ = config::migrate_vm(manifest_.vm);
    vm_["id"] = random_uuid();
    vm_["name"] = vm_name_;
    relink();
    remap_disks();
    remap_boots();
}
void ImportTask::extract(PackageInput& input) {
    manifest_ = input.manifest;
    // The name and folder are settled before any byte lands in it.
    const auto& name = config::member(manifest_.vm, "name");
    if (!name.isString()) throw Error("");
    vm_name_ = unique_vm_name(name.asString());
    vm_dir_ = create_vm_dir(vm_name_);
    total_ = static_cast<int>(manifest_.disks.size() + manifest_.boots.size());
    Json::Value data;
    data["done"] = 0;
    data["total"] = total_;
    emit(data, "pack");
    // Include ignored tar entries and trailing data in cancellation checks.
    class CheckedSource final : public Source {
    public:
        CheckedSource(Source& source, std::function<void()> check) : source_(source), check_(std::move(check)) {}
        size_t read(char* data, size_t size) override { check_(); return source_.read(data, size); }
    private:
        Source& source_;
        std::function<void()> check_;
    } checked(input.data(), [this] { check_cancel(); });
    TarReader(checked).for_each([&](const std::string& entry, int, int64_t size, Source& content) { on_entry(entry, size, content); });
    drain(checked);
    input.validate_data_consumed();
}
void ImportTask::on_entry(const std::string& name, int64_t size, Source& content) {
    check_cancel();
    if (auto* disk = manifest_.find_disk(name)) {
        const auto target = unique_file(vm_dir_, component(disk->name, "disk.img"));
        copy(content, target, size, static_cast<int>(disks_.size()));
        disk->target = target;
        disks_.push_back(static_cast<size_t>(disk - manifest_.disks.data()));
        return;
    }
    if (auto* boot = manifest_.find_boot(name)) {
        const auto dir = path_join(vm_dir_, "boot");
        if (!exists(dir) && !make_dirs(dir)) throw Error("Cannot create " + dir);
        const auto target = unique_file(dir, component(boot->name, "boot.img"));
        copy(content, target, size, static_cast<int>(disks_.size() + boots_.size()));
        boot->target = target;
        boots_.push_back(static_cast<size_t>(boot - manifest_.boots.data()));
    }
}
void ImportTask::copy(Source& in, const std::string& out, int64_t size, int done) {
    Json::Value data;
    data["done"] = done;
    data["total"] = total_;
    data["file"] = basename(out);
    data["bytes_done"] = 0;
    data["bytes_total"] = Json::Int64(size);
    emit(data, "pack");
    {
        FileSink sink(out);
        std::string buffer(buffer_size, '\0');
        int64_t remaining = size, written = 0;
        auto last = Clock::now();
        while (remaining > 0) {
            check_cancel();
            const auto count = in.read(buffer.data(), static_cast<size_t>(std::min<int64_t>(remaining, static_cast<int64_t>(buffer.size()))));
            if (!count) throw Error("entry " + file_name(out) + ": short read");
            sink.write(buffer.data(), count);
            bytes_ += count;
            remaining -= static_cast<int64_t>(count);
            written += static_cast<int64_t>(count);
            const auto now = Clock::now();
            if (now - last >= progress_interval) {
                data["bytes_done"] = Json::Int64(written);
                emit(data, "pack");
                last = now;
            }
        }
        sink.close();
    }
    data["done"] = done + 1;
    data["bytes_done"] = Json::Int64(size);
    emit(data, "pack");
}
void ImportTask::relink() {
    // The packed headers still name the exporting phone's paths.
    std::map<std::string, size_t> by_archive;
    for (const auto index : disks_) by_archive[manifest_.disks[index].archive_path] = index;
    const auto tool = images();
    for (const auto index : disks_) {
        const auto& disk = manifest_.disks[index];
        if (disk.backing_archive.empty() || !disk.target) continue;
        const auto parent = by_archive.find(disk.backing_archive);
        if (parent == by_archive.end() || !manifest_.disks[parent->second].target)
            throw Error("package is missing the backing image " + disk.backing_archive + " needed by " + disk.archive_path);
        tool.rebase(*disk.target, *manifest_.disks[parent->second].target);
    }
}
void ImportTask::remap_disks() {
    std::vector<const DiskEntry*> attached;
    for (const auto index : disks_) {
        const auto& disk = manifest_.disks[index];
        if (disk.target && disk.attached) attached.push_back(&disk);
    }
    // Stable: packages from before slot indices carry 0 everywhere.
    std::stable_sort(attached.begin(), attached.end(), [](const DiskEntry* a, const DiskEntry* b) { return a->ref.index < b->ref.index; });
    Json::Value disks(Json::arrayValue);
    for (const auto* disk : attached) {
        Json::Value item;
        item["path"] = *disk->target;
        item["readonly"] = disk->ref.readonly;
        // DataItem.set(key, Enum) stores the lowercase name.
        auto bus = disk->ref.bus;
        std::transform(bus.begin(), bus.end(), bus.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        item["bus"] = bus;
        disks.append(std::move(item));
    }
    vm_["disks"] = std::move(disks);
}
void ImportTask::remap_boots() {
    std::map<std::string, std::string> by_kind;
    for (const auto index : boots_) by_kind[manifest_.boots[index].kind] = *manifest_.boots[index].target;
    auto& boot = child(vm_, "boot");
    if (by_kind.contains("uefi")) child(boot, "uefi")["firmware"] = by_kind["uefi"];
    if (by_kind.contains("kernel")) child(boot, "linux")["kernel"] = by_kind["kernel"];
    if (by_kind.contains("initrd")) child(boot, "linux")["initrd"] = by_kind["initrd"];
}
Json::Value ImportTask::import_networks() {
    std::map<std::string, std::string> refs;
    Json::Value created(Json::arrayValue);
    NetworkImportPlan plan(context_.networks->list(internal));
    for (const auto& source : manifest_.networks) {
        const auto ref = config::string(source, network_ref_key);
        if (ref.empty()) continue;
        const auto* entry = find_ref(plan_, ref);
        const auto action = entry ? entry->action : fallback_;
        if (action == NetworkAction::skip) continue;
        if (action == NetworkAction::join) {
            std::optional<Json::Value> target;
            if (entry && entry->network_id)
                try { target = context_.networks->get(internal, *entry->network_id); } catch (const ServiceError&) {}
            if (!target) {
                context_.log("WARN", "VMImportTask: Import " + id_ + ": no network to join for " + ref);
                continue;
            }
            refs[ref] = config::uuid(*target);
            continue;
        }
        // The screen's prepared config is taken, with names settled again against the store now.
        auto config = entry && entry->config ? plan.adopt(*entry->config) : plan.prepare_create(source);
        // NetworkConfigValidator.validate normalises the config it registers.
        try { config::validate_network(config); } catch (const std::invalid_argument& error) { throw Error(error.what()); }
        std::string id;
        try { id = context_.networks->create(internal, config); }
        catch (const ServiceError& error) {
            if (error.code() == ErrorCode::conflict) continue;
            throw Error(error.what());
        }
        if (id.empty()) continue;
        refs[ref] = id;
        created.append(std::move(config));
    }
    auto& nics = vm_["networks"];
    if (nics.isNull()) vm_.removeMember("networks");
    else if (nics.isArray()) for (auto& nic : nics) {
        if (!nic.isObject()) continue;
        const auto ref = config::string(nic, network_ref_key);
        nic.removeMember(network_ref_key);
        const auto found = refs.find(ref);
        if (found == refs.end() || found->second.empty()) nic.removeMember("network_id");
        else nic["network_id"] = found->second;
    }
    return created;
}
void ImportTask::resolve_leases() {
    auto& nics = vm_["networks"];
    if (nics.isNull()) { vm_.removeMember("networks"); return; }
    if (!nics.isArray()) return;
    for (auto& nic : nics) {
        if (!nic.isObject()) continue;
        resolve_lease(nic, Family::ipv4);
        resolve_lease(nic, Family::ipv6);
    }
}
void ImportTask::resolve_lease(Json::Value& nic, Family family) {
    const bool ipv6 = family == Family::ipv6;
    auto& lease = child(nic, ipv6 ? "dhcp6_lease" : "dhcp4_lease");
    if (!config::boolean(lease, "enabled")) return;
    const auto network_id = config::string(nic, "network_id");
    std::optional<Json::Value> network;
    if (!network_id.empty()) try { network = context_.networks->get(internal, network_id); } catch (const ServiceError&) {}
    const auto* vlan = network ? vm::nic_dhcp_vlan(nic, *network) : nullptr;
    if (!vlan || !vlan_dhcp_enabled(*vlan, family)) { lease["enabled"] = false; return; }
    std::set<int64_t> used;
    for (const auto& other : context_.vms->list(internal)) add_offsets(used, other, *network, *vlan, family);
    // This VM is not registered yet; its other NICs are only in the config in hand.
    add_offsets(used, vm_, *network, *vlan, family, &nic);
    const auto& offset = config::member(lease, "offset");
    const bool has = (offset.type() == Json::intValue || offset.type() == Json::uintValue) && offset.isInt64() && offset.asInt64() > 0;
    const auto wanted = has ? config::integer(lease, "offset", first_lease_offset) : first_lease_offset;
    const auto resolved = resolve_offset(wanted, used, *vlan, family);
    if (resolved < 0) {
        context_.log("WARN", "VMImportTask: Import " + id_ + ": no free lease offset on network " + network_id);
        lease["enabled"] = false;
        return;
    }
    lease["offset"] = Json::Int64(resolved);
    // Exports strip MACs, but a kept static lease is keyed by one.
    if (config::string(nic, "mac_address").empty()) nic["mac_address"] = random_mac();
}
std::string ImportTask::unique_vm_name(const std::string& name) const {
    std::set<std::string> taken;
    for (const auto& row : context_.vms->list(internal)) {
        const auto& value = config::member(row, "name");
        if (value.isString()) taken.insert(value.asString());
    }
    if (!taken.contains(name)) return name;
    int i = 1;
    while (taken.contains(name + " (" + std::to_string(i) + ")")) ++i;
    return name + " (" + std::to_string(i) + ")";
}
std::string ImportTask::create_vm_dir(const std::string& name) const {
    const auto base = safe_file_name(name, "vm");
    auto dir = path_join(target_, base);
    for (int i = 1; exists(dir); ++i) dir = path_join(target_, base + "_" + std::to_string(i));
    if (!make_dirs(dir)) throw Error("Cannot create " + dir);
    return dir;
}
bool ImportTask::discard() {
    // Everything a failed import wrote is inside the one folder it created.
    if (vm_dir_.empty() || registered_) return true;
    try { delete_tree(vm_dir_); vm_dir_.clear(); return true; } catch (const std::exception& error) {
        context_.log("WARN", "VMImportTask: Failed to clean up " + vm_dir_ + ": " + error.what());
        return false;
    }
}
void ImportTask::emit(Json::Value data, const char* phase) const {
    if (control_) control_->progress({phase, "bytes", bytes_, {}});
    data["event"] = "vm_import_status";
    data["task_id"] = id_;
    data["phase"] = phase;
    if (volume_total_ > 0) data["volume_total"] = volume_total_;
    try { context_.events->publish(data); } catch (const std::exception& error) {
        context_.log("WARN", "VMImportTask: Failed to emit import event for " + id_ + ": " + error.what());
    }
}
}

PkgService::PkgService(PkgContext context) : context_(std::move(context)) {
    if (!context_.tasks) throw std::invalid_argument("Package task service is required");
}
PkgService::~PkgService() { shutdown(); }
TaskRef PkgService::launch(const CallContext& caller, const char* kind, TaskService::Work body, TaskService::Discarded discarded) {
    if (stopping_->load()) throw ServiceError(ErrorCode::unavailable, "the daemon is shutting down");
    struct Slot {
        std::shared_ptr<std::atomic<size_t>> active;
        bool held = false;
        ~Slot() { if (held) active->fetch_sub(1); }
    };
    auto slot = std::make_shared<Slot>();
    slot->active = active_;
    auto count = active_->load();
    do { if (count >= max_tasks) throw RequestError("too many package tasks are running"); }
    while (!active_->compare_exchange_weak(count, count + 1));
    slot->held = true;
    return context_.tasks->submit(caller, {kind, "package", 4096, true, true},
        [slot, body = std::move(body)](TaskControl& control) { return body(control); },
        [slot, discarded = std::move(discarded)](const TaskRef& ref) { discarded(ref); });
}
Json::Value PkgService::vm_export(const CallContext& caller, const Json::Value& request) {
    require_package_access(caller);
    if (!has(request, "vm_id")) throw RequestError("missing vm_id");
    if (opt_string(request, "dest_path", "").empty()) throw RequestError("missing dest_path");
    const auto volume_size = opt_long(request, "volume_size", 0);
    if (volume_size > 0 && volume_size < min_volume_size)
        throw RequestError("volume_size too small: " + std::to_string(volume_size) + " (min " + std::to_string(min_volume_size) + ")");
    std::shared_ptr<ExportTask> task;
    // A chain that cannot be walked is the whole answer for the caller.
    try { task = std::make_shared<ExportTask>(context_, stopping_, request); }
    catch (const Error& error) { throw RequestError(error.what()); }
    const auto ref = launch(caller, "vm_export", [task](TaskControl& control) { return task->run(control); },
                           [task](const TaskRef& ref) { task->cancelled(ref); });
    Json::Value result;
    result["task_id"] = ref.id;
    result["epoch"] = ref.epoch;
    return result;
}
Json::Value PkgService::vm_import(const CallContext& caller, const Json::Value& request) {
    require_package_access(caller);
    if (opt_string(request, "src_path", "").empty()) throw RequestError("missing src_path");
    if (opt_string(request, "target_dir", "").empty()) throw RequestError("missing target_dir");
    auto task = std::make_shared<ImportTask>(context_, stopping_, request);
    const auto ref = launch(caller, "vm_import", [task](TaskControl& control) { return task->run(control); },
                           [task](const TaskRef& ref) { task->cancelled(ref); });
    Json::Value result;
    result["task_id"] = ref.id;
    result["epoch"] = ref.epoch;
    return result;
}
void PkgService::shutdown() {
    stopping_->store(true);
}
}
