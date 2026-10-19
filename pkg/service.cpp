// SPDX-License-Identifier: GPL-3.0-or-later
#include "service.h"
#include "plan.h"
#include "writer.h"
#include "import_preview.h"
#include "services/legacy_events.h"
#include "services/network_config.h"
#include "services/vm.h"
#include "services/vm_config.h"
#include "services/configuration.h"
#include "store/network_config.h"
#include "store/vm_config.h"
#include "vm/boot_plan.h"
#include "vm/nic.h"
#include "build_metadata.h"
#include "common/identity.h"
#include "common/wire.h"
#include <algorithm>
#include <chrono>
#include <map>
#include <set>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>

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

std::string export_vm_id(const std::string& id) {
    Json::Value value;
    value["id"] = id;
    try {
        if (id.size() == 36 && config::uuid(value) == id) return id;
    } catch (const std::invalid_argument&) {}
    throw ServiceError(ErrorCode::invalid_argument, "Invalid VM ID");
}
Json::Value export_vm(const VmConfigService::Snapshot& snapshot, const std::string& id) {
    for (const auto& row : snapshot->document["vms"])
        if (config::uuid(row) == id) return row;
    throw ServiceError(ErrorCode::not_found, "VM not found");
}
void require_export_configuration(const PkgContext& context) {
    if (!context.configuration || !context.configuration->disks())
        throw ServiceError(ErrorCode::unavailable, "Coordinated package export is unavailable");
}
struct ExportInputs { Json::Value vm, networks, disks; };

class ExportTask {
public:
    ExportTask(const PkgContext& context, std::shared_ptr<std::atomic<bool>> stopping, const Json::Value& request,
        const ExportInputs* frozen = nullptr, TaskControl* control = nullptr);
    const std::string& id() const { return id_; }
    TaskCompletion run(TaskControl& control);
    void cancelled(const TaskRef& ref) { sources_.clear(); id_ = ref.id; Json::Value data; data["message"] = "task cancelled"; emit(data, "error"); }
private:
    PkgContext context_;
    TaskControl* control_ = nullptr;
    uint64_t bytes_ = 0;
    std::shared_ptr<std::atomic<bool>> stopping_;
    std::string id_ = random_uuid(), vm_id_, dest_;
    int64_t volume_size_ = 0;
    bool optimize_ = true;
    bool checked_ = false;
    Manifest manifest_;
    int total_ = 0, final_volumes_ = 0;
    const VolumeSplitSink* split_ = nullptr;
    std::map<std::string, std::shared_ptr<config::DiskFileLeases::Lease>> sources_;
    std::set<std::string> protected_paths_;
    std::shared_ptr<config::DiskFileLeases::Lease> retain_source(const std::string& path);
    void collect_disks(const Json::Value& vm, const std::set<int>& wanted, bool all);
    void verify_export_destinations() const;
    void collect_boots();
    void collect_networks(const Json::Value& source, const Json::Value* frozen = nullptr);
    void pack(TarWriter& tar);
    void write_file(TarWriter& tar, const std::string& item, const std::string& path, int done, int total);
    void emit(Json::Value data, const char* phase) const;
};
ExportTask::ExportTask(const PkgContext& context, std::shared_ptr<std::atomic<bool>> stopping, const Json::Value& request,
        const ExportInputs* frozen, TaskControl* control)
    : context_(context), control_(control), stopping_(std::move(stopping)) {
    checked_ = frozen != nullptr;
    dest_ = opt_string(request, "dest_path");
    if (dest_.empty() || dest_.front() != '/') throw std::invalid_argument("missing dest_path");
    volume_size_ = opt_long(request, "volume_size", 0);
    // UUID.fromString then findById: both failures are plain exceptions.
    Json::Value vm;
    try { vm = frozen ? frozen->vm : context_.vms->get(internal, opt_string(request, "vm_id")); }
    catch (const ServiceError&) { throw std::invalid_argument("target vm not found"); }
    if (frozen) {
        // An unchecked attachment is still a VM disk, not an export destination.
        // Registry ancestors are protected without inspecting unselected images.
        const auto& slots = config::member(vm, "disks");
        if (slots.isArray()) for (const auto& slot : slots) {
            const auto path = config::string(slot, "path");
            if (!path.empty()) protected_paths_.insert(canonical_path(path));
        }
        for (const auto& row : frozen->disks) {
            const auto path = config::disk_path(row);
            if (!path.empty()) protected_paths_.insert(canonical_path(path));
        }
    }
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
    collect_disks(vm, wanted, wanted.empty() && (!checked_ || !request.isMember("disks")));
    collect_boots();
    collect_networks(vm, frozen ? &frozen->networks : nullptr);
    manifest_.vm.removeMember("disks");
    manifest_.manifest_version = manifest_.resolve_version();
    total_ = static_cast<int>(manifest_.disks.size() + manifest_.boots.size());
}
std::shared_ptr<config::DiskFileLeases::Lease> ExportTask::retain_source(const std::string& path) {
    const auto pool = context_.configuration ? context_.configuration->disk_files() : nullptr;
    if (!pool) return {};
    auto found = sources_.find(path);
    if (found != sources_.end()) return found->second;
    auto lease = pool->acquire({{path, false}});
    sources_.emplace(path, lease);
    return lease;
}
void ExportTask::collect_disks(const Json::Value& vm, const std::set<int>& wanted, bool all) {
    std::vector<DiskRef> tops;
    const auto& disks = config::member(vm, "disks");
    if (disks.isArray()) for (Json::ArrayIndex i = 0; i < disks.size(); ++i) {
        const auto& item = disks[i];
        if (!item.isObject()) continue;
        if (!all && !wanted.contains(static_cast<int>(i))) continue;
        DiskRef ref{static_cast<int>(i), config::string(item, "path"), config::boolean(item, "readonly"),
                    config::java_enum(item, "bus", "VIRTIO", disk_buses)};
        if (ref.path.empty()) continue;
        ref.path = canonical_path(ref.path);
        tops.push_back(std::move(ref));
    }
    const Images images(path_join(data_root(context_), "usr/bin/qemu-img"), [stopping = stopping_, control = control_] {
        return stopping->load() || (control && control->cancellation_requested());
    });
    for (const auto& member : plan_disks(tops, [&](const std::string& path) {
        const auto lease = retain_source(path);
        return lease ? images.backing_of(*lease, path) : images.backing_of(path);
    }))
        manifest_.disks.push_back(disk_entry(member));
}
void ExportTask::verify_export_destinations() const {
    std::set<std::pair<dev_t, ino_t>> inputs;
    for (const auto& [path, lease] : sources_) {
        struct stat info{};
        if (fstat(lease->read_fd(path), &info) != 0) throw Error(errno_message("stat export source", errno));
        inputs.emplace(info.st_dev, info.st_ino);
    }
    for (const auto& path : protected_paths_) {
        struct stat info{};
        if (stat(path.c_str(), &info) == 0) inputs.emplace(info.st_dev, info.st_ino);
        else if (errno != ENOENT) throw Error(errno_message("stat protected export source", errno));
    }
    auto verify = [&](const std::string& path) {
        if (protected_paths_.contains(canonical_path(path)))
            throw ServiceError(ErrorCode::conflict, "Package destination aliases a registered disk");
        struct stat info{};
        if (stat(path.c_str(), &info) != 0) {
            if (errno == ENOENT) return;
            throw Error(errno_message("stat export destination", errno));
        }
        if (inputs.contains({info.st_dev, info.st_ino}))
            throw ServiceError(ErrorCode::conflict, "Package destination aliases an export source");
    };
    verify(dest_);
    // The writer may remove higher-numbered leftovers, so check the whole
    // bounded namespace, including existing volumes beyond the final count.
    if (volume_size_ > 0) for (int i = 1; i <= volume_max_count; ++i) verify(volume_name(dest_, i));
}
void ExportTask::collect_boots() {
    const auto share = dirname(vm::edk2_firmware());
    const std::set<std::string> builtins{vm::builtin_kernel(), vm::builtin_initrd(), vm::edk2_firmware(), share + "/edk2-qemu.fd",
        "/apex/com.android.virt/etc/fs/microdroid_kernel", "/apex/com.android.virt/etc/microdroid_initrd_normal.img",
        "/apex/com.android.virt/etc/microdroid_initrd_debuggable.img"};
    std::set<std::string> seen;
    auto add = [&](const std::string& path, const char* kind) {
        if (checked_ && !path.empty()) protected_paths_.insert(canonical_path(path));
        if (path.empty() || builtins.contains(path) || !is_file(path)) return;
        BootFile file;
        file.path = path;
        file.kind = kind;
        file.name = file_name(path);
        file.archive_path = file.name;
        file.size = file_length(path);
        if (!seen.insert(file.archive_path).second) return;
        retain_source(path);
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
void ExportTask::collect_networks(const Json::Value& source, const Json::Value* frozen) {
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
        try {
            if (frozen) {
                Json::Value identity;
                identity["id"] = id;
                std::string canonical;
                try { canonical = config::uuid(identity); }
                catch (const std::invalid_argument&) { throw ServiceError(ErrorCode::invalid_argument, "Invalid network ID"); }
                for (const auto& row : *frozen) if (config::uuid(row) == canonical) { network = row; break; }
                if (network.isNull()) throw ServiceError(ErrorCode::not_found, "Network not found");
            } else network = context_.networks->get(internal, id);
        }
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
    struct Release {
        decltype(sources_)& sources;
        ~Release() { sources.clear(); }
    } release{sources_};
    control_ = &control;
    id_ = control.ref().id;
    Json::Value data;
    data["total"] = total_;
    // Keep conflict as a domain error for checked exports. This preflight does
    // not make claims against external filesystem writers replacing paths.
    if (checked_) verify_export_destinations();
    try {
        for (const auto& [path, lease] : sources_) lease->verify();
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
        Json::Value observed(Json::arrayValue);
        if (checked_) spec.completed_file = [&](const std::string& path, int fd) {
            const auto index = path == dest_ ? 0 : std::stoi(path.substr(path.size() - 3));
            observed[static_cast<Json::ArrayIndex>(index)] = observe_package_file(fd);
        };
        final_volumes_ = write_package(spec, manifest_text(manifest_), [this](TarWriter& tar) { pack(tar); });
        data["done"] = total_;
        if (final_volumes_ > 0) { data["volume_index"] = final_volumes_; data["volume_total"] = final_volumes_; }
        emit(data, "done");
        if (checked_) {
            data["_export_manifest"]["destination"] = dest_;
            data["_export_manifest"]["files"] = std::move(observed);
            wire::stringify_bounded(data, import_plan_bytes);
        }
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
    const auto retained = sources_.find(path);
    const auto read_path = retained == sources_.end() ? optimized(path, optimize_) : path;
    Fd input;
    int64_t size;
    if (retained != sources_.end()) {
        input = retained->second->open_file(path);
        struct stat info{};
        if (fstat(input.get(), &info) != 0) throw Error(errno_message("stat export input", errno));
        size = info.st_size;
    } else size = file_length(read_path);
    Json::Value data;
    data["done"] = done;
    data["total"] = total;
    data["file"] = basename(path);
    data["bytes_done"] = 0;
    data["bytes_total"] = Json::Int64(size);
    emit(data, "pack");
    tar.entry(item, size, [&](Sink& out) {
        FileSource in(input.get() >= 0 ? FileSource(std::move(input)) : FileSource(read_path));
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
    ImportTask(const PkgContext& context, std::shared_ptr<std::atomic<bool>> stopping, const Json::Value& request,
        Json::Value confirmed = {}, CallContext caller = internal);
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
    std::unique_ptr<CreatedDirectory> owned_directory_;
    std::vector<std::unique_ptr<RetainedFile>> retained_files_;
    std::map<std::string, RetainedFile*> retained_by_path_;
    bool registered_ = false;
    bool registration_uncertain_ = false;
    Json::Value confirmed_;
    CallContext caller_;
    std::shared_ptr<const void> source_pin_;
    std::unique_ptr<ImportSource> input_;
    std::optional<NetworkConfigService::Snapshot> network_snapshot_;
    Json::Value future_networks_;
    VmConfigService::Snapshot config_snapshot_;
    DiskConfigService::Snapshot disk_snapshot_;
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
    Json::Value registered_disks() const;
    Json::Value import_networks();
    void resolve_leases();
    void resolve_lease(Json::Value& nic, Family family);
    std::string unique_vm_name(const std::string& name) const;
    std::string create_vm_dir(const std::string& name);
    bool discard();
    Json::Value receipt(bool cleaned) const;
    void emit(Json::Value data, const char* phase) const;
};
ImportTask::ImportTask(const PkgContext& context, std::shared_ptr<std::atomic<bool>> stopping, const Json::Value& request,
        Json::Value confirmed, CallContext caller)
    : context_(context), stopping_(std::move(stopping)), confirmed_(std::move(confirmed)), caller_(std::move(caller)) {
    source_ = confirmed_.isNull() ? opt_string(request, "src_path", "") : confirmed_["source_path"].asString();
    if (source_.empty() || source_.front() != '/') throw std::invalid_argument("missing src_path");
    target_ = opt_string(request, "target_dir", "");
    if (target_.empty() || target_.front() != '/') throw std::invalid_argument("missing target_dir");
    target_ = java_path(target_);
    if (confirmed_.isNull()) plan_ = parse_network_plan(request.isMember("network_plan") ? request["network_plan"] : Json::Value());
    else confirmed_["decisions"] = request["network_plan"];
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
    auto failure_code = ErrorCode::io_error;
    try {
        check_cancel();
        if (context_.import_source_pin) source_pin_ = context_.import_source_pin(caller_, source_);
        // Capture before name/lease planning. Concurrent configuration changes
        // must reject this import rather than silently rebasing its decisions.
        if (context_.vm_config) config_snapshot_ = context_.vm_config->snapshot(internal);
        if (context_.configuration) disk_snapshot_ = context_.configuration->disks()->snapshot(internal);
        if (!confirmed_.isNull()) {
            network_snapshot_ = context_.networks->snapshot(caller_);
            if (config_snapshot_->revision != confirmed_["vm_revision"].asString() ||
                    disk_snapshot_->revision != confirmed_["disk_revision"].asString() ||
                    network_snapshot_->revision != confirmed_["network_revision"].asString())
                throw ServiceError(ErrorCode::conflict, "Package import configuration changed; preview again");
            input_ = std::make_unique<ImportSource>(context_.configuration->disk_files(), source_, &confirmed_["_confirmation"]["files"]);
            if (input_->manifest().json() != confirmed_["_confirmation"]["manifest"])
                throw ServiceError(ErrorCode::conflict, "Package manifest changed; preview again");
            plan_ = checked_network_plan(input_->manifest(), confirmed_["decisions"], network_snapshot_->config);
        }
        unpack();
        owned_directory_->verify();
        // Header relinking has completed. Persist the actual retained inodes and
        // all new directory entries before publishing configuration references.
        for (const auto& file : retained_files_) { check_cancel(); file->sync(); }
        owned_directory_->sync();
        Json::Value networks;
        if (input_) {
            networks = import_networks();
            resolve_leases();
            input_->verify();
        }
        // Network creation and VM registration are observable shared state.
        // Finish cancellable extraction/cleanup before entering this commit.
        if (!control.enter_commit()) throw Error("task cancelled");
        if (!input_) { networks = import_networks(); resolve_leases(); }
        owned_directory_->verify();
        for (const auto& file : retained_files_) file->verify();
        std::string id;
        try {
            if (context_.vm_config) {
                id = config::uuid(vm_);
                if (input_) {
                    auto disk_document = registered_disks();
                    auto imported_vm = vm_;
                    auto added_networks = networks;
                    input_->verify();
                    registered_ = true;
                    registration_uncertain_ = true;
                    failure_code = ErrorCode::internal;
                    context_.configuration->import_vm_disks_networks(caller_, config_snapshot_->revision,
                        disk_snapshot_->revision, network_snapshot_->revision, std::move(imported_vm),
                        std::move(disk_document), std::move(added_networks));
                } else {
                Json::Value operations(Json::arrayValue), operation;
                operation["op"] = "create";
                operation["config"] = vm_;
                operations.append(std::move(operation));
                // Unknown failures may occur after installation. Keep files
                // unless the service explicitly proves the commit was rejected.
                registered_ = true;
                failure_code = ErrorCode::internal;
                if (context_.configuration) {
                    auto vms = config_snapshot_->document;
                    vms["vms"].append(vm_);
                    context_.configuration->replace_vm_disks(internal, config_snapshot_->revision,
                        disk_snapshot_->revision, std::move(vms), registered_disks());
                } else context_.vm_config->apply(internal, config_snapshot_->revision, operations);
                }
            } else id = context_.vms->create(internal, vm_);
        }
        catch (const ServiceError& error) {
            if (!context_.vm_config && error.code() == ErrorCode::conflict)
                throw Error("failed to register VM");
            failure_code = error.code();
            switch (error.code()) {
                case ErrorCode::conflict:
                case ErrorCode::invalid_argument:
                case ErrorCode::not_found:
                case ErrorCode::resource_exhausted:
                case ErrorCode::permission_denied:
                case ErrorCode::unauthenticated:
                case ErrorCode::io_error:
                    registered_ = false;
                    registration_uncertain_ = false;
                    break;
                case ErrorCode::unavailable:
                    // The checked coordinator rejects unavailable admission
                    // before creating a transaction decision.
                    if (input_) { registered_ = false; registration_uncertain_ = false; }
                    break;
                default: break;
            }
            throw Error(error.what());
        }
        registered_ = true;
        registration_uncertain_ = false;
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
        Json::Value result = input_ ? receipt(true) : Json::Value();
        result["vm_id"] = id;
        result["done"] = total_;
        result["total"] = total_;
        return TaskCompletion::success(std::move(result));
    } catch (const std::exception& error) {
        if (!confirmed_.isNull()) if (const auto* service = dynamic_cast<const ServiceError*>(&error)) failure_code = service->code();
        context_.log("WARN", "VMImportTask: Import task " + id_ + " failed: " + error.what());
        const bool cleaned = discard();
        data["done"] = 0;
        data["total"] = total_;
        if (*error.what()) data["message"] = error.what();
        data["error_code"] = error_code_name(failure_code);
        if (registered_) {
            data["vm_id"] = vm_["id"];
        }
        if (registered_ || !cleaned) data["retained_directory"] = vm_dir_;
        emit(data, "error");
        if (!confirmed_.isNull()) {
            auto result = receipt(cleaned);
            if (!cleaned) return TaskCompletion::failure(ErrorCode::io_error, "Imported files require cleanup", std::move(result));
            if (control.cancellation_requested() && !registered_) return TaskCompletion::cancelled(std::move(result));
            return TaskCompletion::failure(failure_code, registration_uncertain_ ? "Import registration requires recovery" : "Package import failed", std::move(result));
        }
        if (!cleaned) return TaskCompletion::failure(ErrorCode::io_error, "Failed to clean up imported files");
        if (control.cancellation_requested()) return TaskCompletion::cancelled();
        return TaskCompletion::failure(failure_code, error.what());
    }
}
void ImportTask::unpack() {
    if (!exists(target_) && !make_dirs(target_, true)) throw Error("Cannot create target dir: " + target_);
    // Any picked path maps to its metadata master.
    if (input_) {
        volume_total_ = input_->volume_count();
        auto logical = input_->open_logical();
        auto package = PackageInput::open(*logical, input_->data_size());
        extract(*package);
        input_->verify();
    } else {
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
    }
    vm_ = config::migrate_vm(manifest_.vm);
    vm_["id"] = random_uuid();
    vm_["name"] = vm_name_;
    relink();
    owned_directory_->verify();
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
    if (input_ && (disks_.size() != manifest_.disks.size() || boots_.size() != manifest_.boots.size()))
        throw ServiceError(ErrorCode::invalid_argument, "Package is missing a declared file");
}
void ImportTask::on_entry(const std::string& name, int64_t size, Source& content) {
    check_cancel();
    if (auto* disk = manifest_.find_disk(name)) {
        if (input_ && disk->target) throw ServiceError(ErrorCode::invalid_argument, "Package contains a duplicate disk");
        const auto target = unique_file(vm_dir_, component(disk->name, "disk.img"));
        copy(content, target, size, static_cast<int>(disks_.size()));
        disk->target = target;
        disks_.push_back(static_cast<size_t>(disk - manifest_.disks.data()));
        return;
    }
    if (auto* boot = manifest_.find_boot(name)) {
        if (input_ && boot->target) throw ServiceError(ErrorCode::invalid_argument, "Package contains a duplicate boot file");
        const auto dir = path_join(vm_dir_, "boot");
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
        owned_directory_->verify();
        int directory = owned_directory_->fd();
        Fd boot_directory;
        if (dirname(out) != vm_dir_) {
            if (dirname(out) != path_join(vm_dir_, "boot")) throw Error("Extraction escaped import directory");
            if (mkdirat(directory, "boot", 0700) != 0 && errno != EEXIST)
                throw Error(errno_message("create boot directory", errno));
            boot_directory = Fd(openat(directory, "boot", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
            if (boot_directory.get() < 0) throw Error(errno_message("open boot directory", errno));
            directory = boot_directory.get();
        }
        FileSink sink(directory, file_name(out));
        retained_files_.push_back(std::make_unique<RetainedFile>(sink.fd(), directory, dirname(out), file_name(out)));
        retained_by_path_[out] = retained_files_.back().get();
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
    owned_directory_->verify();
    for (const auto& file : retained_files_) file->verify();
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
        const auto& backing_path = *manifest_.disks[parent->second].target;
        const auto overlay_file = retained_by_path_.find(*disk.target);
        const auto backing_file = retained_by_path_.find(backing_path);
        if (overlay_file == retained_by_path_.end() || backing_file == retained_by_path_.end())
            throw Error("Imported image identity is missing");
        tool.rebase(*overlay_file->second, *backing_file->second);
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
Json::Value ImportTask::registered_disks() const {
    auto document = disk_snapshot_->document;
    std::map<std::string, std::string> ids;
    for (const auto index : disks_) {
        const auto& disk = manifest_.disks[index];
        if (!disk.target || !ids.emplace(disk.archive_path, random_uuid()).second)
            throw ServiceError(ErrorCode::invalid_argument, "Missing or repeated imported disk");
    }
    for (const auto index : disks_) {
        const auto& disk = manifest_.disks[index];
        Json::Value row;
        row["id"] = ids.at(disk.archive_path);
        row["name"] = basename(*disk.target);
        row["folder"] = dirname(*disk.target);
        if (!disk.backing_archive.empty()) {
            const auto parent = ids.find(disk.backing_archive);
            if (parent == ids.end()) throw ServiceError(ErrorCode::invalid_argument, "Imported backing disk is missing");
            row["parent"] = parent->second;
        }
        document["disks"].append(std::move(row));
    }
    return document;
}
Json::Value ImportTask::import_networks() {
    std::map<std::string, std::string> refs;
    Json::Value created(Json::arrayValue);
    if (input_) future_networks_ = network_snapshot_->config;
    NetworkImportPlan plan(input_ ? future_networks_ : context_.networks->list(internal));
    for (const auto& source : manifest_.networks) {
        const auto ref = config::string(source, network_ref_key);
        if (ref.empty()) continue;
        const auto* entry = find_ref(plan_, ref);
        const auto action = entry ? entry->action : fallback_;
        if (action == NetworkAction::skip) continue;
        if (action == NetworkAction::join) {
            std::optional<Json::Value> target;
            if (input_ && entry && entry->network_id) {
                for (const auto& network : future_networks_) if (config::uuid(network) == *entry->network_id) { target = network; break; }
            } else if (entry && entry->network_id)
                try { target = context_.networks->get(internal, *entry->network_id); } catch (const ServiceError&) {}
            if (!target) {
                context_.log("WARN", "VMImportTask: Import " + id_ + ": no network to join for " + ref);
                continue;
            }
            refs[ref] = config::uuid(*target);
            continue;
        }
        // The screen's prepared config is taken, with names settled again against the store now.
        auto config = input_ ? *entry->config : entry && entry->config ? plan.adopt(*entry->config) : plan.prepare_create(source);
        // NetworkConfigValidator.validate normalises the config it registers.
        try { config::validate_network(config); } catch (const std::invalid_argument& error) { throw Error(error.what()); }
        std::string id;
        try {
            if (input_) { id = config::uuid(config); future_networks_.append(config); }
            else id = context_.networks->create(internal, config);
        }
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
    if (input_) {
        for (const auto& row : future_networks_) if (config::uuid(row) == network_id) { network = row; break; }
    } else if (!network_id.empty()) try { network = context_.networks->get(internal, network_id); } catch (const ServiceError&) {}
    const auto* vlan = network ? vm::nic_dhcp_vlan(nic, *network) : nullptr;
    if (!vlan || !vlan_dhcp_enabled(*vlan, family)) { lease["enabled"] = false; return; }
    std::set<int64_t> used;
    const auto rows = config_snapshot_ ? config_snapshot_->document["vms"] : context_.vms->list(internal);
    for (const auto& other : rows) add_offsets(used, other, *network, *vlan, family);
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
    const auto rows = config_snapshot_ ? config_snapshot_->document["vms"] : context_.vms->list(internal);
    for (const auto& row : rows) {
        const auto& value = config::member(row, "name");
        if (value.isString()) taken.insert(value.asString());
    }
    if (!taken.contains(name)) return name;
    int i = 1;
    while (taken.contains(name + " (" + std::to_string(i) + ")")) ++i;
    return name + " (" + std::to_string(i) + ")";
}
std::string ImportTask::create_vm_dir(const std::string& name) {
    const auto base = safe_file_name(name, "vm");
    owned_directory_ = std::make_unique<CreatedDirectory>(target_, base);
    return owned_directory_->path();
}
bool ImportTask::discard() {
    // Everything a failed import wrote is inside the one folder it created.
    if (vm_dir_.empty() || registered_) return true;
    try {
        if (!owned_directory_) throw Error("Import directory identity is unavailable");
        for (const auto& file : retained_files_) file->verify();
        owned_directory_->remove(); vm_dir_.clear(); return true;
    } catch (const std::exception& error) {
        context_.log("WARN", "VMImportTask: Failed to clean up " + vm_dir_ + ": " + error.what());
        return false;
    }
}
Json::Value ImportTask::receipt(bool cleaned) const {
    Json::Value result;
    result["registered"] = registered_ && !registration_uncertain_;
    result["registration_uncertain"] = registration_uncertain_;
    result["recovery_required"] = registration_uncertain_;
    result["cleanup_complete"] = cleaned && !registration_uncertain_;
    result["total"] = total_;
    result["done"] = registered_ && !registration_uncertain_ ? total_ : 0;
    if (registered_) result["vm_id"] = config::string(vm_, "id");
    if ((!cleaned || registration_uncertain_) && !vm_dir_.empty()) result["retained_directory"] = vm_dir_;
    return result;
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
    if (context_.configuration) {
        if (!context_.configuration->disks() || context_.vms != &context_.configuration->inventory()
                || context_.networks != &context_.configuration->networks()
                || context_.tasks != &context_.configuration->events()
                || (context_.vm_config && context_.vm_config != &context_.configuration->vms()))
            throw std::invalid_argument("Package services must share the joint configuration owner");
        context_.vm_config = &context_.configuration->vms();
    }
}
PkgService::~PkgService() { shutdown(); }
TaskRef PkgService::launch(const CallContext& caller, const char* kind, TaskService::Work body, TaskService::Discarded discarded,
        const std::string& request_id, size_t result_bytes) {
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
    TaskSpec spec{kind, "package", result_bytes, true, true};
    if (!request_id.empty()) { spec.request_id = request_id; spec.request_signature = random_secret(); }
    return context_.tasks->submit(caller, std::move(spec),
        [slot, body = std::move(body)](TaskControl& control) { return body(control); },
        [slot, discarded = std::move(discarded)](const TaskRef& ref) { if (discarded) discarded(ref); });
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
Json::Value PkgService::export_plan(const CallContext& caller, const std::string& vm_id) {
    require_package_access(caller);
    const auto id = export_vm_id(vm_id);
    require_export_configuration(context_);
    const auto vms = context_.vm_config->snapshot(caller);
    const auto disks = context_.configuration->disks()->snapshot(caller);
    const auto networks = context_.networks->snapshot(caller);
    const auto vm = export_vm(vms, id);
    Json::Value result;
    result["vm_id"] = id;
    result["vm_name"] = config::string(vm, "name");
    result["vm_revision"] = vms->revision;
    result["disk_revision"] = disks->revision;
    result["network_revision"] = networks.revision;
    result["disks"] = Json::Value(Json::arrayValue);
    const auto& slots = config::member(vm, "disks");
    if (slots.isArray()) for (Json::ArrayIndex i = 0; i < slots.size(); ++i) {
        if (!slots[i].isObject()) continue;
        const auto path = config::string(slots[i], "path");
        if (path.empty()) continue;
        Json::Value disk;
        disk["index"] = i;
        disk["path"] = path;
        disk["readonly"] = config::boolean(slots[i], "readonly");
        result["disks"].append(std::move(disk));
    }
    return result;
}
Json::Value PkgService::vm_export_checked(const CallContext& caller, const Json::Value& request,
        const ExportConfirmation& confirmed, const std::string& request_id) {
    require_package_access(caller);
    require_export_configuration(context_);
    auto invalid = [] { throw ServiceError(ErrorCode::invalid_argument, "Invalid package export request"); };
    if (!request.isObject()) invalid();
    for (const auto& key : request.getMemberNames())
        if (key != "vm_id" && key != "dest_path" && key != "compression" && key != "volume_size" && key != "disks") invalid();
    if (!request["vm_id"].isString() || !request["dest_path"].isString()) invalid();
    const auto id = export_vm_id(request["vm_id"].asString());
    const auto dest = request["dest_path"].asString();
    if (dest.empty() || dest.size() > 4096 || dest.front() != '/' || dest.find('\0') != std::string::npos) invalid();
    if (request.isMember("compression")) {
        if (!request["compression"].isString()) invalid();
        const auto compression = request["compression"].asString();
        if (std::none_of(compression_names.begin(), compression_names.end(),
                [&](const char* name) { return compression == name; })) invalid();
    }
    if (request.isMember("volume_size")) {
        const auto& size = request["volume_size"];
        if ((size.type() != Json::intValue && size.type() != Json::uintValue) || !size.isInt64()) invalid();
        const auto value = size.asInt64();
        if (value < 0 || (value > 0 && value < min_volume_size)) invalid();
    }
    if (request.isMember("disks")) {
        const auto& disks = request["disks"];
        if (!disks.isArray() || disks.size() > 1024) invalid();
        std::set<int> indices;
        for (const auto& index : disks) {
            if ((index.type() != Json::intValue && index.type() != Json::uintValue) ||
                    !index.isInt() || index.asInt() < 0 || !indices.insert(index.asInt()).second) invalid();
        }
    }
    for (const auto* revision : {&confirmed.vm_revision, &confirmed.disk_revision, &confirmed.network_revision})
        if (revision->empty() || revision->size() > 128) invalid();
    if (request_id.empty() || request_id.size() > 128) invalid();
    // No ExportTask exists yet: accepting the task is the only operation on
    // this path. Configuration checks and all qemu/file work run in the pool.
    const auto ref = launch(caller, "vm_export",
        [context = context_, stopping = stopping_, caller, request, confirmed, id](TaskControl& control) {
            if (control.cancellation_requested()) return TaskCompletion::cancelled();
            check_stopping(*stopping);
            const auto vms = context.vm_config->snapshot(caller);
            const auto disks = context.configuration->disks()->snapshot(caller);
            const auto networks = context.networks->snapshot(caller);
            if (vms->revision != confirmed.vm_revision || disks->revision != confirmed.disk_revision ||
                    networks.revision != confirmed.network_revision)
                throw ServiceError(ErrorCode::conflict, "Package export configuration changed; reload the plan");
            const ExportInputs inputs{export_vm(vms, id), networks.config, disks->document["disks"]};
            if (request.isMember("disks")) for (const auto& index : request["disks"]) {
                const auto slot = index.asUInt();
                const auto& slots = config::member(inputs.vm, "disks");
                if (!slots.isArray() || slot >= slots.size() || !slots[slot].isObject() ||
                        config::string(slots[slot], "path").empty())
                    throw ServiceError(ErrorCode::invalid_argument, "Package export disk index is unavailable");
            }
            try {
                ExportTask task(context, stopping, request, &inputs, &control);
                return task.run(control);
            } catch (const ServiceError&) {
                if (control.cancellation_requested()) return TaskCompletion::cancelled();
                throw;
            } catch (const Error& error) {
                if (control.cancellation_requested()) return TaskCompletion::cancelled();
                return TaskCompletion::failure(ErrorCode::io_error, error.what());
            }
        }, {}, request_id, import_plan_bytes);
    Json::Value result;
    result["task_id"] = ref.id;
    result["epoch"] = ref.epoch;
    return result;
}
Json::Value PkgService::vm_import(const CallContext& caller, const Json::Value& request) {
    require_package_access(caller);
    if (opt_string(request, "src_path", "").empty()) throw RequestError("missing src_path");
    if (opt_string(request, "target_dir", "").empty()) throw RequestError("missing target_dir");
    auto task = std::make_shared<ImportTask>(context_, stopping_, request, Json::Value(), caller);
    const auto ref = launch(caller, "vm_import", [task](TaskControl& control) { return task->run(control); },
                           [task](const TaskRef& ref) { task->cancelled(ref); });
    Json::Value result;
    result["task_id"] = ref.id;
    result["epoch"] = ref.epoch;
    return result;
}
Json::Value PkgService::preview_import(const CallContext& caller, const std::string& source, const std::string& request_id) {
    require_package_access(caller);
    require_export_configuration(context_);
    if (source.empty() || source.front() != '/' || source.size() > 4096 || source.find('\0') != std::string::npos ||
            request_id.empty() || request_id.size() > 128)
        throw ServiceError(ErrorCode::invalid_argument, "Invalid package preview request");
    const auto ref = launch(caller, "package_import_plan", [context = context_, stopping = stopping_, caller, source](TaskControl& control) {
        try {
            if (control.cancellation_requested()) return TaskCompletion::cancelled();
            check_stopping(*stopping);
            const auto vms = context.vm_config->snapshot(caller);
            const auto disks = context.configuration->disks()->snapshot(caller);
            const auto networks = context.networks->snapshot(caller);
            const auto source_pin = context.import_source_pin ? context.import_source_pin(caller, source) : nullptr;
            ImportSource input(context.configuration->disk_files(), source);
            auto result = import_preview(input, networks.config);
            result["vm_revision"] = vms->revision;
            result["disk_revision"] = disks->revision;
            result["network_revision"] = networks.revision;
            input.verify();
            wire::stringify_bounded(result, import_plan_bytes);
            if (control.cancellation_requested()) return TaskCompletion::cancelled();
            return TaskCompletion::success(std::move(result));
        } catch (const ServiceError& error) {
            if (control.cancellation_requested()) return TaskCompletion::cancelled();
            return TaskCompletion::failure(error.code(), "Package preview is unavailable");
        } catch (const std::length_error&) {
            return TaskCompletion::failure(ErrorCode::resource_exhausted, "Package preview exceeds its size limit");
        } catch (const std::exception&) {
            if (control.cancellation_requested()) return TaskCompletion::cancelled();
            return TaskCompletion::failure(ErrorCode::io_error, "Package preview could not be read");
        }
    }, {}, request_id, import_plan_bytes);
    Json::Value result;
    result["task_id"] = ref.id; result["epoch"] = ref.epoch;
    return result;
}
Json::Value PkgService::vm_import_checked(const CallContext& caller, const Json::Value& request,
        const std::string& plan_request_id, const std::string& request_id) {
    require_package_access(caller);
    require_export_configuration(context_);
    auto invalid = [] { throw ServiceError(ErrorCode::invalid_argument, "Invalid package import request"); };
    if (!request.isObject() || !request["target_dir"].isString() || !request["network_plan"].isArray() ||
            request["network_plan"].size() > 1024) invalid();
    for (const auto& key : request.getMemberNames()) if (key != "target_dir" && key != "network_plan") invalid();
    const auto target = request["target_dir"].asString();
    if (target.empty() || target.front() != '/' || target.size() > 4096 || target.find('\0') != std::string::npos) invalid();
    for (const auto* id : {&plan_request_id, &request_id}) if (id->empty() || id->size() > 128) invalid();
    // Bound captures before admission. Detailed decisions are checked against
    // the retained server-side preview only after this task is accepted.
    try { wire::stringify_bounded(request, import_plan_bytes); }
    catch (const std::length_error&) { throw ServiceError(ErrorCode::resource_exhausted, "Package import request exceeds its size limit"); }
    const auto ref = launch(caller, "vm_import",
        [context = context_, stopping = stopping_, caller, request, plan_request_id](TaskControl& control) {
            Json::Value clean;
            clean["registered"] = false; clean["registration_uncertain"] = false;
            clean["recovery_required"] = false; clean["cleanup_complete"] = true;
            clean["total"] = 0; clean["done"] = 0;
            std::unique_ptr<ImportTask> task;
            try {
                if (control.cancellation_requested()) return TaskCompletion::cancelled(clean);
                const auto plan = context.tasks->find_request(caller, plan_request_id);
                if (!plan || plan->owner != caller.principal || plan->kind != "package_import_plan" ||
                        plan->resource != "package" || plan->state != TaskState::succeeded || !plan->result.isObject())
                    throw ServiceError(ErrorCode::not_found, "Package preview is missing or expired");
                task = std::make_unique<ImportTask>(context, stopping, request, plan->result, caller);
            } catch (const ServiceError& error) {
                return TaskCompletion::failure(error.code(), "Package import could not start", std::move(clean));
            } catch (const std::exception&) {
                return TaskCompletion::failure(ErrorCode::io_error, "Package import could not start", std::move(clean));
            }
            return task->run(control);
        }, {}, request_id, 8192);
    Json::Value result;
    result["task_id"] = ref.id; result["epoch"] = ref.epoch;
    return result;
}
void PkgService::shutdown() {
    stopping_->store(true);
}
}
