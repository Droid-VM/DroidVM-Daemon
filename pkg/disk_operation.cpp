// SPDX-License-Identifier: GPL-3.0-or-later
#include "disk_operation.h"
#include "io.h"
#include "plan.h"
#include "common/identity.h"
#include "common/wire.h"
#include "runtime/child.h"
#include "services/configuration.h"
#include "store/disk_config.h"
#include "store/network_config.h"
#include "build_metadata.h"
#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <map>
#include <optional>
#include <set>
#include <sys/stat.h>
#include <sys/xattr.h>

namespace droidvm::pkg {
namespace {
const CallContext internal{"disk-operation", true, true, true};
constexpr const char* journal_name = "disk_operations.json";
constexpr size_t max_records = 64;
// Simulated crash: leave files, records and registry exactly as they are.
struct Abandoned : std::runtime_error { Abandoned() : std::runtime_error("disk operation abandoned") {} };
void require_access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || !caller.manage_tasks || caller.principal.empty())
        throw ServiceError(ErrorCode::permission_denied, "Administrator permission required");
}
std::string data_root(const DiskOperationContext& context) {
    return context.data_dir.empty() ? std::string("/data/data/" DROIDVM_PACKAGE_NAME) : context.data_dir;
}
void sync_or_throw(int fd, const char* what) {
    int result;
    do { result = fsync(fd); } while (result != 0 && errno == EINTR);
    if (result != 0) throw ServiceError(ErrorCode::io_error, errno_message(what, errno));
}
std::string descriptor(int fd) { return "/proc/self/fd/" + std::to_string(fd); }
std::string row_id(const Json::Value& value) {
    Json::Value wrapper; wrapper["id"] = value;
    try { return config::uuid(wrapper); }
    catch (const std::invalid_argument&) { throw ServiceError(ErrorCode::invalid_argument, "Invalid disk ID"); }
}
std::optional<std::string> parent_id(const Json::Value& row) {
    const auto& parent = config::member(row, "parent");
    if (parent.isNull()) return std::nullopt;
    return row_id(parent);
}
struct Identity { dev_t device = 0; ino_t inode = 0; };
bool same(const struct stat& a, const struct stat& b) { return a.st_dev == b.st_dev && a.st_ino == b.st_ino; }
Fd open_directory(const std::string& path) {
    Fd directory(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (directory.get() < 0) throw ServiceError(ErrorCode::io_error, errno_message("open disk directory", errno));
    return directory;
}
// Removes only the exact journaled temporary inode, never a replacement.
bool remove_temporary(int directory, const std::string& name, const std::optional<Identity>& expected) {
    struct stat current{};
    if (fstatat(directory, name.c_str(), &current, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) return true;
        throw ServiceError(ErrorCode::io_error, errno_message("inspect disk operation temporary file", errno));
    }
    if (!S_ISREG(current.st_mode) || current.st_nlink != 1
            || (expected && (current.st_dev != expected->device || current.st_ino != expected->inode)))
        return false;
    if (unlinkat(directory, name.c_str(), 0) != 0 && errno != ENOENT)
        throw ServiceError(ErrorCode::io_error, errno_message("remove disk operation temporary file", errno));
    sync_or_throw(directory, "sync disk directory");
    return true;
}
std::optional<Identity> record_identity(const Json::Value& record) {
    if (!record["device"].isUInt64() || !record["inode"].isUInt64()) return std::nullopt;
    return Identity{static_cast<dev_t>(record["device"].asUInt64()), static_cast<ino_t>(record["inode"].asUInt64())};
}
Identity identity_of(int fd) {
    struct stat info{};
    if (fstat(fd, &info) != 0) throw ServiceError(ErrorCode::io_error, errno_message("inspect leased disk", errno));
    return {info.st_dev, info.st_ino};
}
void put_identity(Json::Value& target, const Identity& identity) {
    target["device"] = Json::UInt64(identity.device); target["inode"] = Json::UInt64(identity.inode);
}
// Unlinks only the journaled inode; another file at the name is left alone.
bool unlink_exact(const std::string& path, const std::optional<Identity>& expected) {
    if (!expected) return false;
    const auto directory = open_directory(dirname(path));
    struct stat current{};
    if (fstatat(directory.get(), file_name(path).c_str(), &current, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) return true;
        throw ServiceError(ErrorCode::io_error, errno_message("inspect disk image", errno));
    }
    if (!S_ISREG(current.st_mode) || current.st_dev != expected->device || current.st_ino != expected->inode) return false;
    if (unlinkat(directory.get(), file_name(path).c_str(), 0) != 0 && errno != ENOENT)
        throw ServiceError(ErrorCode::io_error, errno_message("remove disk image", errno));
    sync_or_throw(directory.get(), "sync disk directory");
    return true;
}
// Header-only relink (-u never opens the old backing); the image is reached
// through its retained descriptor, the stored backing name stays durable.
void rebase_header(const std::string& tool, int fd, const std::string& backing, const std::string& format) {
    ChildOptions options;
    options.argv = {tool, "rebase", "-u", "-b", backing, "-F", format, descriptor(fd)};
    options.preserve_fds = {fd};
    const auto result = Child(options).communicate({}, std::chrono::minutes(2), 1u << 20);
    if (result.exit_code != 0 || result.timed_out || result.truncated)
        throw ServiceError(ErrorCode::io_error, "qemu-img rebase failed with " + std::to_string(result.exit_code));
    sync_or_throw(fd, "sync rebased disk");
}
std::set<std::string> registered_ids(const Json::Value& disks) {
    std::set<std::string> ids;
    for (const auto& row : disks["disks"]) try { ids.insert(row_id(row["id"])); } catch (const ServiceError&) {}
    return ids;
}
// Registry and slot rewrite shared by the live operation and its recovery.
Json::Value merged_disks(Json::Value disks, const std::string& overlay, const std::string& parent) {
    Json::Value rows(Json::arrayValue);
    for (auto& row : disks["disks"]) {
        try {
            if (row_id(row["id"]) == overlay) continue;
            if (parent_id(row) == overlay) row["parent"] = parent;
        } catch (const ServiceError&) {}
        rows.append(row);
    }
    disks["disks"] = std::move(rows);
    return disks;
}
Json::Value removed_disks(Json::Value disks, const std::set<std::string>& ids) {
    Json::Value rows(Json::arrayValue);
    for (const auto& row : disks["disks"]) {
        try { if (ids.contains(row_id(row["id"]))) continue; } catch (const ServiceError&) {}
        rows.append(row);
    }
    disks["disks"] = std::move(rows);
    return disks;
}
}

class DiskOperationService::Operation {
public:
    Operation(DiskOperationService& owner, const Json::Value& request);
    ~Operation() {
        std::lock_guard lock(owner_.journal_mutex_);
        owner_.running_.erase(id_);
    }
    Operation(const Operation&) = delete;
    Operation& operator=(const Operation&) = delete;
    TaskCompletion run(TaskControl& control);
    const std::string& disk_id() const { return disk_id_; }
private:
    struct Member { std::string id, path, format; std::optional<std::string> parent; };
    DiskOperationService& owner_;
    std::string id_ = random_id(false), action_, disk_id_, target_format_, compress_ = "none";
    int64_t size_ = 0;
    bool shrink_ = false, preallocate_ = false;
    // create/clone write a new registered image instead of replacing one.
    bool fresh_ = false;
    std::string folder_, name_, new_parent_;
    // In place: operated image first. create: the backing chain. clone: the
    // source chain. Ancestors always follow their child.
    std::vector<Member> chain_;
    // commit: overlays of the merged image. delete: the removed subtree, leaves last.
    std::vector<Member> related_;
    bool delete_files_ = false;
    std::string target() const { return fresh_ ? path_join(folder_, name_) : chain_.front().path; }
    TaskCompletion merge(TaskControl& control);
    TaskCompletion remove(TaskControl& control);
    void admit_tree(const Json::Value& request, const std::string& revision);
    void load_chain(const std::map<std::string, Json::Value>& rows, const std::set<std::string>& valid, const std::string& start);
    std::vector<std::string> command(int output) const;
    void register_new();
    ConfigurationService::DiskReservation reservation_;
    std::shared_ptr<config::DiskFileLeases::Lease> lease_;
    std::string tool() const { return path_join(data_root(owner_.context_), "usr/bin/qemu-img"); }
    void fault(const char* stage) const {
        if (!owner_.context_.fault) return;
        try { owner_.context_.fault(stage); } catch (...) { throw Abandoned(); }
    }
    Json::Value graph(size_t index, int writable_fd = -1) const;
    TaskCompletion resize(TaskControl& control);
    TaskCompletion rewrite(TaskControl& control);
    void finish_flatten();
    Json::Value result() const;
};
DiskOperationService::Operation::Operation(DiskOperationService& owner, const Json::Value& request) : owner_(owner) {
    if (!request.isObject()) throw ServiceError(ErrorCode::invalid_argument, "Disk operation request must be an object");
    const auto& revision = request["disk_revision"];
    if (!revision.isString() || revision.asString().empty() || revision.asString().size() > 128)
        throw ServiceError(ErrorCode::invalid_argument, "Disk revision is required");
    action_ = request["action"].isString() ? request["action"].asString() : "";
    if (action_ != "resize" && action_ != "convert" && action_ != "flatten" && action_ != "create" && action_ != "clone"
            && action_ != "commit" && action_ != "delete")
        throw ServiceError(ErrorCode::invalid_argument, "Unsupported disk operation");
    if (action_ == "commit" || action_ == "delete") {
        admit_tree(request, revision.asString());
        return;
    }
    fresh_ = action_ == "create" || action_ == "clone";
    if (fresh_) {
        const auto& folder = request["folder"];
        const auto& name = request["name"];
        if (!folder.isString() || !name.isString()) throw ServiceError(ErrorCode::invalid_argument, "Folder and name are required");
        folder_ = folder.asString(); name_ = name.asString();
        const auto component = [](std::string_view part) { return part.empty() || part == "." || part == ".."; };
        if (folder_.empty() || folder_.front() != '/' || folder_.find('\0') != std::string::npos || folder_.size() > 4096
                || (folder_.size() > 1 && folder_.back() == '/'))
            throw ServiceError(ErrorCode::invalid_argument, "Folder must be a normalized absolute path");
        for (size_t start = 1; folder_.size() > 1 && start <= folder_.size();) {
            const auto end = std::min(folder_.find('/', start), folder_.size());
            if (component(std::string_view(folder_).substr(start, end - start)))
                throw ServiceError(ErrorCode::invalid_argument, "Folder must be a normalized absolute path");
            start = end + 1;
        }
        if (component(name_) || name_.size() > 255 || name_.find('/') != std::string::npos
                || name_.find('\0') != std::string::npos || name_.starts_with(".dvm-"))
            throw ServiceError(ErrorCode::invalid_argument, "Invalid disk file name");
    }
    if (action_ == "create") {
        if (!request["format"].isString()) throw ServiceError(ErrorCode::invalid_argument, "Format is required");
        target_format_ = request["format"].asString();
        if (target_format_ != "qcow2" && target_format_ != "raw" && target_format_ != "vhdx" && target_format_ != "vdi" && target_format_ != "vmdk")
            throw ServiceError(ErrorCode::invalid_argument, "Unsupported image format");
        if (!request["size"].isInt64() || request["size"].asInt64() <= 0)
            throw ServiceError(ErrorCode::invalid_argument, "Create requires a positive byte size");
        size_ = request["size"].asInt64();
        if (request.isMember("backing_id")) {
            if (target_format_ != "qcow2") throw ServiceError(ErrorCode::invalid_argument, "Only qcow2 images can have a backing disk");
            disk_id_ = row_id(request["backing_id"]);
        }
    } else disk_id_ = row_id(request["disk_id"]);
    if (action_ == "resize") {
        if (!request["size"].isInt64() || request["size"].asInt64() <= 0)
            throw ServiceError(ErrorCode::invalid_argument, "Resize requires a positive byte size");
        size_ = request["size"].asInt64();
        shrink_ = request["shrink"].isBool() && request["shrink"].asBool();
    } else {
        if (action_ == "clone" && request.isMember("format"))
            throw ServiceError(ErrorCode::invalid_argument, "Clone keeps the source format");
        if (action_ != "create" && request.isMember("format")) {
            if (!request["format"].isString() || (request["format"].asString() != "qcow2" && request["format"].asString() != "raw"))
                throw ServiceError(ErrorCode::invalid_argument, "Target format must be qcow2 or raw");
            target_format_ = request["format"].asString();
        }
        if (request.isMember("compress")) {
            if (!request["compress"].isString()) throw ServiceError(ErrorCode::invalid_argument, "Invalid compression");
            compress_ = request["compress"].asString();
            if (compress_ != "none" && compress_ != "deflate" && compress_ != "zstd")
                throw ServiceError(ErrorCode::invalid_argument, "Compression must be none, deflate or zstd");
        }
        preallocate_ = request["preallocate"].isBool() && request["preallocate"].asBool();
    }
    auto* configuration = owner_.context_.configuration;
    const auto snapshot = configuration->disks()->snapshot(internal);
    if (snapshot->revision != revision.asString())
        throw ServiceError(ErrorCode::conflict, "Disk configuration changed; reload before starting the operation");
    const auto valid = config::valid_disk_paths(snapshot->document);
    std::map<std::string, Json::Value> rows;
    for (const auto& row : snapshot->document["disks"]) {
        try { rows.emplace(row_id(row["id"]), row); } catch (const ServiceError&) {}
    }
    if (!disk_id_.empty()) load_chain(rows, valid, disk_id_);
    if (fresh_) {
        const auto path = target();
        for (const auto& [id, row] : rows)
            if (config::disk_path(row) == path) throw ServiceError(ErrorCode::conflict, "A registered disk already uses this path");
        struct stat existing{};
        if (lstat(path.c_str(), &existing) == 0 || errno != ENOENT)
            throw ServiceError(ErrorCode::conflict, "Target disk file already exists");
        if (action_ == "create" && !chain_.empty()) new_parent_ = chain_.front().id;
        if (action_ == "clone" && chain_.size() > 1) new_parent_ = chain_[1].id;
    } else {
        size_t children = 0;
        for (const auto& [id, row] : rows) {
            try { if (parent_id(row) == disk_id_) ++children; } catch (const ServiceError&) {}
        }
        if (action_ != "flatten" && children)
            throw ServiceError(ErrorCode::conflict, "Other disks are overlays of this disk; their content would change");
        if (action_ == "flatten" && chain_.size() < 2)
            throw ServiceError(ErrorCode::conflict, "Disk is not an overlay");
    }
    {
        std::lock_guard lock(owner_.journal_mutex_);
        for (const auto& record : owner_.records_)
            if ((!fresh_ && record["disk_id"].asString() == disk_id_) || record["path"].asString() == target())
                throw ServiceError(ErrorCode::unavailable, "An interrupted operation on this disk must be recovered first");
    }
    // A new row is reserved by its future ID; reads only share their sources.
    std::set<std::string> shared;
    for (size_t i = fresh_ ? 0 : 1; i < chain_.size(); ++i) shared.insert(chain_[i].id);
    if (fresh_) disk_id_ = random_id(true);
    reservation_ = configuration->reserve_disks(revision.asString(), {disk_id_}, shared);
    std::vector<config::DiskFileLeases::Request> files;
    for (size_t i = 0; i < chain_.size(); ++i) files.push_back({chain_[i].path, i == 0 && !fresh_});
    if (!files.empty()) lease_ = configuration->disk_files()->acquire(files);
    const auto stopping = owner_.stopping_;
    const Images images(tool(), [stopping] { return stopping->load(); }, std::chrono::seconds(10));
    for (auto& member : chain_) {
        try { member.format = images.validate_backing(*lease_, member.path, member.parent).format; }
        catch (const ServiceError&) { throw; }
        catch (const std::exception& error) { throw ServiceError(ErrorCode::conflict, error.what()); }
        if (member.format != "qcow2" && member.format != "raw")
            throw ServiceError(ErrorCode::invalid_argument, "Only qcow2 and raw images are supported");
    }
    if (target_format_.empty()) target_format_ = chain_.front().format;
    if (action_ == "clone" && chain_.size() > 1 && target_format_ != "qcow2")
        throw ServiceError(ErrorCode::conflict, "Registered overlay is not a qcow2 image");
    if (action_ == "convert" && chain_.size() > 1 && target_format_ != "qcow2")
        throw ServiceError(ErrorCode::invalid_argument, "Converting an overlay to raw would flatten it; use flatten");
    if (compress_ != "none" && target_format_ != "qcow2")
        throw ServiceError(ErrorCode::invalid_argument, "Only qcow2 images can be compressed");
}
void DiskOperationService::Operation::load_chain(const std::map<std::string, Json::Value>& rows,
        const std::set<std::string>& valid, const std::string& start) {
    std::set<std::string> seen;
    for (auto id = std::optional<std::string>(start); id;) {
        const auto found = rows.find(*id);
        if (found == rows.end()) throw ServiceError(chain_.empty() ? ErrorCode::not_found : ErrorCode::conflict,
            chain_.empty() ? "Disk not found" : "Registered parent disk is missing");
        if (!seen.insert(*id).second || seen.size() > static_cast<size_t>(max_chain))
            throw ServiceError(ErrorCode::conflict, "Disk parent chain is invalid");
        const auto path = config::disk_path(found->second);
        if (!valid.contains(path)) throw ServiceError(ErrorCode::conflict, "Disk registry entry is invalid; repair it first");
        if (!chain_.empty()) chain_.back().parent = path;
        chain_.push_back({*id, path, {}, {}});
        id = parent_id(found->second);
    }
}
void DiskOperationService::Operation::admit_tree(const Json::Value& request, const std::string& revision) {
    disk_id_ = row_id(request["disk_id"]);
    if (action_ == "delete") {
        if (request.isMember("delete_files") && !request["delete_files"].isBool())
            throw ServiceError(ErrorCode::invalid_argument, "Invalid delete_files option");
        delete_files_ = request["delete_files"].isBool() && request["delete_files"].asBool();
    }
    auto* configuration = owner_.context_.configuration;
    const auto snapshot = configuration->disks()->snapshot(internal);
    if (snapshot->revision != revision)
        throw ServiceError(ErrorCode::conflict, "Disk configuration changed; reload before starting the operation");
    const auto valid = config::valid_disk_paths(snapshot->document);
    std::map<std::string, Json::Value> rows;
    std::map<std::string, std::vector<std::string>> children;
    for (const auto& row : snapshot->document["disks"]) {
        try {
            const auto id = row_id(row["id"]);
            rows.emplace(id, row);
            if (const auto parent = parent_id(row)) children[*parent].push_back(id);
        } catch (const ServiceError&) {}
    }
    load_chain(rows, valid, disk_id_);
    std::set<std::string> exclusive{disk_id_}, shared;
    std::vector<config::DiskFileLeases::Request> files;
    if (action_ == "commit") {
        if (chain_.size() < 2) throw ServiceError(ErrorCode::conflict, "Disk is not an overlay");
        if (children[chain_[1].id] != std::vector<std::string>{disk_id_})
            throw ServiceError(ErrorCode::conflict, "The parent disk has other overlays; their content would change");
        exclusive.insert(chain_[1].id);
        for (const auto& id : children[disk_id_]) {
            const auto path = config::disk_path(rows.at(id));
            if (!valid.contains(path)) throw ServiceError(ErrorCode::conflict, "Disk registry entry is invalid; repair it first");
            related_.push_back({id, path, {}, chain_.front().path});
            exclusive.insert(id);
        }
        for (size_t i = 2; i < chain_.size(); ++i) shared.insert(chain_[i].id);
        for (size_t i = 0; i < chain_.size(); ++i) files.push_back({chain_[i].path, i < 2});
        for (const auto& child : related_) files.push_back({child.path, true});
    } else {
        // Breadth first from the deleted disk; removal runs leaves first.
        related_.push_back(chain_.front());
        for (size_t i = 0; i < related_.size(); ++i) {
            if (related_.size() > 4096) throw ServiceError(ErrorCode::conflict, "Disk subtree is too large");
            for (const auto& id : children[related_[i].id]) {
                if (!exclusive.insert(id).second) throw ServiceError(ErrorCode::conflict, "Disk parent chain is invalid");
                related_.push_back({id, config::disk_path(rows.at(id)), {}, related_[i].path});
            }
        }
        chain_.resize(1);
        if (delete_files_) {
            // Files that are already gone need no lease; Java's rm -f ignored them too.
            struct stat info{};
            for (const auto& member : related_)
                if (lstat(member.path.c_str(), &info) == 0) files.push_back({member.path, true});
                else if (errno != ENOENT) throw ServiceError(ErrorCode::io_error, errno_message("inspect disk image", errno));
        }
    }
    {
        std::lock_guard lock(owner_.journal_mutex_);
        for (const auto& record : owner_.records_)
            if (exclusive.contains(record["disk_id"].asString()))
                throw ServiceError(ErrorCode::unavailable, "An interrupted operation on this disk must be recovered first");
    }
    reservation_ = configuration->reserve_disks(revision, exclusive, shared);
    if (!files.empty()) lease_ = configuration->disk_files()->acquire(files);
    if (action_ == "delete") {
        if (!lease_) return;
        // A surviving entry aliasing a deleted inode would lose its image.
        std::set<std::pair<dev_t, ino_t>> doomed;
        for (const auto& file : files) {
            const auto identity = identity_of(lease_->read_fd(file.path));
            doomed.insert({identity.device, identity.inode});
        }
        struct stat info{};
        for (const auto& [id, row] : rows)
            if (!exclusive.contains(id) && stat(config::disk_path(row).c_str(), &info) == 0 && doomed.contains({info.st_dev, info.st_ino}))
                throw ServiceError(ErrorCode::conflict, "Another disk entry still uses an image selected for deletion");
        return;
    }
    const auto stopping = owner_.stopping_;
    const Images images(tool(), [stopping] { return stopping->load(); }, std::chrono::seconds(10));
    auto inspect = [&](Member& member) {
        try { member.format = images.validate_backing(*lease_, member.path, member.parent).format; }
        catch (const ServiceError&) { throw; }
        catch (const std::exception& error) { throw ServiceError(ErrorCode::conflict, error.what()); }
        if (member.format != "qcow2" && member.format != "raw")
            throw ServiceError(ErrorCode::invalid_argument, "Only qcow2 and raw images are supported");
    };
    for (auto& member : chain_) inspect(member);
    for (auto& child : related_) inspect(child);
    if (chain_.front().format != "qcow2") throw ServiceError(ErrorCode::conflict, "Registered overlay is not a qcow2 image");
}
std::vector<std::string> DiskOperationService::Operation::command(int output) const {
    std::string settings;
    if (preallocate_) settings = "preallocation=falloc";
    if (compress_ != "none") settings += std::string(settings.empty() ? "" : ",") + "compression_type=" + (compress_ == "zstd" ? "zstd" : "zlib");
    std::vector<std::string> argv{tool()};
    if (action_ == "create") {
        // The header stores the durable backing path; qemu-img checks it by
        // that path while the read lease pins the admitted inode.
        argv.insert(argv.end(), {"create", "-f", target_format_});
        if (!chain_.empty()) argv.insert(argv.end(), {"-b", chain_.front().path, "-F", chain_.front().format});
        if (!settings.empty()) argv.insert(argv.end(), {"-o", settings});
        argv.insert(argv.end(), {descriptor(output), std::to_string(size_)});
        return argv;
    }
    argv.insert(argv.end(), {"convert", "-O", target_format_});
    // convert reads the whole chain; keep an overlay's own layer over its parent.
    if (action_ != "flatten" && chain_.size() > 1) argv.insert(argv.end(), {"-B", chain_[1].path, "-F", chain_[1].format});
    if (!settings.empty()) argv.insert(argv.end(), {"-o", settings});
    if (compress_ != "none") argv.push_back("-c");
    argv.insert(argv.end(), {"json:" + wire::stringify(graph(0)), descriptor(output)});
    return argv;
}
// Explicit node tree: qcow2 nodes never resolve header names relative to the
// /proc descriptor path, and the operated image never follows a backing link
// unless the graph names its retained parent.
Json::Value DiskOperationService::Operation::graph(size_t index, int writable_fd) const {
    const auto& member = chain_[index];
    Json::Value node;
    node["driver"] = member.format;
    node["file"]["driver"] = "file";
    node["file"]["filename"] = descriptor(writable_fd >= 0 ? writable_fd : lease_->read_fd(member.path));
    if (member.format == "qcow2")
        node["backing"] = writable_fd < 0 && index + 1 < chain_.size() ? graph(index + 1) : Json::Value();
    return node;
}
TaskCompletion DiskOperationService::Operation::run(TaskControl& control) {
    try {
        if (owner_.stopping_->load()) throw ServiceError(ErrorCode::unavailable, "the daemon is shutting down");
        if (lease_) lease_->verify();
        if (action_ == "commit") return merge(control);
        if (action_ == "delete") return remove(control);
        return action_ == "resize" ? resize(control) : rewrite(control);
    } catch (const Abandoned& error) {
        return TaskCompletion::failure(ErrorCode::internal, error.what());
    } catch (const ServiceError& error) {
        owner_.context_.log("WARN", "DiskOperation: " + action_ + " " + disk_id_ + " failed: " + error.what());
        return TaskCompletion::failure(error.code(), error.what());
    } catch (const std::exception& error) {
        owner_.context_.log("WARN", "DiskOperation: " + action_ + " " + disk_id_ + " failed: " + error.what());
        return TaskCompletion::failure(ErrorCode::io_error, error.what());
    }
}
TaskCompletion DiskOperationService::Operation::resize(TaskControl& control) {
    // qemu-img resize rewrites metadata in place; interrupting it is unsafe.
    if (!control.enter_commit()) return TaskCompletion::cancelled();
    control.progress({"resize", "", 0, {}});
    const auto io = lease_->open_file(chain_.front().path, true);
    ChildOptions options;
    options.argv = {tool(), "resize"};
    if (shrink_) options.argv.push_back("--shrink");
    options.argv.push_back("json:" + wire::stringify(graph(0, io.get())));
    options.argv.push_back(std::to_string(size_));
    options.preserve_fds = {io.get()};
    const auto output = Child(options).communicate({}, std::chrono::minutes(30), 1u << 20);
    lease_->verify();
    if (output.exit_code != 0 || output.timed_out || output.truncated)
        throw ServiceError(ErrorCode::io_error, "qemu-img resize failed with " + std::to_string(output.exit_code));
    sync_or_throw(io.get(), "sync resized disk");
    return TaskCompletion::success(result());
}
TaskCompletion DiskOperationService::Operation::rewrite(TaskControl& control) {
    const auto path = target();
    const auto name = file_name(path);
    const auto directory_path = dirname(path);
    const auto directory = open_directory(directory_path);
    struct stat source{};
    if (fresh_) {
        // New images belong to the folder owner, like files the app creates there.
        if (fstat(directory.get(), &source) != 0) throw ServiceError(ErrorCode::io_error, errno_message("inspect disk folder", errno));
        source.st_mode = 0644;
    } else {
        struct stat entry{};
        if (fstat(lease_->read_fd(path), &source) != 0 || fstatat(directory.get(), name.c_str(), &entry, AT_SYMLINK_NOFOLLOW) != 0
                || !same(source, entry))
            throw ServiceError(ErrorCode::conflict, "Disk file changed after lease admission");
    }
    const auto temporary = ".dvm-" + id_ + ".tmp";
    Json::Value record;
    record["id"] = id_; record["action"] = action_; record["disk_id"] = disk_id_;
    record["path"] = path; record["directory"] = directory_path; record["temporary"] = temporary;
    record["phase"] = "prepared";
    if (fresh_) record["fresh"] = true;
    if (!fresh_ && chain_.size() > 1) record["parent_id"] = chain_[1].id;
    // Journal the name before the file exists, so any crash leaves a findable owner.
    owner_.put_record(record);
    std::optional<Identity> created;
    auto discard = [&] {
        try {
            if (remove_temporary(directory.get(), temporary, created)) owner_.drop_record(id_);
            else owner_.context_.log("WARN", "DiskOperation: temporary " + temporary + " changed; kept for recovery");
        } catch (const std::exception& error) {
            owner_.context_.log("WARN", "DiskOperation: failed to discard " + temporary + ": " + error.what());
        }
    };
    try {
        Fd output(openat(directory.get(), temporary.c_str(), O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
        if (output.get() < 0) throw ServiceError(ErrorCode::io_error, errno_message("create disk operation temporary file", errno));
        struct stat made{};
        if (fstat(output.get(), &made) != 0) throw ServiceError(ErrorCode::io_error, errno_message("inspect temporary file", errno));
        created = Identity{made.st_dev, made.st_ino};
        record["device"] = Json::UInt64(made.st_dev); record["inode"] = Json::UInt64(made.st_ino);
        owner_.put_record(record);
        // Keep the replacement accessible exactly like the original image.
        if (fchown(output.get(), source.st_uid, source.st_gid) != 0 || fchmod(output.get(), source.st_mode & 07777) != 0)
            throw ServiceError(ErrorCode::io_error, errno_message("copy disk ownership", errno));
        if (!fresh_) {
            char label[256];
            const auto length = fgetxattr(lease_->read_fd(path), "security.selinux", label, sizeof(label));
            if (length > 0 && fsetxattr(output.get(), "security.selinux", label, static_cast<size_t>(length), 0) != 0)
                owner_.context_.log("WARN", "DiskOperation: could not copy SELinux label: " + errno_message("fsetxattr", errno));
        }
        fault("prepared");
        control.progress({action_, "", 0, {}});
        ChildOptions options;
        options.argv = command(output.get());
        options.preserve_fds = {output.get()};
        for (const auto& member : chain_) options.preserve_fds.push_back(lease_->read_fd(member.path));
        const auto stopping = owner_.stopping_;
        const auto converted = Child(options).communicate({}, std::chrono::hours(24), 1u << 20,
            [&control, stopping] { return control.cancellation_requested() || stopping->load(); });
        if (converted.cancelled) { discard(); return TaskCompletion::cancelled(); }
        if (converted.exit_code != 0 || converted.timed_out || converted.truncated)
            throw ServiceError(ErrorCode::io_error, "qemu-img " + action_ + " failed with " + std::to_string(converted.exit_code));
        sync_or_throw(output.get(), "sync written disk");
        fault("converted");
        struct stat current{};
        if (fstatat(directory.get(), temporary.c_str(), &current, AT_SYMLINK_NOFOLLOW) != 0 || !same(current, made))
            throw ServiceError(ErrorCode::conflict, "Disk operation temporary file was replaced");
        if (lease_) lease_->verify();
        if (!control.enter_commit()) { discard(); return TaskCompletion::cancelled(); }
        record["phase"] = "replacing";
        owner_.put_record(record);
        if (fresh_) {
            // Never replace a file that appeared at the target meanwhile.
            if (linkat(directory.get(), temporary.c_str(), directory.get(), name.c_str(), 0) != 0) {
                const int error = errno;
                throw ServiceError(error == EEXIST ? ErrorCode::conflict : ErrorCode::io_error, errno_message("install new disk image", error));
            }
        }
    } catch (const Abandoned&) {
        throw;
    } catch (...) {
        discard();
        throw;
    }
    // Past this point the only safe direction is forward: the journal decides.
    if (fresh_) {
        if (unlinkat(directory.get(), temporary.c_str(), 0) != 0)
            throw ServiceError(ErrorCode::io_error, errno_message("remove installed disk temporary name", errno));
    } else if (renameat(directory.get(), temporary.c_str(), directory.get(), name.c_str()) != 0)
        throw ServiceError(ErrorCode::io_error, errno_message("replace disk image", errno));
    sync_or_throw(directory.get(), "sync disk directory");
    fault("replaced");
    if (fresh_ || action_ == "flatten") {
        try { fresh_ ? register_new() : finish_flatten(); }
        catch (const ServiceError& error) {
            owner_.context_.log("WARN", "DiskOperation: registry update deferred: " + std::string(error.what()));
            // A definite rejection leaves the new file unregistered: roll it back.
            if (fresh_ && error.code() != ErrorCode::commit_uncertain && error.code() != ErrorCode::internal
                    && error.code() != ErrorCode::unavailable) {
                try { if (owner_.replay_one(record)) owner_.drop_record(id_); }
                catch (const std::exception& cleanup) {
                    owner_.context_.log("WARN", "DiskOperation: rollback deferred: " + std::string(cleanup.what()));
                }
                return TaskCompletion::failure(error.code(), error.what());
            }
            return TaskCompletion::failure(ErrorCode::commit_uncertain,
                "Image was written but the disk registry update is uncertain; recover disk operations");
        }
    }
    owner_.drop_record(id_);
    return TaskCompletion::success(result());
}
// qemu-img commit writes the overlay's clusters into its parent in place. The
// overlay keeps them (-d), so its view stays exact if this is interrupted;
// once the copy completes the journal only ever moves forward.
TaskCompletion DiskOperationService::Operation::merge(TaskControl& control) {
    if (!control.enter_commit()) return TaskCompletion::cancelled();
    const auto& overlay = chain_[0];
    const auto& parent = chain_[1];
    Json::Value record;
    record["id"] = id_; record["action"] = action_; record["disk_id"] = disk_id_; record["path"] = overlay.path;
    record["parent_id"] = parent.id; record["parent_path"] = parent.path; record["parent_format"] = parent.format;
    put_identity(record, identity_of(lease_->read_fd(overlay.path)));
    auto& children = record["children"] = Json::Value(Json::arrayValue);
    for (const auto& child : related_) {
        Json::Value item; item["id"] = child.id; item["path"] = child.path;
        children.append(std::move(item));
    }
    record["phase"] = "committing";
    owner_.put_record(record);
    try {
        control.progress({"commit", "", 0, {}});
        const auto top = lease_->open_file(overlay.path, true), base = lease_->open_file(parent.path, true);
        auto node = graph(0);
        node["file"]["filename"] = descriptor(top.get());
        node["backing"]["file"]["filename"] = descriptor(base.get());
        ChildOptions options;
        options.argv = {tool(), "commit", "-d", "json:" + wire::stringify(node)};
        options.preserve_fds = {top.get(), base.get()};
        for (size_t i = 2; i < chain_.size(); ++i) options.preserve_fds.push_back(lease_->read_fd(chain_[i].path));
        const auto result = Child(options).communicate({}, std::chrono::hours(24), 1u << 20);
        if (result.exit_code != 0 || result.timed_out || result.truncated)
            throw ServiceError(ErrorCode::io_error, "qemu-img commit failed with " + std::to_string(result.exit_code));
        sync_or_throw(base.get(), "sync merged parent disk");
        lease_->verify();
        fault("committed");
    } catch (const Abandoned&) {
        throw;
    } catch (...) {
        // Registry and children are untouched; the overlay still shows its full view.
        owner_.drop_record(id_);
        throw;
    }
    record["phase"] = "rebasing";
    owner_.put_record(record);
    control.progress({"relink", "", 0, {}});
    for (const auto& child : related_) {
        const auto io = lease_->open_file(child.path, true);
        rebase_header(tool(), io.get(), parent.path, parent.format);
    }
    fault("rebased");
    record["phase"] = "registering";
    owner_.put_record(record);
    auto& configuration = *owner_.context_.configuration;
    const auto vms = configuration.vms().snapshot(internal);
    const auto disks = configuration.disks()->snapshot(internal);
    auto merged = merged_disks(disks->document, disk_id_, parent.id);
    configuration.replace_vm_disks(internal, vms->revision, disks->revision,
        config::reattach_disk_slots(vms->document, disks->document, merged), std::move(merged), reservation_);
    fault("registered");
    record["phase"] = "unlinking";
    owner_.put_record(record);
    if (!unlink_exact(overlay.path, record_identity(record)))
        owner_.context_.log("WARN", "DiskOperation: merged overlay " + overlay.path + " changed; left in place");
    owner_.drop_record(id_);
    return TaskCompletion::success(result());
}
// Registry first (slots move to the nearest surviving base or are removed),
// then the image files, leaves first, each only if still the admitted inode.
TaskCompletion DiskOperationService::Operation::remove(TaskControl& control) {
    if (!control.enter_commit()) return TaskCompletion::cancelled();
    Json::Value record;
    record["id"] = id_; record["action"] = action_; record["disk_id"] = disk_id_; record["path"] = chain_.front().path;
    record["delete_files"] = delete_files_;
    auto& members = record["subtree"] = Json::Value(Json::arrayValue);
    std::set<std::string> ids;
    for (const auto& member : related_) {
        Json::Value item; item["id"] = member.id; item["path"] = member.path;
        struct stat info{};
        if (lease_ && lstat(member.path.c_str(), &info) == 0) put_identity(item, identity_of(lease_->read_fd(member.path)));
        members.append(std::move(item));
        ids.insert(member.id);
    }
    record["phase"] = "registering";
    owner_.put_record(record);
    auto& configuration = *owner_.context_.configuration;
    const auto vms = configuration.vms().snapshot(internal);
    const auto disks = configuration.disks()->snapshot(internal);
    auto removed = removed_disks(disks->document, ids);
    try {
        configuration.replace_vm_disks(internal, vms->revision, disks->revision,
            config::reattach_disk_slots(vms->document, disks->document, removed), std::move(removed), reservation_);
    } catch (const ServiceError& error) {
        if (error.code() == ErrorCode::commit_uncertain || error.code() == ErrorCode::internal) throw;
        owner_.drop_record(id_); // Definitely rejected: nothing changed.
        throw;
    }
    fault("registered");
    if (delete_files_) {
        record["phase"] = "unlinking";
        owner_.put_record(record);
        for (auto index = members.size(); index-- > 0;) {
            const auto& member = members[index];
            if (record_identity(member) && !unlink_exact(member["path"].asString(), record_identity(member)))
                owner_.context_.log("WARN", "DiskOperation: deleted disk file " + member["path"].asString() + " changed; left in place");
        }
    }
    owner_.drop_record(id_);
    return TaskCompletion::success(result());
}
void DiskOperationService::Operation::register_new() {
    auto& configuration = *owner_.context_.configuration;
    const auto vms = configuration.vms().snapshot(internal);
    const auto disks = configuration.disks()->snapshot(internal);
    auto document = disks->document;
    const auto path = target();
    for (const auto& row : document["disks"])
        if (config::disk_path(row) == path) throw ServiceError(ErrorCode::conflict, "A registered disk already uses this path");
    Json::Value row;
    row["id"] = disk_id_; row["name"] = name_; row["folder"] = folder_;
    if (!new_parent_.empty()) row["parent"] = new_parent_;
    document["disks"].append(std::move(row));
    configuration.replace_vm_disks(internal, vms->revision, disks->revision, vms->document, std::move(document), reservation_);
}
void DiskOperationService::Operation::finish_flatten() {
    auto& configuration = *owner_.context_.configuration;
    const auto vms = configuration.vms().snapshot(internal);
    const auto disks = configuration.disks()->snapshot(internal);
    auto document = disks->document;
    for (auto& row : document["disks"]) {
        if (!row.isObject() || row_id(row["id"]) != disk_id_) continue;
        if (config::disk_path(row) != chain_.front().path || parent_id(row) != chain_[1].id)
            throw ServiceError(ErrorCode::conflict, "Flattened disk registry entry changed");
        row.removeMember("parent");
        configuration.replace_vm_disks(internal, vms->revision, disks->revision, vms->document, std::move(document), reservation_);
        return;
    }
    throw ServiceError(ErrorCode::conflict, "Flattened disk registry entry disappeared");
}
Json::Value DiskOperationService::Operation::result() const {
    Json::Value value;
    value["disk_id"] = disk_id_;
    value["action"] = action_;
    value["path"] = target();
    value["format"] = action_ == "resize" ? chain_.front().format : target_format_;
    return value;
}

DiskOperationService::DiskOperationService(DiskOperationContext context) : context_(std::move(context)) {
    if (!context_.configuration || !context_.configuration->disks() || !context_.configuration->disk_files())
        throw std::invalid_argument("Disk operations require coordinated disk configuration");
    journal_ = std::make_unique<config::JsonFile>(context_.directory, journal_name, context_.owner, context_.observer,
        config::JsonFile::max_bytes, config::JsonSyntax::strict);
    if (const auto loaded = journal_->load()) {
        const auto& operations = loaded->value["operations"];
        if (!loaded->value.isObject() || !operations.isArray())
            throw std::runtime_error("Disk operation journal is malformed");
        records_ = operations;
    }
    replay();
}
DiskOperationService::~DiskOperationService() { shutdown(); }
void DiskOperationService::put_record(const Json::Value& record) {
    std::lock_guard lock(journal_mutex_);
    auto next = Json::Value(Json::arrayValue);
    bool replaced = false;
    for (const auto& existing : records_) {
        if (existing["id"] == record["id"]) { next.append(record); replaced = true; }
        else next.append(existing);
    }
    if (!replaced) {
        if (records_.size() >= max_records) throw ServiceError(ErrorCode::resource_exhausted, "Too many unrecovered disk operations");
        next.append(record);
    }
    Json::Value document;
    document["operations"] = next;
    try { journal_->save(document); }
    catch (const config::CommitError& error) {
        if (!error.installed) throw ServiceError(ErrorCode::io_error, error.what());
    }
    records_ = std::move(next);
    running_.insert(record["id"].asString());
}
void DiskOperationService::drop_record(const std::string& id) {
    std::lock_guard lock(journal_mutex_);
    auto next = Json::Value(Json::arrayValue);
    for (const auto& existing : records_) if (existing["id"].asString() != id) next.append(existing);
    Json::Value document;
    document["operations"] = next;
    try { journal_->save(document); }
    catch (const config::CommitError& error) {
        // A stale record only causes a harmless, idempotent replay.
        if (!error.installed) { context_.log("WARN", "DiskOperation: journal cleanup deferred: " + std::string(error.what())); return; }
    } catch (const std::exception& error) {
        context_.log("WARN", "DiskOperation: journal cleanup deferred: " + std::string(error.what()));
        return;
    }
    records_ = std::move(next);
}
bool DiskOperationService::replay_merge(const Json::Value& record) {
    const auto phase = record["phase"].asString();
    if (phase == "committing") {
        // Nothing was relinked: the overlay still shows its complete view.
        context_.log("WARN", "DiskOperation: merge of " + record["path"].asString() + " was interrupted; overlay kept");
        return true;
    }
    auto& configuration = *context_.configuration;
    const auto overlay = record["disk_id"].asString(), parent = record["parent_id"].asString();
    const auto parent_path = record["parent_path"].asString(), parent_format = record["parent_format"].asString();
    if (overlay.empty() || parent.empty() || parent_path.empty() || (parent_format != "qcow2" && parent_format != "raw"))
        throw std::runtime_error("Malformed disk merge record");
    std::set<std::string> exclusive{overlay, parent};
    for (const auto& child : record["children"]) exclusive.insert(child["id"].asString());
    if (phase == "rebasing") {
        std::vector<config::DiskFileLeases::Request> files;
        for (const auto& child : record["children"]) files.push_back({child["path"].asString(), true});
        if (!files.empty()) {
            const auto lease = configuration.disk_files()->acquire(files);
            const auto tool = path_join(data_root(context_), "usr/bin/qemu-img");
            for (const auto& file : files) {
                const auto io = lease->open_file(file.path, true);
                rebase_header(tool, io.get(), parent_path, parent_format);
            }
        }
    }
    if (phase == "rebasing" || phase == "registering") {
        const auto disks = configuration.disks()->snapshot(internal);
        if (registered_ids(disks->document).contains(overlay)) {
            const auto reservation = configuration.reserve_disks(disks->revision, exclusive, {});
            const auto vms = configuration.vms().snapshot(internal);
            auto merged = merged_disks(disks->document, overlay, parent);
            configuration.replace_vm_disks(internal, vms->revision, disks->revision,
                config::reattach_disk_slots(vms->document, disks->document, merged), std::move(merged), reservation);
        }
    }
    for (const auto& row : configuration.disks()->snapshot(internal)->document["disks"])
        if (config::disk_path(row) == record["path"].asString()) return true;
    if (!unlink_exact(record["path"].asString(), record_identity(record)))
        context_.log("WARN", "DiskOperation: merged overlay " + record["path"].asString() + " changed; left in place");
    return true;
}
bool DiskOperationService::replay_delete(const Json::Value& record) {
    auto& configuration = *context_.configuration;
    std::set<std::string> ids;
    for (const auto& member : record["subtree"]) ids.insert(member["id"].asString());
    if (ids.empty()) throw std::runtime_error("Malformed disk delete record");
    if (record["phase"].asString() == "registering") {
        const auto disks = configuration.disks()->snapshot(internal);
        const auto present = registered_ids(disks->document);
        if (std::any_of(ids.begin(), ids.end(), [&](const std::string& id) { return present.contains(id); })) {
            const auto reservation = configuration.reserve_disks(disks->revision, ids, {});
            const auto vms = configuration.vms().snapshot(internal);
            auto removed = removed_disks(disks->document, ids);
            configuration.replace_vm_disks(internal, vms->revision, disks->revision,
                config::reattach_disk_slots(vms->document, disks->document, removed), std::move(removed), reservation);
        }
    }
    if (!record["delete_files"].asBool()) return true;
    std::set<std::string> registered;
    for (const auto& row : configuration.disks()->snapshot(internal)->document["disks"]) registered.insert(config::disk_path(row));
    const auto& members = record["subtree"];
    for (auto index = members.size(); index-- > 0;) {
        const auto& member = members[index];
        const auto path = member["path"].asString();
        if (!record_identity(member) || registered.contains(path)) continue;
        if (!unlink_exact(path, record_identity(member)))
            context_.log("WARN", "DiskOperation: deleted disk file " + path + " changed; left in place");
    }
    return true;
}
bool DiskOperationService::replay_one(const Json::Value& record) {
    if (record["action"].asString() == "commit") return replay_merge(record);
    if (record["action"].asString() == "delete") return replay_delete(record);
    const auto directory = open_directory(record["directory"].asString());
    const auto temporary = record["temporary"].asString();
    if (temporary.empty() || temporary.find('/') != std::string::npos) throw std::runtime_error("Malformed disk operation record");
    const auto identity = record_identity(record);
    struct stat current{};
    const bool temporary_present = fstatat(directory.get(), temporary.c_str(), &current, AT_SYMLINK_NOFOLLOW) == 0;
    if (record["fresh"].asBool()) return replay_new(directory.get(), record);
    if (record["phase"].asString() == "prepared" || temporary_present) {
        // The image was never replaced; only the partial copy remains.
        if (!remove_temporary(directory.get(), temporary, identity))
            throw std::runtime_error("Disk operation temporary file changed; inspect " + temporary);
        return true;
    }
    if (record["action"].asString() != "flatten") return true;
    struct stat image{};
    if (!identity || stat(record["path"].asString().c_str(), &image) != 0
            || image.st_dev != identity->device || image.st_ino != identity->inode) {
        context_.log("WARN", "DiskOperation: flattened image " + record["path"].asString() + " was replaced; registry left unchanged");
        return true;
    }
    auto& configuration = *context_.configuration;
    const auto disk_id = record["disk_id"].asString();
    const auto disks = configuration.disks()->snapshot(internal);
    auto document = disks->document;
    for (auto& row : document["disks"]) {
        if (!row.isObject()) continue;
        try { if (row_id(row["id"]) != disk_id) continue; } catch (const ServiceError&) { continue; }
        if (config::disk_path(row) != record["path"].asString() || config::member(row, "parent").isNull()) return true;
        if (!record["parent_id"].isString() || parent_id(row) != record["parent_id"].asString()) return true;
        row.removeMember("parent");
        const auto reservation = configuration.reserve_disks(disks->revision, {disk_id}, {});
        const auto vms = configuration.vms().snapshot(internal);
        configuration.replace_vm_disks(internal, vms->revision, disks->revision, vms->document, std::move(document), reservation);
        return true;
    }
    return true;
}
// A new image counts only once registered; otherwise the exact installed
// inode is rolled back. Foreign files at either name are never removed.
bool DiskOperationService::replay_new(int directory, const Json::Value& record) {
    const auto identity = record_identity(record);
    const auto temporary = record["temporary"].asString();
    const auto path = record["path"].asString();
    const auto name = file_name(path);
    if (dirname(path) != record["directory"].asString() || name.empty() || name.find('/') != std::string::npos)
        throw std::runtime_error("Malformed disk operation record");
    struct stat final_entry{}, temporary_entry{};
    const auto matches = [&](const struct stat& entry) {
        return identity && S_ISREG(entry.st_mode) && entry.st_dev == identity->device && entry.st_ino == identity->inode;
    };
    const bool installed = fstatat(directory, name.c_str(), &final_entry, AT_SYMLINK_NOFOLLOW) == 0 && matches(final_entry);
    if (!installed) {
        if (!remove_temporary(directory, temporary, identity))
            throw std::runtime_error("Disk operation temporary file changed; inspect " + temporary);
        return true;
    }
    if (fstatat(directory, temporary.c_str(), &temporary_entry, AT_SYMLINK_NOFOLLOW) == 0 && matches(temporary_entry)) {
        if (unlinkat(directory, temporary.c_str(), 0) != 0 && errno != ENOENT)
            throw ServiceError(ErrorCode::io_error, errno_message("remove installed disk temporary name", errno));
        sync_or_throw(directory, "sync disk directory");
    }
    for (const auto& row : context_.configuration->disks()->snapshot(internal)->document["disks"])
        if (config::disk_path(row) == path) return true;
    if (!remove_temporary(directory, name, identity))
        throw std::runtime_error("Unregistered new disk changed; inspect " + path);
    return true;
}
void DiskOperationService::replay() {
    Json::Value records;
    std::set<std::string> running;
    { std::lock_guard lock(journal_mutex_); records = records_; running = running_; }
    for (const auto& record : records) {
        if (running.contains(record["id"].asString())) continue;
        try { if (replay_one(record)) drop_record(record["id"].asString()); }
        catch (const std::exception& error) {
            context_.log("WARN", "DiskOperation: recovery of " + record["id"].asString() + " deferred: " + error.what());
        }
    }
}
size_t DiskOperationService::pending() const {
    std::lock_guard lock(journal_mutex_);
    return records_.size();
}
Json::Value DiskOperationService::recover(const CallContext& caller) {
    require_access(caller);
    replay();
    Json::Value result;
    result["pending"] = Json::UInt64(pending());
    return result;
}
Json::Value DiskOperationService::start(const CallContext& caller, const Json::Value& request) {
    require_access(caller);
    if (stopping_->load()) throw ServiceError(ErrorCode::unavailable, "the daemon is shutting down");
    struct Slot {
        std::shared_ptr<std::atomic<size_t>> active;
        bool held = false;
        ~Slot() { if (held) active->fetch_sub(1); }
    };
    auto slot = std::make_shared<Slot>();
    slot->active = active_;
    auto count = active_->load();
    do { if (count >= max_tasks) throw ServiceError(ErrorCode::resource_exhausted, "Too many disk operations are running"); }
    while (!active_->compare_exchange_weak(count, count + 1));
    slot->held = true;
    // One cell: leases and reservations end with the work, not with the callbacks.
    auto cell = std::make_shared<std::shared_ptr<Operation>>(std::make_shared<Operation>(*this, request));
    const auto resource = "disk:" + (*cell)->disk_id();
    const auto ref = context_.configuration->events().submit(caller, {"disk_operation", resource, 4096, true, true},
        [slot, cell](TaskControl& control) {
            auto operation = std::move(*cell);
            auto completion = operation->run(control);
            operation.reset();
            return completion;
        },
        [slot, cell](const TaskRef&) { cell->reset(); });
    Json::Value result;
    result["task_id"] = ref.id;
    result["epoch"] = ref.epoch;
    return result;
}
void DiskOperationService::shutdown() { stopping_->store(true); }
}
