// SPDX-License-Identifier: GPL-3.0-or-later
#include "transfers.h"
#include "import_preview.h"
#include "common/identity.h"
#include "store/json_file.h"
#include <algorithm>
#include <atomic>
#include <charconv>
#include <climits>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <set>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <linux/fs.h>
#include <unistd.h>

namespace droidvm::pkg {
namespace {
void access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || !caller.manage_tasks || caller.principal.empty())
        throw ServiceError(ErrorCode::permission_denied, "Package transfer permission required");
}
[[noreturn]] void invalid() { throw ServiceError(ErrorCode::invalid_argument, "Invalid package transfer request"); }
void identity(const std::string& value) {
    if (value.empty() || value.size() > 128 || !std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
    })) invalid();
}
void filename(const std::string& name) {
    if (name.empty() || name.size() > 255 || name == "." || name == ".." || !valid_utf8(name) ||
            name.find_first_of("/\\") != std::string::npos || std::any_of(name.begin(), name.end(), [](unsigned char c) { return c < 32 || c == 127; })) invalid();
}
uint64_t decimal(const Json::Value& value) {
    if (!value.isString()) invalid();
    const auto text = value.asString();
    uint64_t result = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), result);
    if (text.empty() || error != std::errc() || end != text.data() + text.size() || std::to_string(result) != text) invalid();
    return result;
}
struct File {
    std::string name;
    uint64_t size = 0, offset = 0;
    std::unique_ptr<RetainedFile> retained;
    Json::Value observed;
};
struct Entry {
    std::mutex mutex;
    std::string id, owner, destination, directory_name;
    bool download = false, image = false, ready = false, failed = false, closing = false, removed = false;
    Json::Value installation;
    std::string install_target;
    uint64_t total = 0;
    size_t master = 0;
    std::atomic<uint64_t> received{0};
    std::atomic<size_t> pins{0};
    TransferService::Clock::time_point expires;
    std::unique_ptr<CreatedDirectory> directory;
    std::vector<File> files;
};
struct Pin {
    std::shared_ptr<Entry> entry;
    explicit Pin(std::shared_ptr<Entry> value) : entry(std::move(value)) { entry->pins.fetch_add(1); }
    ~Pin() { entry->pins.fetch_sub(1); }
};
bool owned_name(std::string_view name) {
    const size_t prefix = name.starts_with("image-upload-") ? 13 : name.starts_with("upload-") ? 7 : 0;
    return prefix && name.size() == prefix + 64 && std::all_of(name.begin() + prefix, name.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
void verify_size(int fd, uint64_t expected) {
    struct stat value{};
    if (fstat(fd, &value) != 0 || value.st_size < 0 || static_cast<uint64_t>(value.st_size) != expected)
        throw ServiceError(ErrorCode::io_error, "Package upload file size changed");
}
void sync_file(int fd) {
    while (fsync(fd) != 0) if (errno != EINTR) throw ServiceError(ErrorCode::io_error, "Package upload synchronization failed");
}
void image_folder(const std::string& folder) {
    if (folder.empty() || folder.front() != '/' || folder.size() > 4096 || !valid_utf8(folder) ||
            folder.find('\0') != std::string::npos || (folder != "/" && folder.back() == '/')) invalid();
    for (size_t start = 1; start < folder.size();) {
        const auto end = std::min(folder.find('/', start), folder.size());
        const auto part = folder.substr(start, end - start);
        if (part.empty() || part == "." || part == "..") invalid();
        start = end + 1;
    }
}
bool beneath(const std::string& path, const std::string& root) {
    return path == root || path.starts_with(root + "/");
}
bool image_temporary(const std::string& name) {
    return name.size() == 79 && name.starts_with(".dvm-image-") && name.ends_with(".tmp") &&
        name.substr(11, 64).find_first_not_of("0123456789abcdef") == std::string::npos;
}
bool same_file(const struct stat& a, const struct stat& b) { return a.st_dev == b.st_dev && a.st_ino == b.st_ino; }
struct CreatedImageDirectory {
    std::string path, name;
    Fd parent;
    struct stat identity{};
};
// The canonical existing prefix may include Android storage aliases. Missing
// descendants are opened relative to retained parents and never follow links.
Fd image_directory(const std::string& path, std::vector<CreatedImageDirectory>& created,
        bool& creation_uncertain) {
    std::vector<std::string> missing;
    auto existing = path;
    Fd directory;
    for (;;) {
        directory = Fd(open(existing.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (directory.get() >= 0) break;
        if (errno != ENOENT || existing == "/")
            throw ServiceError(ErrorCode::io_error, "Cannot open image destination directory");
        missing.push_back(file_name(existing));
        existing = dirname(existing);
    }
    for (auto item = missing.rbegin(); item != missing.rend(); ++item) {
        struct stat parent{};
        struct stat named_parent{};
        if (fstat(directory.get(), &parent) != 0 || stat(existing.c_str(), &named_parent) != 0 ||
                !same_file(parent, named_parent) || canonical_path(existing) != existing)
            throw ServiceError(ErrorCode::io_error, "Cannot inspect image destination parent");
        const bool made = mkdirat(directory.get(), item->c_str(), parent.st_mode & 0777) == 0;
        if (!made && errno != EEXIST)
            throw ServiceError(ErrorCode::io_error, "Cannot create image destination directory");
        creation_uncertain = made;
        struct stat entry{}, opened{};
        if (fstatat(directory.get(), item->c_str(), &entry, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISDIR(entry.st_mode))
            throw ServiceError(ErrorCode::conflict, "Image destination must be a directory");
        Fd child(openat(directory.get(), item->c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (child.get() < 0 || fstat(child.get(), &opened) != 0 || !same_file(entry, opened))
            throw ServiceError(ErrorCode::conflict, "Image destination directory changed");
        existing = path_join(existing, *item);
        if (made) {
            Fd held_parent(fcntl(directory.get(), F_DUPFD_CLOEXEC, 3));
            if (held_parent.get() < 0)
                throw ServiceError(ErrorCode::io_error, "Cannot retain image destination parent");
            created.push_back({existing, *item, std::move(held_parent), opened});
            creation_uncertain = false;
            inherit_directory_access(child.get(), directory.get());
            sync_file(child.get());
            sync_file(directory.get());
        }
        directory = std::move(child);
    }
    return directory;
}
bool discard_image_directories(std::vector<CreatedImageDirectory>& created) {
    try {
        for (auto item = created.rbegin(); item != created.rend(); ++item) {
            struct stat parent{}, current_parent{}, current{};
            if (fstat(item->parent.get(), &parent) != 0 ||
                    stat(dirname(item->path).c_str(), &current_parent) != 0 || !same_file(parent, current_parent)) return false;
            if (fstatat(item->parent.get(), item->name.c_str(), &current, AT_SYMLINK_NOFOLLOW) != 0) {
                if (errno == ENOENT) continue;
                return false;
            }
            if (!S_ISDIR(current.st_mode) || !same_file(item->identity, current)) return false;
            // Only an empty directory belonging to this task can be removed.
            // Never recursively remove content another writer placed here.
            if (unlinkat(item->parent.get(), item->name.c_str(), AT_REMOVEDIR) != 0) return false;
            sync_file(item->parent.get());
        }
        created.clear();
        return true;
    } catch (...) { return false; }
}
// No check-then-rename fallback: an unsupported filesystem must fail closed.
bool install_image_name(int directory, const std::string& from, const std::string& to) {
    if (linkat(directory, from.c_str(), directory, to.c_str(), 0) == 0) return false;
    const int error = errno;
    if ((error == EPERM || error == EOPNOTSUPP || error == ENOSYS || error == EXDEV || error == EMLINK) &&
            syscall(SYS_renameat2, directory, from.c_str(), directory, to.c_str(), RENAME_NOREPLACE) == 0) return true;
    throw ServiceError(errno == EEXIST ? ErrorCode::conflict : ErrorCode::io_error, "Cannot install image without replacing an existing file");
}
using FileIdentities = std::map<std::string, std::pair<dev_t, ino_t>>;
bool reclaim_upload(int parent, const std::string& name, uid_t owner, size_t maximum, const FileIdentities* expected_files = nullptr) {
    try {
        Fd child(openat(parent, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (child.get() < 0) { if (errno == ENOENT) { sync_file(parent); return true; } return false; }
        struct stat directory{};
        if (fstat(child.get(), &directory) != 0 || directory.st_uid != owner) return false;
        const int duplicate = fcntl(child.get(), F_DUPFD_CLOEXEC, 3);
        if (duplicate < 0) return false;
        DIR* raw = fdopendir(duplicate);
        if (!raw) { close(duplicate); return false; }
        std::unique_ptr<DIR, int(*)(DIR*)> stream(raw, closedir);
        std::vector<std::pair<std::string, struct stat>> files;
        std::string master;
        for (;;) {
            errno = 0;
            const auto* item = readdir(stream.get());
            if (!item) { if (errno) return false; break; }
            const std::string filename_value = item->d_name;
            if (filename_value == "." || filename_value == "..") continue;
            if (files.size() >= maximum) return false;
            filename(filename_value);
            if (name.starts_with("image-upload-")) {
                if (filename_value != "image.bin") return false;
            } else {
                const auto base = master_of(filename_value);
                if (!base.ends_with(".vmpkg") || (!master.empty() && master != base)) return false;
                master = base;
            }
            struct stat info{};
            if (fstatat(child.get(), filename_value.c_str(), &info, AT_SYMLINK_NOFOLLOW) != 0 ||
                    !S_ISREG(info.st_mode) || info.st_uid != owner || info.st_nlink != 1) return false;
            if (expected_files) {
                const auto expected = expected_files->find(filename_value);
                if (expected == expected_files->end() || expected->second != std::make_pair(info.st_dev, info.st_ino)) return false;
            }
            files.emplace_back(filename_value, info);
        }
        // Validate every child before deleting any; never recurse into an
        // unknown entry, even beneath a directory bearing our generated name.
        for (const auto& [filename_value, expected] : files) {
            struct stat current{};
            if (fstatat(child.get(), filename_value.c_str(), &current, AT_SYMLINK_NOFOLLOW) != 0 ||
                    current.st_dev != expected.st_dev || current.st_ino != expected.st_ino || !S_ISREG(current.st_mode)) return false;
            if (unlinkat(child.get(), filename_value.c_str(), 0) != 0) return false;
        }
        struct stat current{};
        if (fstatat(parent, name.c_str(), &current, AT_SYMLINK_NOFOLLOW) != 0 ||
                current.st_dev != directory.st_dev || current.st_ino != directory.st_ino) return false;
        if (unlinkat(parent, name.c_str(), AT_REMOVEDIR) != 0) return false;
        sync_file(parent);
        return true;
    } catch (...) { return false; }
}
}
struct TransferService::Shared {
    mutable std::mutex mutex;
    std::map<std::pair<std::string, std::string>, std::shared_ptr<Entry>> entries;
    std::atomic<bool> stopping{false};
    uint64_t reserved = 0;
    uid_t owner = 0;
    std::vector<std::string> orphans;
    Limits limits;
    Now now;
    std::string root, cache_root;
    Fd directory;
    std::shared_ptr<config::DiskFileLeases> leases;
    std::mutex install_mutex;
    std::unique_ptr<config::JsonFile> install_journal;
    Json::Value install_records{Json::objectValue};
    std::set<std::string> install_active;
    void journal_put(const std::string& key, const Json::Value& record) {
        std::lock_guard lock(install_mutex);
        if (!install_records.isMember(key) && install_records.size() >= 64)
            throw ServiceError(ErrorCode::resource_exhausted, "Image installation residue requires cleanup");
        auto next = install_records; next[key] = record;
        install_journal->save(next);
        install_records = std::move(next);
    }
    void journal_drop(const std::string& key) {
        std::lock_guard lock(install_mutex);
        auto next = install_records; next.removeMember(key);
        install_journal->save(next);
        install_records = std::move(next);
    }
    void recover_installs() {
        std::lock_guard lock(install_mutex);
        auto next = install_records;
        for (const auto& key : install_records.getMemberNames()) {
            if (install_active.contains(key)) continue;
            const auto& record = install_records[key];
            try {
                const auto folder = record["folder"].asString(), temporary = record["temporary"].asString();
                image_folder(folder);
                if (!image_temporary(temporary)) continue;
                Fd parent(open(folder.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
                struct stat directory{}, file{};
                if (parent.get() < 0 || fstat(parent.get(), &directory) != 0 ||
                        record["directory_device"] != std::to_string(directory.st_dev) ||
                        record["directory_inode"] != std::to_string(directory.st_ino)) continue;
                if (fstatat(parent.get(), temporary.c_str(), &file, AT_SYMLINK_NOFOLLOW) != 0) {
                    if (errno != ENOENT) continue;
                } else {
                    // A crash before recording the created inode leaves a residue
                    // for manual inspection; never infer ownership from its name.
                    if (!S_ISREG(file.st_mode) || record["device"] != std::to_string(file.st_dev) ||
                            record["inode"] != std::to_string(file.st_ino)) continue;
                    if (unlinkat(parent.get(), temporary.c_str(), 0) != 0) continue;
                }
                sync_file(parent.get());
                // The final destination is deliberately never removed or retried.
                next.removeMember(key);
            } catch (...) { /* Keep exact cleanup ownership for a later sweep. */ }
        }
        if (next != install_records) {
            install_journal->save(next);
            install_records = std::move(next);
        }
    }
    void verify_root() const {
        struct stat held{}, current{};
        if (fstat(directory.get(), &held) != 0 || stat(root.c_str(), &current) != 0 ||
                held.st_dev != current.st_dev || held.st_ino != current.st_ino || !S_ISDIR(current.st_mode))
            throw ServiceError(ErrorCode::conflict, "Package transfer directory changed");
    }
    std::shared_ptr<Entry> find(const CallContext& caller, const std::string& id, bool image = false) const {
        access(caller); identity(id);
        std::lock_guard lock(mutex);
        const auto found = entries.find({caller.principal, id});
        if (found == entries.end() || found->second->owner != caller.principal || found->second->image != image)
            throw ServiceError(ErrorCode::not_found, "Package transfer not found");
        return found->second;
    }
    void live(const Entry& entry) const {
        if (stopping.load() || entry.closing) throw ServiceError(ErrorCode::unavailable, "Package transfer is closing");
        if (now() >= entry.expires) throw ServiceError(ErrorCode::not_found, "Package transfer expired");
    }
    Json::Value view(const Entry& entry) const {
        Json::Value result;
        result["id"] = entry.id; result["kind"] = entry.download ? "download" : "upload";
        result["purpose"] = entry.image ? "image" : "package";
        result["state"] = entry.closing ? "closing" : entry.failed ? "failed" : entry.ready ? "ready" : "receiving";
        auto& files = result["files"] = Json::Value(Json::arrayValue);
        for (size_t i = 0; i < entry.files.size(); ++i) {
            const auto& file = entry.files[i];
            Json::Value row;
            row["index"] = Json::UInt(i); row["name"] = file.name;
            row["size_bytes"] = std::to_string(file.size); row["offset_bytes"] = std::to_string(file.offset);
            files.append(std::move(row));
        }
        if (entry.image) result["installation"] = entry.installation;
        if (!entry.download && !entry.image && entry.ready && !entry.closing)
            result["master_path"] = path_join(entry.directory->path(), entry.files[entry.master].name);
        result["limits"]["max_files"] = Json::UInt(limits.files);
        result["limits"]["max_file_bytes"] = std::to_string(limits.file_bytes);
        result["limits"]["max_session_bytes"] = std::to_string(limits.session_bytes);
        result["limits"]["max_total_bytes"] = std::to_string(limits.total_bytes);
        result["limits"]["chunk_bytes"] = Json::UInt(limits.chunk_bytes);
        result["limits"]["ttl_ms"] = Json::UInt64(limits.ttl.count());
        return result;
    }
    void admit(const std::shared_ptr<Entry>& entry) {
        std::lock_guard lock(mutex);
        if (stopping.load()) throw ServiceError(ErrorCode::unavailable, "Package transfers are stopping");
        if (entries.contains({entry->owner, entry->id})) throw ServiceError(ErrorCode::conflict, "Package transfer request ID already exists");
        if (!entry->download && !orphans.empty()) throw ServiceError(ErrorCode::resource_exhausted, "Previous package uploads require cleanup");
        if (entries.size() >= limits.records || (!entry->download && entry->total > limits.total_bytes - reserved))
            throw ServiceError(ErrorCode::resource_exhausted, "Package transfer quota exhausted");
        if (!entry->download) {
            struct statvfs space{};
            if (fstatvfs(directory.get(), &space) != 0) throw ServiceError(ErrorCode::io_error, "Cannot inspect upload free space");
            const auto available = static_cast<long double>(space.f_bavail) * space.f_frsize;
            uint64_t pending = 0;
            for (const auto& [id, existing] : entries) if (!existing->download) pending += existing->total - existing->received.load();
            if (available < static_cast<long double>(pending) + entry->total + limits.free_bytes)
                throw ServiceError(ErrorCode::resource_exhausted, "Insufficient space for package upload");
        }
        entries.emplace(std::make_pair(entry->owner, entry->id), entry);
        if (!entry->download) reserved += entry->total;
    }
    void remove(const std::shared_ptr<Entry>& entry) {
        std::lock_guard lock(entry->mutex);
        if (!entry->download && entry->pins.load()) throw ServiceError(ErrorCode::conflict, "Package upload is in use");
        entry->closing = true;
        if (entry->pins.load()) throw ServiceError(ErrorCode::conflict, "Package transfer is in use");
        if (!entry->download) {
            verify_root();
            if (!entry->directory_name.empty() && !entry->removed) {
                if (entry->directory) entry->directory->verify();
                FileIdentities expected;
                for (const auto& file : entry->files) if (file.retained) {
                    struct stat info{};
                    if (fstat(file.retained->fd(), &info) != 0) throw ServiceError(ErrorCode::io_error, "Cannot verify uploaded file cleanup");
                    expected.emplace(entry->image ? "image.bin" : file.name, std::make_pair(info.st_dev, info.st_ino));
                }
                if (!reclaim_upload(directory.get(), entry->directory_name, owner, limits.files, &expected))
                    throw ServiceError(ErrorCode::io_error, "Package upload cleanup is incomplete");
                entry->removed = true;
            }
            sync_file(directory.get());
        }
        std::lock_guard registry(mutex);
        const auto found = entries.find({entry->owner, entry->id});
        if (found != entries.end() && found->second == entry) {
            if (!entry->download) reserved -= entry->total;
            entries.erase(found);
        }
    }
};
TransferService::TransferService(int cache_fd, std::string path, uid_t owner, std::shared_ptr<config::DiskFileLeases> leases)
    : TransferService(cache_fd, std::move(path), owner, std::move(leases), Limits{}) {}
TransferService::TransferService(int cache_fd, std::string path, uid_t owner, std::shared_ptr<config::DiskFileLeases> leases,
        Limits limits, Now now) : shared_(std::make_shared<Shared>()) {
    if (!leases || !now || !limits.records || limits.records > 32 || !limits.files || limits.files > 1000 ||
            !limits.readers || limits.readers > 8 || !limits.chunk_bytes || limits.chunk_bytes > (256u << 10) ||
            !limits.file_bytes || limits.file_bytes > (64ull << 30) || limits.session_bytes < limits.file_bytes ||
            limits.session_bytes > (128ull << 30) || limits.total_bytes < limits.session_bytes ||
            limits.total_bytes > (512ull << 30) || limits.ttl.count() <= 0 || limits.ttl > std::chrono::hours(24)) invalid();
    struct stat held{}, named{};
    if (fstat(cache_fd, &held) != 0 || stat(path.c_str(), &named) != 0 || !S_ISDIR(held.st_mode) || held.st_uid != owner ||
            held.st_dev != named.st_dev || held.st_ino != named.st_ino)
        throw ServiceError(ErrorCode::conflict, "Invalid package transfer cache");
    const bool created = mkdirat(cache_fd, "webui-transfers", 0700) == 0;
    if (!created && errno != EEXIST)
        throw ServiceError(ErrorCode::io_error, "Cannot create package transfer directory");
    auto& state = *shared_;
    state.root = path_join(path, "webui-transfers");
    state.cache_root = path;
    state.directory = Fd(openat(cache_fd, "webui-transfers", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    // The daemon may run as root while the cache belongs to the App. Match
    // other private runtime storage, without repairing an existing directory.
    if (created) {
        if (state.directory.get() < 0 || fstat(state.directory.get(), &held) != 0 || held.st_uid != geteuid())
            throw ServiceError(ErrorCode::permission_denied, "Package transfer directory owner changed");
        if (fchown(state.directory.get(), owner, owner) != 0 || fchmod(state.directory.get(), 0700) != 0)
            throw ServiceError(ErrorCode::io_error, "Cannot protect package transfer directory");
    }
    if (state.directory.get() < 0 || fstat(state.directory.get(), &held) != 0 || held.st_uid != owner || (held.st_mode & 077) != 0)
        throw ServiceError(ErrorCode::permission_denied, "Package transfer directory is not private");
    state.limits = limits; state.now = std::move(now); state.leases = std::move(leases); state.owner = owner;
    state.verify_root();
    state.install_journal = std::make_unique<config::JsonFile>(cache_fd, "webui-image-installs.json", owner,
        config::JsonFile::Observer{}, 64u << 10, config::JsonSyntax::strict);
    if (const auto saved = state.install_journal->load()) {
        if (!saved->value.isObject() || saved->value.size() > 64)
            throw ServiceError(ErrorCode::io_error, "Invalid image installation recovery journal");
        state.install_records = saved->value;
    }
    state.recover_installs();
    // No transfer survives daemon restart. Only our exact generated directory
    // names under the dedicated private root qualify for crash reclamation.
    const int duplicate = fcntl(state.directory.get(), F_DUPFD_CLOEXEC, 3);
    if (duplicate < 0) throw ServiceError(ErrorCode::io_error, "Cannot inspect package upload residue");
    DIR* raw = fdopendir(duplicate);
    if (!raw) { close(duplicate); throw ServiceError(ErrorCode::io_error, "Cannot inspect package upload residue"); }
    std::unique_ptr<DIR, int(*)(DIR*)> directory(raw, closedir);
    size_t scanned = 0, owned = 0;
    for (;;) {
        errno = 0;
        const auto* item = readdir(directory.get());
        if (!item) { if (errno) throw ServiceError(ErrorCode::io_error, "Cannot inspect package upload residue"); break; }
        if (++scanned > 1024) throw ServiceError(ErrorCode::resource_exhausted, "Package transfer directory exceeds cleanup limit");
        if (!owned_name(item->d_name)) continue;
        if (++owned > limits.records * 2) throw ServiceError(ErrorCode::resource_exhausted, "Too many incomplete package uploads");
        struct stat residue{};
        if (fstatat(state.directory.get(), item->d_name, &residue, AT_SYMLINK_NOFOLLOW) != 0 ||
                !S_ISDIR(residue.st_mode) || residue.st_uid != owner) continue;
        state.verify_root();
        if (!reclaim_upload(state.directory.get(), item->d_name, owner, limits.files)) state.orphans.emplace_back(item->d_name);
    }
    sync_file(state.directory.get());
}
TransferService::~TransferService() = default;
Json::Value TransferService::begin(const CallContext& caller, const std::string& request_id, const std::vector<TransferFile>& files) {
    return begin_upload(caller, request_id, files, false);
}
Json::Value TransferService::begin_image(const CallContext& caller, const std::string& request_id, const TransferFile& file) {
    if (!file.size) invalid();
    return begin_upload(caller, request_id, {file}, true);
}
Json::Value TransferService::begin_upload(const CallContext& caller, const std::string& request_id,
        const std::vector<TransferFile>& files, bool image) {
    access(caller); identity(request_id);
    auto state = shared_;
    if (files.empty() || files.size() > state->limits.files) invalid();
    auto entry = std::make_shared<Entry>();
    entry->image = image;
    entry->id = request_id; entry->owner = caller.principal; entry->expires = state->now() + state->limits.ttl;
    std::set<std::string> names;
    std::string master;
    size_t masters = 0;
    for (const auto& file : files) {
        filename(file.name);
        if (!names.insert(file.name).second || file.size > state->limits.file_bytes || file.size > state->limits.session_bytes - entry->total) invalid();
        entry->total += file.size;
        if (!is_sub_volume(file.name)) { master = file.name; entry->master = entry->files.size(); ++masters; }
        entry->files.push_back({file.name, file.size, 0, {}, {}});
    }
    if (!image) {
        if (masters != 1 || !master.ends_with(".vmpkg")) invalid();
        for (const auto& file : files) if (master_of(file.name) != master) invalid();
        if (files.size() > 1) for (size_t i = 1; i < files.size(); ++i) if (!names.contains(volume_name(master, static_cast<int>(i)))) invalid();
    }
    std::unique_lock lock(entry->mutex);
    state->verify_root();
    state->admit(entry);
    try {
        entry->directory_name = std::string(image ? "image-upload-" : "upload-") + random_secret();
        entry->directory = std::make_unique<CreatedDirectory>(state->root, entry->directory_name);
        entry->directory_name = file_name(entry->directory->path());
        if (fchown(entry->directory->fd(), state->owner, state->owner) != 0 || fchmod(entry->directory->fd(), 0700) != 0)
            throw ServiceError(ErrorCode::io_error, "Cannot protect package upload directory");
        for (auto& file : entry->files) {
            entry->directory->verify();
            const auto stored_name = image ? std::string("image.bin") : file.name;
            Fd output(openat(entry->directory->fd(), stored_name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
            if (output.get() < 0) throw ServiceError(ErrorCode::io_error, "Cannot create package upload file");
            file.retained = std::make_unique<RetainedFile>(output.get(), entry->directory->fd(), entry->directory->path(), stored_name);
            if (fchown(output.get(), state->owner, state->owner) != 0 || fchmod(output.get(), 0600) != 0)
                throw ServiceError(ErrorCode::io_error, "Cannot protect package upload file");
        }
        return state->view(*entry);
    } catch (...) {
        entry->failed = true;
        lock.unlock();
        try { state->remove(entry); } catch (...) {}
        throw ServiceError(ErrorCode::io_error, "Package upload could not be created");
    }
}
Json::Value TransferService::status(const CallContext& caller, const std::string& id, bool image) const {
    const auto entry = shared_->find(caller, id, image);
    std::lock_guard lock(entry->mutex);
    if (shared_->now() >= entry->expires) throw ServiceError(ErrorCode::not_found, "Package transfer expired");
    return shared_->view(*entry);
}
Json::Value TransferService::append(const CallContext& caller, const std::string& id, size_t index, uint64_t offset, std::string_view bytes, bool image) {
    auto state = shared_; const auto entry = state->find(caller, id, image);
    std::lock_guard lock(entry->mutex); state->live(*entry);
    if (entry->download || entry->ready || entry->failed || index >= entry->files.size() || bytes.empty() || bytes.size() > state->limits.chunk_bytes) invalid();
    auto& file = entry->files[index];
    if (offset != file.offset) throw ServiceError(ErrorCode::conflict, "Upload offset changed; read transfer status");
    if (bytes.size() > file.size - file.offset) invalid();
    try {
        entry->directory->verify(); file.retained->verify();
        verify_size(file.retained->fd(), file.offset);
        size_t written = 0;
        while (written < bytes.size()) {
            const auto count = pwrite(file.retained->fd(), bytes.data() + written, bytes.size() - written, static_cast<off_t>(file.offset));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) throw ServiceError(ErrorCode::io_error, "Package upload write failed");
            written += static_cast<size_t>(count); file.offset += static_cast<uint64_t>(count); entry->received.fetch_add(static_cast<uint64_t>(count));
        }
        file.retained->verify();
        verify_size(file.retained->fd(), file.offset);
    } catch (...) { entry->failed = true; throw ServiceError(ErrorCode::io_error, "Package upload write failed; inspect transfer status"); }
    return state->view(*entry);
}
Json::Value TransferService::finish(const CallContext& caller, const std::string& id, bool image) {
    auto state = shared_; const auto entry = state->find(caller, id, image);
    std::lock_guard lock(entry->mutex); state->live(*entry);
    if (entry->download || entry->failed) invalid();
    if (entry->ready) return state->view(*entry);
    for (const auto& file : entry->files) if (file.offset != file.size) throw ServiceError(ErrorCode::conflict, "Package upload is incomplete");
    try {
        for (const auto& file : entry->files) {
            verify_size(file.retained->fd(), file.size);
            file.retained->sync();
            verify_size(file.retained->fd(), file.size);
        }
        entry->directory->sync();
        entry->ready = true;
    } catch (...) { entry->failed = true; throw ServiceError(ErrorCode::io_error, "Package upload synchronization failed"); }
    return state->view(*entry);
}
void TransferService::erase(const CallContext& caller, const std::string& id, bool image) { shared_->remove(shared_->find(caller, id, image)); }
TaskCompletion TransferService::install_image(const CallContext& caller, const std::string& upload_id,
        const std::string& folder, const std::string& name, const std::string& qemu_img, TaskControl& control,
        PublishImage publish_image) {
    access(caller);
    image_folder(folder); filename(name);
    if (name.starts_with(".dvm-")) invalid();
    auto state = shared_; const auto entry = state->find(caller, upload_id, true);
    const auto destination = path_join(folder, name);
    Json::Value receipt;
    receipt["upload_id"] = upload_id; receipt["path"] = destination;
    receipt["installed"] = false; receipt["durability_confirmed"] = false;
    receipt["installation_uncertain"] = false; receipt["recovery_required"] = false;
    std::shared_ptr<Pin> pin;
    {
        std::lock_guard lock(entry->mutex); state->live(*entry);
        if (!entry->ready || entry->failed || entry->files.size() != 1)
            throw ServiceError(ErrorCode::conflict, "Image upload is not ready");
        if (!entry->install_target.empty()) {
            if (entry->install_target != destination)
                throw ServiceError(ErrorCode::conflict, "Image upload already has a different installation target");
            const auto& prior = entry->installation;
            if (prior["state"] == "installed") return TaskCompletion::success(prior);
            throw ServiceError(ErrorCode::conflict, "Image installation already started; inspect its original task");
        }
        pin = std::make_shared<Pin>(entry);
        entry->install_target = destination;
        entry->installation = receipt; entry->installation["state"] = "installing";
    }
    const auto key = random_secret(), temporary = ".dvm-image-" + key + ".tmp";
    Fd directory, output;
    struct stat parent_identity{}, made{};
    bool journaled = false, created = false, published = false, renamed = false;
    bool directory_creation_uncertain = false;
    std::vector<CreatedImageDirectory> created_directories;
    std::string admitted_folder;
    auto verify_directory = [&] {
        struct stat current{}, canonical{};
        if (stat(folder.c_str(), &current) != 0 || stat(admitted_folder.c_str(), &canonical) != 0 ||
                !same_file(parent_identity, current) || !same_file(parent_identity, canonical))
            throw ServiceError(ErrorCode::conflict, "Image target directory changed");
    };
    auto finish = [&](TaskCompletion result, const char* status) {
        receipt["state"] = status;
        result.result = receipt;
        { std::lock_guard lock(entry->mutex); entry->installation = receipt; }
        { std::lock_guard lock(state->install_mutex); state->install_active.erase(key); }
        return result;
    };
    auto discard = [&] {
        try {
            if (output.get() >= 0 && !created) return false; // Created, but inode identity could not be obtained.
            if (created) {
                struct stat current{};
                if (fstatat(directory.get(), temporary.c_str(), &current, AT_SYMLINK_NOFOLLOW) != 0) {
                    if (errno != ENOENT) return false;
                } else if (!S_ISREG(current.st_mode) || !same_file(current, made) ||
                        unlinkat(directory.get(), temporary.c_str(), 0) != 0) return false;
                sync_file(directory.get());
            }
            if (journaled) state->journal_drop(key);
            return !directory_creation_uncertain && discard_image_directories(created_directories);
        } catch (...) { return false; }
    };
    try {
        if (control.cancellation_requested() || state->stopping.load())
            return finish(TaskCompletion::cancelled(), "cancelled");
        state->verify_root();
        admitted_folder = canonical_path(folder);
        const auto cache = canonical_path(state->cache_root);
        if (beneath(admitted_folder, cache))
            throw ServiceError(ErrorCode::conflict, "Image destination cannot be temporary transfer storage");
        directory = image_directory(admitted_folder, created_directories, directory_creation_uncertain);
        if (directory.get() < 0 || fstat(directory.get(), &parent_identity) != 0)
            throw ServiceError(ErrorCode::io_error, "Cannot inspect image target directory");
        verify_directory();
        struct stat occupied{};
        if (fstatat(directory.get(), name.c_str(), &occupied, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT)
            throw ServiceError(ErrorCode::conflict, "Image target already exists");
        if (publish_image) publish_image(destination, [] {});
        const auto& source = entry->files.front();
        source.retained->verify();
        const auto source_path = source.retained->path();
        auto lease = state->leases->acquire({{source_path, false}});
        const int input = lease->read_fd(source_path);
        const auto observed = observe_package_file(input);
        verify_size(input, source.size);
        auto stopping = [&] { return control.cancellation_requested() || state->stopping.load(); };
        const auto info = Images(qemu_img, stopping, std::chrono::seconds(5)).leased_info(*lease, source_path);
        const auto& specific = info["format-specific"];
        if (!specific.isNull() && !specific.isObject()) invalid();
        const auto& data = specific["data"];
        if (!data.isNull() && !data.isObject()) invalid();
        if ((info["format"] != "raw" && info["format"] != "qcow2") ||
                !info["virtual-size"].isUInt64() || !info["virtual-size"].asUInt64() ||
                info["virtual-size"].asUInt64() > uint64_t(INT64_MAX) ||
                !info["backing-filename"].isNull() || !info["full-backing-filename"].isNull() ||
                !data["data-file"].isNull() || info.get("encrypted", false).asBool())
            throw ServiceError(ErrorCode::invalid_argument, "Only standalone unencrypted raw and qcow2 images can be uploaded");
        if (stopping()) {
            receipt["recovery_required"] = !discard();
            if (receipt["recovery_required"].asBool())
                return finish(TaskCompletion::failure(ErrorCode::io_error, "Image directory cleanup is incomplete"), "failed");
            return finish(TaskCompletion::cancelled(), "cancelled");
        }
        struct statvfs space{};
        if (fstatvfs(directory.get(), &space) != 0 ||
                static_cast<long double>(space.f_bavail) * space.f_frsize < static_cast<long double>(source.size) + state->limits.free_bytes)
            throw ServiceError(ErrorCode::resource_exhausted, "Insufficient space to install uploaded image");
        Json::Value record;
        record["folder"] = admitted_folder; record["temporary"] = temporary;
        record["directory_device"] = std::to_string(parent_identity.st_dev);
        record["directory_inode"] = std::to_string(parent_identity.st_ino);
        { std::lock_guard lock(state->install_mutex); state->install_active.insert(key); }
        // Record temporary file ownership before copying. Created empty directories
        // are only reclaimed with retained identities in this task, never by path after a crash.
        journaled = true;
        state->journal_put(key, record);
        output = Fd(openat(directory.get(), temporary.c_str(), O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
        if (output.get() < 0 || fstat(output.get(), &made) != 0)
            throw ServiceError(ErrorCode::io_error, "Cannot create image installation temporary file");
        created = true;
        record["device"] = std::to_string(made.st_dev); record["inode"] = std::to_string(made.st_ino);
        state->journal_put(key, record);
        std::string buffer(state->limits.chunk_bytes, '\0');
        uint64_t copied = 0;
        control.progress({"image_copy", "bytes", 0, source.size});
        while (copied < source.size) {
            if (stopping()) {
                receipt["recovery_required"] = !discard();
                if (receipt["recovery_required"].asBool())
                    return finish(TaskCompletion::failure(ErrorCode::io_error, "Image copy cleanup is incomplete"), "failed");
                return finish(TaskCompletion::cancelled(), "cancelled");
            }
            const auto wanted = static_cast<size_t>(std::min<uint64_t>(buffer.size(), source.size - copied));
            ssize_t count;
            do { count = pread(input, buffer.data(), wanted, static_cast<off_t>(copied)); } while (count < 0 && errno == EINTR);
            if (count <= 0) throw ServiceError(ErrorCode::io_error, "Cannot read uploaded image");
            size_t written = 0;
            while (written < static_cast<size_t>(count)) {
                const auto bytes = pwrite(output.get(), buffer.data() + written, static_cast<size_t>(count) - written,
                    static_cast<off_t>(copied + written));
                if (bytes < 0 && errno == EINTR) continue;
                if (bytes <= 0) throw ServiceError(ErrorCode::io_error, "Cannot write installed image");
                written += static_cast<size_t>(bytes);
            }
            copied += static_cast<uint64_t>(count);
            control.progress({"image_copy", "bytes", copied, source.size});
        }
        lease->verify(); source.retained->verify();
        if (observe_package_file(input) != observed)
            throw ServiceError(ErrorCode::conflict, "Uploaded image changed during installation");
        verify_size(output.get(), source.size);
        if (fchown(output.get(), parent_identity.st_uid, parent_identity.st_gid) != 0 || fchmod(output.get(), 0644) != 0)
            throw ServiceError(ErrorCode::io_error, "Cannot set installed image ownership");
        sync_file(output.get()); verify_directory();
        struct stat current{};
        if (fstatat(directory.get(), temporary.c_str(), &current, AT_SYMLINK_NOFOLLOW) != 0 ||
                !same_file(made, current) || current.st_nlink != 1)
            throw ServiceError(ErrorCode::conflict, "Image installation temporary file changed");
        if (!control.enter_commit()) {
            receipt["recovery_required"] = !discard();
            if (receipt["recovery_required"].asBool())
                return finish(TaskCompletion::failure(ErrorCode::io_error, "Image copy cleanup is incomplete"), "failed");
            return finish(TaskCompletion::cancelled(), "cancelled");
        }
        const auto publish = [&] {
            verify_directory();
            renamed = install_image_name(directory.get(), temporary, name);
            published = true; receipt["installed"] = true;
            if (!renamed && unlinkat(directory.get(), temporary.c_str(), 0) != 0)
                throw ServiceError(ErrorCode::commit_uncertain, "Installed image temporary link cleanup failed");
            sync_file(directory.get()); verify_directory();
            if (fstatat(directory.get(), name.c_str(), &current, AT_SYMLINK_NOFOLLOW) != 0 ||
                    !same_file(made, current) || current.st_nlink != 1)
                throw ServiceError(ErrorCode::commit_uncertain, "Installed image identity could not be confirmed");
        };
        if (publish_image) publish_image(destination, publish);
        else publish();
        state->journal_drop(key);
        receipt["durability_confirmed"] = true;
        return finish(TaskCompletion::success(), "installed");
    } catch (const std::exception& error) {
        if (published) {
            receipt["installation_uncertain"] = true; receipt["recovery_required"] = true;
            return finish(TaskCompletion::failure(ErrorCode::commit_uncertain,
                "Image may be installed; inspect the original task and target before further action"), "uncertain");
        }
        receipt["recovery_required"] = !discard();
        if (!receipt["recovery_required"].asBool() && (control.cancellation_requested() || state->stopping.load()))
            return finish(TaskCompletion::cancelled(), "cancelled");
        const auto* service = dynamic_cast<const ServiceError*>(&error);
        return finish(TaskCompletion::failure(service ? service->code() : ErrorCode::io_error,
            "Image installation did not complete; inspect the upload and target"), "failed");
    }
}
Json::Value TransferService::prepare_download(const CallContext& caller, const std::string& request_id, const Json::Value& exported) {
    access(caller); identity(request_id);
    auto state = shared_;
    const auto& manifest = exported["_export_manifest"];
    if (!manifest.isObject() || !manifest["destination"].isString() || !manifest["files"].isArray() ||
            manifest["files"].empty() || manifest["files"].size() > state->limits.files) invalid();
    auto entry = std::make_shared<Entry>();
    entry->id = request_id; entry->owner = caller.principal; entry->download = true; entry->ready = true;
    entry->expires = state->now() + state->limits.ttl; entry->destination = manifest["destination"].asString();
    if (entry->destination.empty() || entry->destination.front() != '/' || entry->destination.size() > 4096 || entry->destination.find('\0') != std::string::npos) invalid();
    for (Json::ArrayIndex i = 0; i < manifest["files"].size(); ++i) {
        const auto& observed = manifest["files"][i];
        if (!observed.isObject() || observed.getMemberNames().size() != 7) invalid();
        for (const auto* key : {"device", "inode", "size", "mtime_sec", "mtime_nsec", "ctime_sec", "ctime_nsec"})
            if (!observed[key].isString() || observed[key].asString().size() > 32) invalid();
        const auto size = decimal(observed["size"]);
        if (size > state->limits.file_bytes || size > state->limits.session_bytes - entry->total) invalid();
        const auto path = i == 0 ? entry->destination : volume_name(entry->destination, static_cast<int>(i));
        filename(file_name(path));
        const auto lease = state->leases->acquire({{path, false}});
        if (observe_package_file(lease->read_fd(path)) != observed)
            throw ServiceError(ErrorCode::conflict, "Exported package changed; export it again");
        entry->files.push_back({file_name(path), size, size, {}, observed}); entry->total += size;
    }
    std::lock_guard lock(entry->mutex); state->admit(entry);
    return state->view(*entry);
}
std::shared_ptr<DownloadReader> TransferService::open_download(const CallContext& caller, const std::string& id, size_t index) {
    auto state = shared_; auto entry = state->find(caller, id);
    std::lock_guard lock(entry->mutex); state->live(*entry);
    if (!entry->download || index >= entry->files.size()) invalid();
    if (entry->pins.load() >= state->limits.readers) throw ServiceError(ErrorCode::resource_exhausted, "Too many package download readers");
    const auto path = index == 0 ? entry->destination : volume_name(entry->destination, static_cast<int>(index));
    const auto expected = entry->files[index].observed;
    auto lease = state->leases->acquire({{path, false}});
    if (observe_package_file(lease->read_fd(path)) != expected) throw ServiceError(ErrorCode::conflict, "Exported package changed");
    auto file = std::make_shared<Fd>(lease->open_file(path));
    auto pin = std::make_shared<Pin>(entry);
    auto reader = std::make_shared<DownloadReader>();
    reader->size_ = entry->files[index].size;
    reader->read_ = [state, entry, expected, lease, file, pin, size = reader->size_](uint64_t offset, size_t maximum) {
        (void)pin;
        std::lock_guard lock(entry->mutex); state->live(*entry);
        if (!maximum || maximum > state->limits.chunk_bytes || offset > size) invalid();
        lease->verify();
        if (observe_package_file(file->get()) != expected) throw ServiceError(ErrorCode::conflict, "Exported package changed");
        std::string bytes(static_cast<size_t>(std::min<uint64_t>(maximum, size - offset)), '\0');
        size_t read = 0;
        while (read < bytes.size()) {
            const auto count = pread(file->get(), bytes.data() + read, bytes.size() - read, static_cast<off_t>(offset + read));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) throw ServiceError(ErrorCode::io_error, "Package download read failed");
            read += static_cast<size_t>(count);
        }
        lease->verify();
        if (observe_package_file(file->get()) != expected) throw ServiceError(ErrorCode::conflict, "Exported package changed");
        return bytes;
    };
    return reader;
}
std::shared_ptr<const void> TransferService::pin_source(const CallContext& caller, const std::string& path) {
    access(caller);
    auto state = shared_;
    state->verify_root();
    const auto canonical = canonical_path(path);
    const auto prefix = canonical_path(state->root) + "/";
    struct stat source{};
    const bool observed = stat(path.c_str(), &source) == 0 && S_ISREG(source.st_mode);
    std::vector<std::shared_ptr<Entry>> entries;
    { std::lock_guard lock(state->mutex); for (const auto& [id, entry] : state->entries) entries.push_back(entry); }
    for (const auto& entry : entries) {
        std::lock_guard lock(entry->mutex);
        if (entry->download || !entry->directory) continue;
        for (const auto& file : entry->files) {
            struct stat held{};
            const bool same_inode = observed && file.retained && fstat(file.retained->fd(), &held) == 0 &&
                source.st_dev == held.st_dev && source.st_ino == held.st_ino;
            if (!same_inode && (!file.retained || canonical != canonical_path(file.retained->path()))) continue;
            if (entry->owner != caller.principal) throw ServiceError(ErrorCode::not_found, "Package upload not found");
            if (entry->image) throw ServiceError(ErrorCode::conflict, "Temporary image upload is not a package import source");
            state->live(*entry);
            if (!entry->ready || entry->failed) throw ServiceError(ErrorCode::conflict, "Package upload is not ready");
            entry->directory->verify(); file.retained->verify();
            return std::make_shared<Pin>(entry);
        }
    }
    if (canonical.starts_with(prefix)) throw ServiceError(ErrorCode::not_found, "Package upload is missing or expired");
    return {};
}
void TransferService::require_persistent_source(const std::string& path, int admitted_fd) const {
    auto state = shared_;
    state->verify_root();
    struct stat source{};
    if (fstat(admitted_fd, &source) != 0 || !S_ISREG(source.st_mode))
        throw ServiceError(ErrorCode::conflict, "Cannot verify image source identity");
    const auto canonical = canonical_path(path);
    const auto rejected = [] { throw ServiceError(ErrorCode::conflict, "Temporary transfer files cannot be registered as persistent images"); };
    if (beneath(canonical, canonical_path(state->root)) || image_temporary(file_name(canonical))) rejected();
    std::vector<std::shared_ptr<Entry>> entries;
    std::vector<std::string> orphans;
    {
        std::lock_guard lock(state->mutex);
        for (const auto& [id, entry] : state->entries) if (!entry->download) entries.push_back(entry);
        orphans = state->orphans;
    }
    for (const auto& entry : entries) {
        std::lock_guard lock(entry->mutex);
        for (const auto& file : entry->files) if (file.retained) {
            struct stat held{};
            if (fstat(file.retained->fd(), &held) != 0)
                throw ServiceError(ErrorCode::io_error, "Cannot verify temporary image ownership");
            if (same_file(source, held)) rejected();
        }
    }
    // Crash residue with a hardlink is deliberately not reclaimed. The alias
    // still must not turn that temporary inode into a registered durable image.
    for (const auto& name : orphans) {
        Fd directory(openat(state->directory.get(), name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (directory.get() < 0) {
            if (errno == ENOENT) continue;
            throw ServiceError(ErrorCode::io_error, "Cannot inspect temporary image residue");
        }
        const int duplicate = fcntl(directory.get(), F_DUPFD_CLOEXEC, 3);
        if (duplicate < 0) throw ServiceError(ErrorCode::io_error, "Cannot inspect temporary image residue");
        DIR* raw = fdopendir(duplicate);
        if (!raw) { close(duplicate); throw ServiceError(ErrorCode::io_error, "Cannot inspect temporary image residue"); }
        std::unique_ptr<DIR, int(*)(DIR*)> stream(raw, closedir);
        size_t scanned = 0;
        for (;;) {
            errno = 0;
            const auto* file = readdir(stream.get());
            if (!file) {
                if (errno) throw ServiceError(ErrorCode::io_error, "Cannot inspect temporary image residue");
                break;
            }
            if (++scanned > state->limits.files + 2)
                throw ServiceError(ErrorCode::resource_exhausted, "Temporary image residue exceeds inspection limit");
            struct stat held{};
            if (fstatat(directory.get(), file->d_name, &held, AT_SYMLINK_NOFOLLOW) == 0 && same_file(source, held)) rejected();
        }
    }
    std::lock_guard lock(state->install_mutex);
    for (const auto& key : state->install_records.getMemberNames()) {
        const auto& record = state->install_records[key];
        if (record["device"] == std::to_string(source.st_dev) && record["inode"] == std::to_string(source.st_ino)) rejected();
    }
}
void TransferService::maintenance() {
    auto state = shared_;
    std::vector<std::shared_ptr<Entry>> entries;
    { std::lock_guard lock(state->mutex); for (const auto& [id, entry] : state->entries) entries.push_back(entry); }
    for (const auto& entry : entries) {
        bool remove;
        { std::lock_guard lock(entry->mutex); remove = state->stopping.load() || entry->closing || state->now() >= entry->expires; }
        if (remove) try { state->remove(entry); } catch (...) {}
    }
    std::vector<std::string> orphans;
    { std::lock_guard lock(state->mutex); orphans = state->orphans; }
    for (const auto& name : orphans) try {
        state->verify_root();
        if (reclaim_upload(state->directory.get(), name, state->owner, state->limits.files)) {
            std::lock_guard lock(state->mutex); std::erase(state->orphans, name);
        }
    } catch (...) {}
    try { state->recover_installs(); } catch (...) {}
}
void TransferService::shutdown() { shared_->stopping.store(true); maintenance(); }
}
