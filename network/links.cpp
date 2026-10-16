// SPDX-License-Identifier: GPL-3.0-or-later
#include "links.h"
#include "common/identity.h"
#include "services/context.h"
#include <charconv>
#include <dirent.h>
#include <fcntl.h>
#include <memory>
#include <set>
#include <sys/stat.h>
#include <system_error>

namespace droidvm::network {
namespace {
void require(bool ok, const char* operation) {
    if (!ok) throw std::system_error(errno, std::generic_category(), operation);
}
std::string read_at(int directory, const char* path, size_t limit) {
    Fd fd(openat(directory, path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    require(fd.get() >= 0, "open network identity");
    std::string result;
    char buffer[256];
    for (;;) {
        auto count = read(fd.get(), buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        require(count >= 0, "read network identity");
        if (!count) break;
        result.append(buffer, static_cast<size_t>(count));
        if (result.size() > limit) throw std::runtime_error("network identity exceeds budget");
    }
    if (!result.empty() && result.back() == '\n') result.pop_back();
    return result;
}
Fd link_directory(const std::string& name) {
    Netbox::interface_name(name);
    // /sys/class/net entries are kernel-owned symlinks to device directories.
    auto path = "/sys/class/net/" + name;
    int fd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT) return Fd();
    require(fd >= 0, "open network link directory");
    return Fd(fd);
}
uint32_t index_at(int directory) {
    auto text = read_at(directory, "ifindex", 32);
    uint32_t value = 0;
    auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size() || !value)
        throw std::runtime_error("invalid kernel interface index");
    return value;
}
uint32_t group_at(int directory) {
    const auto text = read_at(directory, "netdev_group", 32);
    int64_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    // Some kernels expose the u32 group through a signed %d sysfs formatter.
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() || value < INT32_MIN || value > UINT32_MAX)
        throw std::runtime_error("invalid kernel interface group");
    return static_cast<uint32_t>(value);
}
void tag_at(int directory, const std::string& tag) {
    Fd fd(openat(directory, "ifalias", O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
    require(fd.get() >= 0, "open network ownership alias");
    ssize_t count;
    do { count = write(fd.get(), tag.data(), tag.size()); } while (count < 0 && errno == EINTR);
    if (count >= 0 && static_cast<size_t>(count) != tag.size()) errno = EIO;
    require(count == static_cast<ssize_t>(tag.size()), "write network ownership alias");
}
void owner_id(const std::string& owner) {
    if (owner.empty() || owner.size() > 128 || owner.find('\0') != std::string::npos)
        throw ServiceError(ErrorCode::invalid_argument, "invalid network resource owner");
}
}
OwnedLinks::OwnedLinks(int directory, uid_t uid, const Netbox& netbox, Observer observer,
                       config::JsonFile::Observer file_observer)
    : netbox_(netbox), file_(directory, "network-links.json", uid, std::move(file_observer)), observer_(std::move(observer)) {
    boot_ = read_at(AT_FDCWD, "/proc/sys/kernel/random/boot_id", 64);
    struct stat ns{};
    require(stat("/proc/self/ns/net", &ns) == 0, "stat network namespace");
    namespace_device_ = ns.st_dev; namespace_inode_ = ns.st_ino;
    auto loaded = file_.load();
    if (loaded && loaded->recovered)
        throw ServiceError(ErrorCode::io_error, "network link primary is damaged; recovery requires the latest inventory");
    document_ = loaded ? loaded->value : Json::Value(Json::objectValue);
    if (!loaded) { document_["schema"] = 1; document_["links"] = Json::Value(Json::arrayValue); }
    if (document_["schema"] != 1 || !document_["links"].isArray() || document_["links"].size() > 1024)
        throw ServiceError(ErrorCode::io_error, "invalid network resource inventory");
    std::set<std::string> names;
    for (const auto& record : document_["links"]) {
        if (!record.isObject() || !record["owner"].isString() || !record["name"].isString() ||
            !record["tag"].isString() || !record["boot"].isString() || !record["index"].isUInt() ||
            !record["namespace_device"].isUInt64() || !record["namespace_inode"].isUInt64() ||
            !record["parent"].isString() || !record["kind"].isString())
            throw ServiceError(ErrorCode::io_error, "invalid network resource record");
        owner_id(record["owner"].asString()); Netbox::interface_name(record["name"].asString());
        if (record["kind"] != "bridge" && record["kind"] != "vlan" && record["kind"] != "tap")
            throw ServiceError(ErrorCode::io_error, "unknown network resource kind");
        auto tag = record["tag"].asString();
        if (!tag.starts_with("droidvm:") || tag.size() != 40 ||
            tag.substr(8).find_first_not_of("0123456789abcdef") != std::string::npos ||
            !names.insert(record["name"].asString()).second)
            throw ServiceError(ErrorCode::io_error, "invalid network resource identity");
        if (record.isMember("staging_name") && (!record["staging_name"].isString() ||
            record["staging_name"].asString() != creation_mark(tag).name))
            throw ServiceError(ErrorCode::io_error, "invalid staging interface identity");
    }
}
void OwnedLinks::save(Json::Value next) {
    try { file_.save(next); }
    catch (const config::CommitError& error) { if (error.installed) document_ = std::move(next); throw; }
    document_ = std::move(next);
}
Json::ArrayIndex OwnedLinks::find(const std::string& owner, const std::string& name) const {
    for (Json::ArrayIndex i = 0; i < document_["links"].size(); ++i) {
        const auto& row = document_["links"][i];
        if (row["name"] == name) {
            if (row["owner"] != owner) throw ServiceError(ErrorCode::conflict, "link belongs to another network: " + name);
            return i;
        }
    }
    throw ServiceError(ErrorCode::not_found, "network link is not owned: " + name);
}
bool OwnedLinks::matches_at(const Json::Value& record, int directory, const std::string& name, bool allow_pending) const {
    if (record["boot"] != boot_ || record["namespace_device"].asUInt64() != namespace_device_ ||
        record["namespace_inode"].asUInt64() != namespace_inode_) return false;
    const auto index = record["index"].asUInt();
    if (index ? index_at(directory) != index : !allow_pending) return false;
    const auto alias = read_at(directory, "ifalias", 256);
    if (alias == record["tag"].asString()) return true;
    if (index || !alias.empty() || record.get("creation_mark", false) != true || !record["staging_name"].isString()) return false;
    const auto mark = creation_mark(record["tag"].asString());
    return name == mark.name && group_at(directory) == mark.group;
}
OwnedLinks::Located OwnedLinks::locate(const Json::Value& record, bool allow_pending) const {
    for (const char* key : {"name", "staging_name"}) {
        if (!record[key].isString()) continue;
        const auto name = record[key].asString();
        auto directory = link_directory(name);
        if (directory.get() >= 0 && matches_at(record, directory.get(), name, allow_pending))
            return {std::move(directory), name};
    }
    return {Fd(), {}};
}
bool OwnedLinks::matches(const Json::Value& record, bool allow_pending) const {
    return locate(record, allow_pending).directory.get() >= 0;
}
void OwnedLinks::require_owned(const std::string& owner, const std::string& name) const {
    identity(owner, name);
}
Json::Value OwnedLinks::identity(const std::string& owner, const std::string& name) const {
    std::lock_guard guard(mutex_);
    const auto& record = document_["links"][find(owner, name)];
    if (record.isMember("staging_name") || !matches(record, false))
        throw ServiceError(ErrorCode::conflict, "network link identity changed or incomplete: " + name);
    return record;
}
void OwnedLinks::create(const std::string& owner, const std::string& name, const char* kind,
                        const std::string& parent, int vid) {
    std::lock_guard guard(mutex_);
    owner_id(owner); Netbox::interface_name(name);
    uint32_t parent_index = 0;
    if (!parent.empty()) {
        const auto& parent_record = document_["links"][find(owner, parent)];
        if (parent_record.isMember("staging_name") || !matches(parent_record, false))
            throw ServiceError(ErrorCode::conflict, "VLAN parent is not an owned link");
        parent_index = parent_record["index"].asUInt();
    }
    for (const auto& row : document_["links"]) if (row["name"] == name)
        throw ServiceError(ErrorCode::conflict, "network link already reserved: " + name);
    if (link_directory(name).get() >= 0) throw ServiceError(ErrorCode::conflict, "network interface already exists: " + name);
    if (document_["links"].size() >= 1024) throw ServiceError(ErrorCode::resource_exhausted, "network link inventory is full");
    Json::Value record;
    record["name"] = name; record["owner"] = owner; record["kind"] = kind; record["parent"] = parent;
    record["boot"] = boot_; record["namespace_device"] = Json::UInt64(namespace_device_);
    record["namespace_inode"] = Json::UInt64(namespace_inode_);
    record["index"] = 0u; record["tag"] = "droidvm:" + random_id(false);
    record["creation_mark"] = std::string_view(kind) != "tap";
    const auto staging = creation_mark(record["tag"].asString()).name;
    record["staging_name"] = staging;
    auto next = document_;
    const auto at = next["links"].size();
    next["links"].append(record);
    save(std::move(next)); // intent must be durable before a kernel side effect
    point("intent_saved");
    try {
        Fd transient;
        const bool tap = std::string_view(kind) == "tap";
        if (std::string_view(kind) == "bridge") create_marked_bridge(staging, record["tag"].asString());
        else if (tap) transient = open_transient_tap(staging);
        else create_marked_vlan(staging, record["tag"].asString(), parent_index, static_cast<uint16_t>(vid));
        point("link_created");
        auto directory = link_directory(staging);
        if (directory.get() < 0) throw ServiceError(ErrorCode::conflict, "created network link disappeared");
        if (!tap && !matches(record, true)) throw ServiceError(ErrorCode::conflict, "created link marker was not installed");
        record["index"] = index_at(directory.get());
        // A TAP remains nonpersistent until alias and journal are committed.
        // The other links retain their atomic creation mark until that point.
        tag_at(directory.get(), record["tag"].asString());
        point("alias_written");
        if (!matches(record, false)) throw ServiceError(ErrorCode::conflict, "created network link changed");
        next = document_; next["links"][at] = record;
        save(std::move(next));
        point("identity_saved");
        rename_owned_link(record["index"].asUInt(), name);
        point("link_renamed");
        if (!tap) clear_creation_group(record["index"].asUInt());
        record.removeMember("staging_name"); record.removeMember("creation_mark");
        next = document_; next["links"][at] = record;
        save(std::move(next));
        point("name_saved");
        if (tap) { persist_tap(transient.get()); point("tap_persistent"); }
        point("link_owned");
    } catch (const std::exception& error) {
        const std::string detail = error.what();
        try { remove_at(at); }
        catch (const std::exception& cleanup_error) {
            throw ServiceError(ErrorCode::io_error, detail + "; link cleanup pending: " + cleanup_error.what());
        }
        throw;
    }
}
void OwnedLinks::bridge(const std::string& owner, const std::string& name) { create(owner, name, "bridge"); }
void OwnedLinks::tap(const std::string& owner, const std::string& name) { create(owner, name, "tap"); }
void OwnedLinks::vlan(const std::string& owner, const std::string& parent, const std::string& name, int vid) {
    if (vid < 1 || vid > 4094) throw ServiceError(ErrorCode::invalid_argument, "invalid tagged VLAN id");
    create(owner, name, "vlan", parent, vid);
}
void OwnedLinks::remove_at(Json::ArrayIndex index) {
    const auto record = document_["links"][index];
    const auto configured_name = record["name"].asString();
    // A reboot destroys these kernel links. A different live namespace does not.
    if (record["boot"] == boot_) {
        if (record["namespace_device"].asUInt64() != namespace_device_ || record["namespace_inode"].asUInt64() != namespace_inode_)
            throw ServiceError(ErrorCode::conflict, "network resource belongs to another namespace");
        auto owned = locate(record, true);
        if (owned.directory.get() < 0) {
            if (link_directory(configured_name).get() >= 0 ||
                (record["staging_name"].isString() && link_directory(record["staging_name"].asString()).get() >= 0))
                throw ServiceError(ErrorCode::conflict, "refusing to delete unverified network link: " + configured_name);
        } else {
            const auto& name = owned.name;
            point("before_delete");
            if (!matches(record, true)) throw ServiceError(ErrorCode::conflict, "refusing to delete unverified network link: " + name);
            // Deleting a parent implicitly deletes VLAN children; do not bypass
            // a child's failed identity check. Likewise refuse foreign ports.
            for (const auto& row : document_["links"]) if (row["parent"] == configured_name)
                throw ServiceError(ErrorCode::conflict, "network link still has a recorded child: " + name);
            if (record["kind"] == "bridge" && !netbox_.links(name).empty())
                throw ServiceError(ErrorCode::conflict, "network bridge still has attached ports: " + name);
            // The kernel also deletes unrecorded VLAN children on parent
            // deletion. Reject those even when their names are unrelated.
            auto directory = std::move(owned.directory);
            int scan_fd = openat(directory.get(), ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            require(scan_fd >= 0, "open network dependency scan");
            DIR* raw = fdopendir(scan_fd);
            if (!raw) { close(scan_fd); require(false, "scan network dependencies"); }
            std::unique_ptr<DIR, int(*)(DIR*)> scan(raw, closedir);
            for (;;) {
                errno = 0;
                auto* entry = readdir(scan.get());
                if (!entry) { require(errno == 0, "read network dependencies"); break; }
                const std::string_view child(entry->d_name);
                if (!child.starts_with("upper_")) continue;
                // An owned port can be removed from its owned bridge. Other
                // uppers (notably VLAN children) must be removed explicitly.
                bool owned_master = false;
                for (const auto& row : document_["links"]) if (row["name"] == child.substr(6) &&
                    row["kind"] == "bridge" && row["owner"] == record["owner"] && matches(row, false))
                    owned_master = true;
                if (!owned_master) throw ServiceError(ErrorCode::conflict, "network link has an unowned upper dependency: " + name);
            }
            // Capture identity again from the open sysfs directory. Deletion
            // addresses this index, never a replacement that reused the name.
            const auto actual_index = index_at(directory.get());
            if (!matches_at(record, directory.get(), name, true))
                throw ServiceError(ErrorCode::conflict, "network link identity changed before deletion: " + name);
            point("delete_identity_checked");
            delete_link_index(actual_index);
            point("link_deleted");
            if (link_directory(name).get() >= 0) throw ServiceError(ErrorCode::conflict, "network link remains after delete: " + name);
        }
    }
    auto next = document_;
    next["links"].removeIndex(index, nullptr);
    save(std::move(next));
}
void OwnedLinks::remove(const std::string& owner, const std::string& name) {
    std::lock_guard guard(mutex_);
    remove_at(find(owner, name));
}
Json::Value OwnedLinks::cleanup(const std::string& owner) {
    std::lock_guard guard(mutex_);
    return cleanup_locked(&owner);
}
Json::Value OwnedLinks::recover_all() {
    std::lock_guard guard(mutex_);
    return cleanup_locked(nullptr);
}
Json::Value OwnedLinks::cleanup_locked(const std::string* owner) {
    Json::Value errors(Json::arrayValue);
    for (auto i = document_["links"].size(); i > 0; --i) {
        const auto record = document_["links"][i - 1];
        if (owner && record["owner"] != *owner) continue;
        try { remove_at(i - 1); }
        catch (const std::exception& error) {
            Json::Value failure; failure["name"] = record["name"]; failure["error"] = error.what();
            errors.append(std::move(failure));
        }
    }
    return errors;
}
Json::Value OwnedLinks::inventory() const { std::lock_guard guard(mutex_); return document_; }
Json::Value OwnedLinks::scope() const {
    Json::Value result; result["boot"] = boot_;
    result["namespace_device"] = Json::UInt64(namespace_device_);
    result["namespace_inode"] = Json::UInt64(namespace_inode_);
    return result;
}
std::string OwnedLinks::vlan_code(int vid) {
    if (vid < 0 || vid > 4094) throw ServiceError(ErrorCode::invalid_argument, "invalid VLAN id");
    constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    return {alphabet[(vid >> 6) & 63], alphabet[vid & 63]};
}
std::string OwnedLinks::vlan_device(const std::string& bridge, int vid) {
    auto result = vid == 0 ? bridge : bridge + "v" + vlan_code(vid);
    Netbox::interface_name(result); return result;
}
std::string OwnedLinks::vlan_leg(const std::string& bridge, int vid) {
    if (!vid) throw ServiceError(ErrorCode::invalid_argument, "VLAN zero has no trunk leg");
    auto result = bridge + "." + vlan_code(vid);
    Netbox::interface_name(result); return result;
}
}
