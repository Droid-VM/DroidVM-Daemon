// SPDX-License-Identifier: GPL-3.0-or-later
#include "switch_runtime.h"
#include "common/identity.h"
#include "runtime/helper_identity.h"
#include "services/context.h"
#include <fcntl.h>
#include <set>
#include <sys/stat.h>
#include <system_error>

namespace droidvm::network {
namespace {
void require(bool ok, const char* operation) {
    if (!ok) throw std::system_error(errno, std::generic_category(), operation);
}
bool valid_name(const std::string& name) {
    return name.size() == 35 && name.starts_with("gv-") &&
        name.substr(3).find_first_not_of("0123456789abcdef") == std::string::npos;
}
}
SwitchRuntime::SwitchRuntime(int directory, uid_t owner, Observer observer, config::JsonFile::Observer file_observer)
    : directory_(fcntl(directory, F_DUPFD_CLOEXEC, 3)), owner_(owner),
      file_(directory, "network-runtime.json", owner, std::move(file_observer)), observer_(std::move(observer)) {
    require(directory_.get() >= 0, "hold switch inventory directory");
    auto loaded = file_.load();
    // A backup can omit the most recently launched process. Never treat a
    // rolled-back resource inventory as a complete account of live helpers.
    if (loaded && loaded->recovered) throw std::runtime_error("switch runtime primary is damaged; automatic recovery requires the latest inventory");
    if (loaded) document_ = loaded->value;
    else { document_["schema"] = 1; document_["switches"] = Json::Value(Json::arrayValue); }
    if (document_["schema"] != 1 || !document_["switches"].isArray() || document_["switches"].size() > 1024)
        throw std::runtime_error("invalid switch runtime inventory");
    std::set<std::string> names, owners;
    for (const auto& entry : document_["switches"]) {
        if (!entry.isObject() || !entry["name"].isString() || !valid_name(entry["name"].asString()) ||
            !entry["owner"].isString() || entry["owner"].asString().empty() || entry["owner"].asString().size() > 128 ||
            !entry["device"].isUInt64() || !entry["inode"].isUInt64() ||
            (entry["phase"] != "reserved" && entry["phase"] != "owned" && entry["phase"] != "stopped") ||
            !names.insert(entry["name"].asString()).second || !owners.insert(entry["owner"].asString()).second)
            throw std::runtime_error("invalid switch runtime entry");
        if ((entry["phase"] == "reserved") != (entry["inode"].asUInt64() == 0))
            throw std::runtime_error("invalid switch directory identity phase");
    }
}
Json::Value SwitchRuntime::inventory() const { std::lock_guard lock(mutex_); return document_; }
void SwitchRuntime::save(Json::Value next) {
    try { file_.save(next); }
    catch (const config::CommitError& error) { if (error.installed) document_ = std::move(next); throw; }
    document_ = std::move(next);
}
Json::ArrayIndex SwitchRuntime::find(const std::string& name) const {
    for (Json::ArrayIndex i = 0; i < document_["switches"].size(); ++i)
        if (document_["switches"][i]["name"] == name) return i;
    throw ServiceError(ErrorCode::not_found, "switch runtime entry not found");
}
void SwitchRuntime::erase(const std::string& name) {
    std::lock_guard lock(mutex_);
    auto next = document_;
    next["switches"].removeIndex(find(name), nullptr);
    save(std::move(next));
}
void SwitchRuntime::allocate(const std::string& owner, Allocation& allocation) {
    if (!allocation.name.empty() || allocation.directory.get() >= 0) throw std::logic_error("switch allocation is not empty");
    if (owner.empty() || owner.size() > 128 || owner.find('\0') != std::string::npos)
        throw std::invalid_argument("invalid switch runtime owner");
    const auto name = "gv-" + random_id(false);
    {
        std::lock_guard lock(mutex_);
        for (const auto& row : document_["switches"]) if (row["owner"] == owner)
            throw ServiceError(ErrorCode::conflict, "network has unresolved switch resources");
        if (document_["switches"].size() >= 1024) throw ServiceError(ErrorCode::resource_exhausted, "switch runtime inventory full");
        allocation.name = name;
        Json::Value entry;
        entry["name"] = name; entry["owner"] = owner; entry["phase"] = "reserved";
        entry["device"] = Json::UInt64(0); entry["inode"] = Json::UInt64(0);
        auto next = document_; next["switches"].append(entry); save(std::move(next));
    }
    point("switch_reserved");
    if (mkdirat(directory_.get(), name.c_str(), 0700) < 0) {
        const auto error = errno;
        // A reported collision is never a directory this allocation owns.
        erase(name);
        throw std::system_error(error, std::generic_category(), "create reserved switch directory");
    }
    point("switch_created");
    Fd directory(openat(directory_.get(), name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    require(directory.get() >= 0, "open reserved switch directory");
    require(fchown(directory.get(), owner_, owner_) == 0 && fchmod(directory.get(), 0700) == 0, "protect switch directory");
    struct stat identity{};
    require(fstat(directory.get(), &identity) == 0 && fsync(directory_.get()) == 0, "sync switch directory allocation");
    {
        std::lock_guard lock(mutex_);
        auto next = document_; auto& entry = next["switches"][find(name)];
        entry["phase"] = "owned";
        entry["device"] = Json::UInt64(identity.st_dev); entry["inode"] = Json::UInt64(identity.st_ino);
        save(std::move(next)); // no files or child launch before this commit succeeds
    }
    point("switch_owned");
    allocation.directory = std::move(directory);
}
void SwitchRuntime::cleanup(const std::string& name) {
    Json::Value entry;
    {
        std::lock_guard lock(mutex_);
        try { entry = document_["switches"][find(name)]; }
        catch (const ServiceError& error) { if (error.code() == ErrorCode::not_found) return; throw; }
    }
    Fd directory(openat(directory_.get(), name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (directory.get() < 0 && errno == ENOENT && entry["phase"] != "owned") { erase(name); return; }
    require(directory.get() >= 0, "open switch directory for recovery");
    struct stat identity{};
    require(fstat(directory.get(), &identity) == 0, "stat recovery directory");
    if (entry["phase"] == "reserved") {
        // A 128-bit name is durably reserved in our private namespace before
        // mkdir. Before inode commit no files or helper may exist. Remove only
        // an empty private reservation; unknown contents are never traversed.
        if ((identity.st_mode & 0777) != 0700 || (identity.st_uid != owner_ && identity.st_uid != geteuid()))
            throw std::runtime_error("switch reservation permissions changed");
    } else {
        if (entry["device"].asUInt64() != identity.st_dev || entry["inode"].asUInt64() != identity.st_ino || identity.st_uid != owner_)
            throw std::runtime_error("switch runtime directory identity changed");
        if (entry["phase"] == "owned") {
            HelperIdentity::recover(directory.get(), owner_);
            point("switch_process_stopped");
            std::lock_guard lock(mutex_);
            auto next = document_; next["switches"][find(name)]["phase"] = "stopped";
            save(std::move(next)); // permit missing directory only after this durable proof
        }
        // Also reclaim JsonFile's interrupted temporary writes by its existing
        // constructor. It only recognizes exact temporary names and ownership.
        config::JsonFile config(directory.get(), "config.json", owner_);
        config::JsonFile helper(directory.get(), "helper.json", owner_);
        for (const char* file : {"s", "config.json", "config.json.bak", "config.json.corrupt",
                                "helper.json", "helper.json.bak", "helper.json.corrupt", "helper.identity"})
            require(unlinkat(directory.get(), file, 0) == 0 || errno == ENOENT, "remove known switch file");
        point("switch_files_removed");
    }
    struct stat named{};
    require(fstatat(directory_.get(), name.c_str(), &named, AT_SYMLINK_NOFOLLOW) == 0, "recheck switch directory name");
    if (named.st_dev != identity.st_dev || named.st_ino != identity.st_ino || !S_ISDIR(named.st_mode))
        throw std::runtime_error("switch directory replaced during cleanup");
    require(unlinkat(directory_.get(), name.c_str(), AT_REMOVEDIR) == 0, "remove empty switch directory");
    require(fsync(directory_.get()) == 0, "sync switch directory removal");
    point("switch_directory_removed");
    erase(name);
    point("switch_forgotten");
}
Json::Value SwitchRuntime::recover_all() {
    const auto entries = inventory()["switches"];
    Json::Value failures(Json::arrayValue);
    for (const auto& entry : entries) {
        try { cleanup(entry["name"].asString()); }
        catch (const std::exception& error) {
            Json::Value failure; failure["name"] = entry["name"]; failure["owner"] = entry["owner"];
            failure["error"] = std::string(error.what()).substr(0, 4096); failures.append(std::move(failure));
        }
    }
    return failures;
}
}
