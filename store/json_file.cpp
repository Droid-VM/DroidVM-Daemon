// SPDX-License-Identifier: GPL-3.0-or-later
#include "json_file.h"
#include "common/identity.h"
#include "common/wire.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <cerrno>
#include <memory>
#include <cmath>
#include <system_error>

namespace droidvm::config {
namespace {
void normalize_numbers(Json::Value& value, unsigned depth = 0) {
    if (depth > 64) throw std::invalid_argument("configuration nesting limit exceeded");
    if (value.type() == Json::realValue) {
        double number = value.asDouble();
        if (!std::isfinite(number)) throw std::invalid_argument("non-finite configuration number");
        // Java Number.longValue saturates before JSONObject compares doubles.
        int64_t whole = number >= static_cast<double>(INT64_MAX) ? INT64_MAX :
                        number <= static_cast<double>(INT64_MIN) ? INT64_MIN : static_cast<int64_t>(number);
        if (number == static_cast<double>(whole)) value = Json::Int64(whole);
    } else if (value.isArray() || value.isObject()) {
        for (auto& child : value) normalize_numbers(child, depth + 1);
    }
}
void require(bool result, const char* operation) {
    if (!result) throw std::system_error(errno, std::generic_category(), operation);
}
Json::Value parse(std::string_view bytes) {
    Json::CharReaderBuilder builder;
    builder["failIfExtra"] = true;
    builder["stackLimit"] = 64;
    std::unique_ptr<Json::CharReader> parser(builder.newCharReader());
    Json::Value result;
    std::string error;
    bool parsed = false;
    try { parsed = parser->parse(bytes.data(), bytes.data() + bytes.size(), &result, &error); }
    catch (const Json::Exception&) { throw std::invalid_argument("invalid configuration JSON object"); }
    if (!parsed || !result.isObject())
        throw std::invalid_argument("invalid configuration JSON object");
    return result;
}
}
std::string encode_json(const Json::Value& value, size_t max_bytes) {
    auto normalized = value;
    normalize_numbers(normalized);
    return wire::stringify_bounded(normalized, max_bytes);
}
JsonFile::JsonFile(int directory, std::string name, uid_t owner, Observer observer)
    : directory_(fcntl(directory, F_DUPFD_CLOEXEC, 3)), name_(std::move(name)), owner_(owner), observer_(std::move(observer)) {
    require(directory_.get() >= 0, "duplicate configuration directory");
    if (name_.empty() || name_.size() > 128 || name_.front() == '.' || name_.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789_.-") != std::string::npos)
        throw std::invalid_argument("invalid configuration filename");
    // The owning service has the instance lock: no live transaction can own
    // these exact temporary names. Reclaim leftovers from interrupted saves.
    int scan_fd = openat(directory_.get(), ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(scan_fd >= 0, "open configuration scan");
    DIR* scan = fdopendir(scan_fd);
    if (!scan) { close(scan_fd); require(false, "scan configuration temporaries"); }
    bool changed = false;
    const auto prefix = "." + name_ + ".";
    while (auto* entry = readdir(scan)) {
        std::string_view candidate(entry->d_name);
        if (!candidate.starts_with(prefix) || !candidate.ends_with(".tmp") || candidate.size() != prefix.size() + 36) continue;
        auto nonce = candidate.substr(prefix.size(), 32);
        if (nonce.find_first_not_of("0123456789abcdef") != std::string_view::npos) continue;
        struct stat info{};
        if (fstatat(directory_.get(), entry->d_name, &info, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(info.st_mode) && info.st_nlink == 1 &&
            (info.st_uid == owner_ || info.st_uid == geteuid())) {
            if (unlinkat(directory_.get(), entry->d_name, 0) == 0) changed = true;
        }
    }
    closedir(scan);
    if (changed) require(fsync(directory_.get()) == 0, "sync temporary recovery");
}
JsonFile::Read JsonFile::read(const std::string& name) {
    Fd file(openat(directory_.get(), name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (file.get() < 0 && errno == ENOENT) return {};
    require(file.get() >= 0, "open configuration");
    struct stat info{};
    require(fstat(file.get(), &info) == 0, "stat configuration");
    if (!S_ISREG(info.st_mode) || info.st_nlink != 1)
        throw std::runtime_error("configuration must be a single-link regular file");
    if (info.st_size < 0 || static_cast<uint64_t>(info.st_size) > max_bytes) return {std::nullopt, true};
    std::string bytes(static_cast<size_t>(info.st_size), '\0');
    size_t offset = 0;
    while (offset < bytes.size()) {
        auto count = ::read(file.get(), bytes.data() + offset, bytes.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        require(count >= 0, "read configuration");
        if (!count) return {std::nullopt, true};
        offset += static_cast<size_t>(count);
    }
    char extra;
    ssize_t count;
    do { count = ::read(file.get(), &extra, 1); } while (count < 0 && errno == EINTR);
    require(count >= 0, "read configuration tail");
    if (count) return {std::nullopt, true};
    return {std::move(bytes), false};
}
std::optional<LoadedJson> JsonFile::load_unlocked(Read* primary) {
    auto current = read(name_);
    if (current.bytes) {
        try {
            auto value = parse(*current.bytes);
            if (primary) *primary = std::move(current);
            return LoadedJson{std::move(value), false};
        } catch (const std::invalid_argument&) { current.corrupt = true; }
    }
    auto backup = read(name_ + ".bak");
    if (primary) *primary = current;
    if (backup.bytes) return LoadedJson{parse(*backup.bytes), true};
    if (current.corrupt || backup.corrupt) throw std::runtime_error("configuration and recovery copy are unavailable");
    return std::nullopt;
}
std::optional<LoadedJson> JsonFile::load() {
    std::lock_guard guard(mutex_);
    return load_unlocked();
}
std::string JsonFile::temporary(std::string_view bytes) {
    std::string name = "." + name_ + "." + random_id(false) + ".tmp";
    Fd file(openat(directory_.get(), name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
    require(file.get() >= 0, "create configuration temporary");
    try {
        require(fchown(file.get(), owner_, owner_) == 0 && fchmod(file.get(), 0600) == 0, "protect configuration");
        while (!bytes.empty()) {
            auto count = ::write(file.get(), bytes.data(), bytes.size());
            if (count < 0 && errno == EINTR) continue;
            require(count > 0, "write configuration temporary");
            bytes.remove_prefix(static_cast<size_t>(count));
        }
        require(fsync(file.get()) == 0, "sync configuration temporary");
    } catch (...) { unlinkat(directory_.get(), name.c_str(), 0); throw; }
    return name;
}
void JsonFile::save(const Json::Value& value) {
    // Encoding limits and schema-independent JSON validity are checked before IO.
    if (!value.isObject()) throw std::invalid_argument("configuration must be an object");
    auto bytes = encode_json(value, max_bytes);
    parse(bytes);
    std::lock_guard guard(mutex_);
    Read primary;
    auto previous = load_unlocked(&primary);
    std::string pending, backup;
    bool installed = false;
    try {
        point("before_write");
        pending = temporary(bytes);
        point("value_synced");
        if (previous && !previous->recovered) {
            backup = temporary(*primary.bytes);
            require(renameat(directory_.get(), backup.c_str(), directory_.get(), (name_ + ".bak").c_str()) == 0, "install configuration backup");
            backup.clear();
            require(fsync(directory_.get()) == 0, "sync configuration backup");
        }
        point("backup_synced");
        if (primary.corrupt) {
            // Keep one damaged primary as evidence. Never replace the valid
            // backup with bytes that failed parsing (including oversized files).
            require(renameat(directory_.get(), name_.c_str(), directory_.get(), (name_ + ".corrupt").c_str()) == 0, "retain corrupt configuration");
            require(fsync(directory_.get()) == 0, "sync corrupt configuration evidence");
        }
        point("before_install");
        require(renameat(directory_.get(), pending.c_str(), directory_.get(), name_.c_str()) == 0, "install configuration");
        pending.clear();
        installed = true;
        point("installed");
        require(fsync(directory_.get()) == 0, "sync configuration directory");
    } catch (const std::exception& error) {
        if (!pending.empty()) unlinkat(directory_.get(), pending.c_str(), 0);
        if (!backup.empty()) unlinkat(directory_.get(), backup.c_str(), 0);
        throw CommitError(error.what(), installed);
    }
}
}
