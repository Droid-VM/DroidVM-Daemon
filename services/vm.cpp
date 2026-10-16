// SPDX-License-Identifier: GPL-3.0-or-later
#include "vm.h"
#include "store/network_config.h"
#include "store/vm_config.h"
#include "common/fd.h"
#include <fcntl.h>
#include <unistd.h>
#include <array>
#include <memory>

namespace droidvm {
namespace {
void access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || caller.principal.empty()) throw ServiceError(ErrorCode::permission_denied, "Administrator permission required");
}
constexpr std::array state_names{"STOPPED", "STARTING", "RUNNING", "SUSPENDED", "STOPPING", "REBOOTING"};
std::string read_file(int directory, const char* name) {
    Fd file(openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
    if (file.get() < 0) throw std::runtime_error(errno == ENOENT ? "absent" : "open failed");
    std::string result;
    char buffer[65536];
    for (;;) {
        const auto count = read(file.get(), buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) throw std::runtime_error("read failed");
        if (!count) return result;
        result.append(buffer, static_cast<size_t>(count));
        if (result.size() > (16u << 20)) throw std::runtime_error("file exceeds budget");
    }
}
// org.json rejects duplicate keys; the app's file is never repaired here.
Json::Value parse_strict(const std::string& text) {
    Json::CharReaderBuilder builder;
    builder["rejectDupKeys"] = true; builder["allowComments"] = false; builder["failIfExtra"] = true;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    Json::Value value;
    std::string error;
    if (!reader->parse(text.data(), text.data() + text.size(), &value, &error) || !value.isObject())
        throw std::runtime_error("invalid JSON");
    return value;
}
}
const char* vm_state_name(VmState state) { return state_names[static_cast<size_t>(state)]; }
VmService::VmService(int files_directory) {
    try {
        const auto document = parse_strict(read_file(files_directory, "vms.json"));
        const auto& rows = config::member(document, "vms");
        if (!rows.isNull() && !rows.isArray()) throw std::runtime_error("vms is not an array");
        for (const auto& row : rows) {
            if (!row.isObject()) throw std::runtime_error("entry is not an object");
            Entry entry;
            if (row.isMember("state")) {
                // VMInstance validates a persisted state; a restarted daemon
                // never adopts a running process, so the entry is stopped.
                bool known = false;
                for (const auto* name : state_names) known = known || row["state"] == name;
                if (!known) throw std::runtime_error("invalid state");
            }
            entry.config = config::migrate_vm(row);
            entry.id = config::uuid(entry.config);
            add(std::move(entry));
        }
        loaded_ = entries_.size();
    } catch (const std::exception& error) {
        entries_.clear(); loaded_ = 0; load_error_ = error.what();
    }
}
std::optional<std::string> VmService::canonical(const std::string& id) {
    Json::Value value;
    value["id"] = id;
    try { return config::uuid(value); } catch (const std::invalid_argument&) { return {}; }
}
const VmService::Entry* VmService::find(const std::string& id) const {
    const auto key = canonical(id);
    if (!key) return nullptr;
    for (const auto& entry : entries_) if (entry.id == *key) return &entry;
    return nullptr;
}
void VmService::add(Entry entry) {
    const auto& name = config::member(entry.config, "name");
    // IllegalArgumentException in DataStore.add: never a legacy business message.
    if (!name.isString()) throw ServiceError(ErrorCode::invalid_argument, "Config name cannot be null");
    for (const auto& other : entries_) {
        if (other.id == entry.id) throw ServiceError(ErrorCode::invalid_argument, "Config ID already exists: " + entry.id);
        if (config::member(other.config, "name") == name) throw ServiceError(ErrorCode::invalid_argument, "Config name already exists: " + name.asString());
    }
    entries_.push_back(std::move(entry));
}
Json::Value VmService::list(const CallContext& caller) const {
    access(caller);
    std::lock_guard lock(mutex_);
    Json::Value rows(Json::arrayValue);
    for (const auto& entry : entries_) {
        auto row = entry.config;
        row["state"] = vm_state_name(entry.state);
        row["pid"] = -1;
        row["streams"] = config::vm_streams(entry.config);
        rows.append(std::move(row));
    }
    return rows;
}
Json::Value VmService::get(const CallContext& caller, const std::string& id) const {
    access(caller);
    std::lock_guard lock(mutex_);
    const auto* entry = find(id);
    if (!entry) throw ServiceError(ErrorCode::not_found, "VM not found: " + id);
    return entry->config;
}
bool VmService::exists(const CallContext& caller, const std::string& id) const {
    access(caller);
    std::lock_guard lock(mutex_);
    return find(id) != nullptr;
}
VmState VmService::state(const CallContext& caller, const std::string& id) const {
    access(caller);
    std::lock_guard lock(mutex_);
    const auto* entry = find(id);
    if (!entry) throw ServiceError(ErrorCode::not_found, "VM not found: " + id);
    return entry->state;
}
std::string VmService::create(const CallContext& caller, Json::Value value) {
    access(caller);
    auto config = config::migrate_vm(std::move(value));
    const auto id = config::uuid(config); // invalid_argument: legacy internal error
    std::lock_guard lock(mutex_);
    for (const auto& entry : entries_) if (entry.id == id) throw ServiceError(ErrorCode::conflict, "VM " + id + " already exists");
    config["id"] = id;
    add({id, std::move(config), VmState::stopped});
    return id;
}
std::string VmService::modify(const CallContext& caller, Json::Value value) {
    access(caller);
    auto config = config::migrate_vm(std::move(value));
    const auto id = config::uuid(config);
    std::lock_guard lock(mutex_);
    auto at = entries_.begin();
    while (at != entries_.end() && at->id != id) ++at;
    if (at == entries_.end()) throw ServiceError(ErrorCode::not_found, "VM " + id + " not found");
    if (at->state != VmState::stopped) throw ServiceError(ErrorCode::conflict, "VM " + id + " is not stopped, cannot modify");
    config["id"] = id;
    // removeById + add re-appends the entry. Unlike the legacy store, a
    // rejected duplicate name restores the previous entry in place.
    const auto index = at - entries_.begin();
    auto previous = std::move(*at);
    entries_.erase(at);
    try { add({id, std::move(config), VmState::stopped}); }
    catch (...) { entries_.insert(entries_.begin() + index, std::move(previous)); throw; }
    return id;
}
bool VmService::remove(const CallContext& caller, const std::string& id) {
    access(caller);
    std::lock_guard lock(mutex_);
    const auto key = canonical(id);
    if (!key) return false;
    for (auto at = entries_.begin(); at != entries_.end(); ++at) {
        if (at->id != *key) continue;
        if (at->state != VmState::stopped) throw ServiceError(ErrorCode::unavailable, "Failed to stop VM: " + id);
        entries_.erase(at);
        return true;
    }
    return false;
}
}
