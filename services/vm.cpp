// SPDX-License-Identifier: GPL-3.0-or-later
#include "vm.h"
#include "store/network_config.h"
#include "store/vm_config.h"
#include "vm/boot_plan.h"
#include "vm/nic.h"
#include <bit>
#include <regex>
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
VmService::VmService(vm::RuntimeContext context) : context_(std::move(context)) {
    auto flag = shutting_down_;
    auto outer = context_.shutting_down;
    context_.shutting_down = [flag, outer] { return flag->load() || outer(); };
    // KEY_OPTIMIZE_SDCARD through DataItem.optBoolean: only a boolean counts.
    context_.optimize_sdcard = [this] {
        std::lock_guard lock(app_mutex_);
        const auto& value = config::member(app_config_, "optimize_sdcard");
        return value.isBool() ? value.asBool() : true;
    };
    context_.app_config = [this] { return app_config(); };
}
VmService::VmService(int files_directory, vm::RuntimeContext context) : VmService(std::move(context)) {
    try {
        const auto document = parse_strict(read_file(files_directory, "vms.json"));
        const auto& rows = config::member(document, "vms");
        if (!rows.isNull() && !rows.isArray()) throw std::runtime_error("vms is not an array");
        for (const auto& row : rows) {
            if (!row.isObject()) throw std::runtime_error("entry is not an object");
            if (row.isMember("state")) {
                // VMInstance validates a persisted state; a restarted daemon
                // never adopts a running process, so the entry is stopped.
                bool known = false;
                for (const auto* name : state_names) known = known || row["state"] == name;
                if (!known) throw std::runtime_error("invalid state");
            }
            auto config = config::migrate_vm(row);
            add(config::uuid(config), std::move(config));
        }
        loaded_ = entries_.size();
    } catch (const std::exception& error) {
        entries_.clear(); loaded_ = 0; load_error_ = error.what();
    }
}
VmService::~VmService() { try { stop_all(); } catch (...) {} }
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
void VmService::add(const std::string& id, Json::Value config) {
    const auto& name = config::member(config, "name");
    // IllegalArgumentException in DataStore.add: never a legacy business message.
    if (!name.isString()) throw ServiceError(ErrorCode::invalid_argument, "Config name cannot be null");
    for (const auto& other : entries_) {
        if (other.id == id) throw ServiceError(ErrorCode::invalid_argument, "Config ID already exists: " + id);
        if (config::member(other.vm->config(), "name") == name) throw ServiceError(ErrorCode::invalid_argument, "Config name already exists: " + name.asString());
    }
    entries_.push_back({id, std::make_shared<vm::VmRuntime>(id, std::move(config), context_)});
}
Json::Value VmService::list(const CallContext& caller) const {
    access(caller);
    std::lock_guard lock(mutex_);
    Json::Value rows(Json::arrayValue);
    for (const auto& entry : entries_) {
        auto row = entry.vm->config();
        row["state"] = vm_state_name(entry.vm->state());
        row["pid"] = Json::Int64(entry.vm->pid());
        row["streams"] = Json::Value(Json::arrayValue);
        for (const auto& name : entry.vm->streams()) row["streams"].append(name);
        rows.append(std::move(row));
    }
    return rows;
}
Json::Value VmService::get(const CallContext& caller, const std::string& id) const { return runtime(caller, id)->config(); }
bool VmService::exists(const CallContext& caller, const std::string& id) const {
    access(caller);
    std::lock_guard lock(mutex_);
    return find(id) != nullptr;
}
VmState VmService::state(const CallContext& caller, const std::string& id) const { return runtime(caller, id)->state(); }
std::shared_ptr<vm::VmRuntime> VmService::runtime(const CallContext& caller, const std::string& id) const {
    access(caller);
    std::lock_guard lock(mutex_);
    const auto* entry = find(id);
    if (!entry) throw ServiceError(ErrorCode::not_found, "VM not found: " + id);
    return entry->vm;
}
std::string VmService::create(const CallContext& caller, Json::Value value) {
    access(caller);
    auto config = config::migrate_vm(std::move(value));
    const auto id = config::uuid(config); // invalid_argument: legacy internal error
    std::lock_guard lock(mutex_);
    for (const auto& entry : entries_) if (entry.id == id) throw ServiceError(ErrorCode::conflict, "VM " + id + " already exists");
    config["id"] = id;
    add(id, std::move(config));
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
    auto edit = at->vm->try_edit();
    if (!edit) throw ServiceError(ErrorCode::conflict, "VM " + id + " is not stopped, cannot modify");
    config["id"] = id;
    // removeById + add re-appends a rebuilt instance. Unlike the legacy store,
    // a rejected duplicate name restores the previous entry in place.
    const auto index = at - entries_.begin();
    auto previous = std::move(*at);
    entries_.erase(at);
    try { add(id, std::move(config)); }
    catch (...) { entries_.insert(entries_.begin() + index, std::move(previous)); throw; }
    edit.retire();
    return id;
}
bool VmService::remove(const CallContext& caller, const std::string& id) {
    access(caller);
    std::shared_ptr<vm::VmRuntime> target;
    {
        std::lock_guard lock(mutex_);
        const auto* entry = find(id);
        if (!entry) return false;
        target = entry->vm;
    }
    // The legacy check stops the VM and then reports the successful stop as
    // a failure (inverted condition); here a failed stop is the failure.
    if (target->state() != VmState::stopped) {
        if (!target->stop() && target->state() != VmState::stopped) throw ServiceError(ErrorCode::unavailable, "Failed to stop VM: " + id);
        target->shutdown();
        if (target->state() != VmState::stopped) throw ServiceError(ErrorCode::unavailable, "Failed to stop VM: " + id);
    }
    std::lock_guard lock(mutex_);
    // A start may have acquired a reference before removal, or raced the stop
    // above. Never remove an instance whose lifecycle cannot be frozen now.
    auto edit = target->try_edit();
    if (!edit) {
        // Another remover/modify may already have retired precisely this object.
        for (const auto& entry : entries_) if (entry.vm == target)
            throw ServiceError(ErrorCode::conflict, "VM changed while being deleted: " + id);
        return true;
    }
    edit.retire();
    std::erase_if(entries_, [&](const Entry& entry) { return entry.vm == target; });
    return true;
}
std::map<int, network::DhcpStatics> VmService::statics(const Json::Value& network) const {
    std::map<int, network::DhcpStatics> result;
    const auto& vlans = config::member(config::member(network, "l3"), "vlans");
    if (!vlans.isArray()) return result;
    static const std::regex mac_pattern("([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}");
    const auto id = config::uuid(network);
    std::lock_guard lock(mutex_);
    for (const auto& vlan : vlans) {
        if (!vlan.isObject()) continue;
        const int vid = std::bit_cast<int32_t>(static_cast<uint32_t>(config::integer(vlan, "vlan_id")));
        auto& statics = result[vid];
        const auto& ipv4 = config::member(vlan, "ipv4");
        const auto& ipv6 = config::member(vlan, "ipv6");
        const bool dhcp4 = !config::string(ipv4, "cidr").empty() && config::boolean(config::member(ipv4, "dhcp"), "enabled");
        const bool dhcp6 = (config::string(ipv6, "source") == "dhcp_pd" || !config::string(ipv6, "cidr").empty()) &&
            config::boolean(config::member(ipv6, "dhcp"), "enabled");
        for (const auto& entry : entries_) {
            const auto config = entry.vm->config();
            const auto& nics = config::member(config, "networks");
            if (!nics.isArray()) continue;
            for (Json::ArrayIndex i = 0; i < nics.size(); ++i) {
                auto nic = nics[i];
                const auto mac = config::string(nic, "mac_address");
                if (config::string(nic, "network_id") != id || mac.empty()) continue;
                const auto* nic_vlan = vm::nic_dhcp_vlan(nic, network);
                if (!nic_vlan || std::bit_cast<int32_t>(static_cast<uint32_t>(config::integer(*nic_vlan, "vlan_id"))) != vid) continue;
                // bridgedhcp refuses a malformed binding; the legacy push logged it per VM.
                if (!std::regex_match(mac, mac_pattern)) continue;
                for (const bool v6 : {false, true}) {
                    const auto& lease = config::member(nic, v6 ? "dhcp6_lease" : "dhcp4_lease");
                    if (!config::boolean(lease, "enabled") || !(v6 ? dhcp6 : dhcp4)) continue;
                    const auto offset = config::integer(lease, "offset", 64);
                    if (offset <= 0) continue;
                    Json::Value row;
                    row["id"] = entry.id + "-" + std::to_string(i);
                    row["mac"] = mac;
                    row["offset"] = Json::Int64(offset);
                    (v6 ? statics.ipv6 : statics.ipv4).append(std::move(row));
                }
            }
        }
    }
    return result;
}
std::string VmService::running_vm_using(const std::string& network) const {
    std::lock_guard lock(mutex_);
    for (const auto& entry : entries_) {
        if (entry.vm->state() == VmState::stopped) continue;
        const auto config = entry.vm->config();
        const auto& nics = config::member(config, "networks");
        if (nics.isArray()) for (const auto& nic : nics)
            if (config::string(nic, "network_id") == network) return config::string(config, "name");
    }
    return {};
}
std::vector<std::string> VmService::busy_vms_using(const std::string& network) const {
    std::vector<std::string> names;
    std::lock_guard lock(mutex_);
    for (const auto& entry : entries_) {
        const auto config = entry.vm->config();
        const auto& nics = config::member(config, "networks");
        if (!nics.isArray()) continue;
        for (const auto& nic : nics) if (config::string(nic, "network_id") == network) {
            if (entry.vm->state() != VmState::stopped) names.push_back(config::string(config, "name"));
            break;
        }
    }
    return names;
}
void VmService::drop_network(const std::string& network) {
    std::lock_guard lock(mutex_);
    for (const auto& entry : entries_) {
        const auto config = entry.vm->config();
        const auto& nics = config::member(config, "networks");
        if (!nics.isArray()) continue;
        Json::Value kept(Json::arrayValue);
        for (const auto& nic : nics) if (config::string(nic, "network_id") != network) kept.append(nic);
        if (kept.size() == nics.size()) continue;
        entry.vm->set_networks(std::move(kept));
    }
}
Json::Value VmService::vm_by_tap(const std::string& tap) const {
    std::lock_guard lock(mutex_);
    for (const auto& entry : entries_) {
        if (entry.vm->state() == VmState::stopped) continue;
        const auto config = entry.vm->config();
        const auto& nics = config::member(config, "networks");
        if (!nics.isArray()) continue;
        for (const auto& nic : nics) if (config::string(nic, "tap_name") == tap) {
            Json::Value found;
            found["vm_id"] = entry.id; found["vm_name"] = config::string(config, "name");
            return found;
        }
    }
    return {};
}
void VmService::auto_up_async() {
    std::lock_guard lock(sweep_mutex_);
    if (shutting_down_->load() || sweep_.joinable()) return;
    sweep_ = std::thread(&VmService::auto_up, this);
}
void VmService::auto_up() {
    std::vector<std::shared_ptr<vm::VmRuntime>> pending;
    {
        std::lock_guard lock(mutex_);
        for (const auto& entry : entries_)
            if (config::boolean(entry.vm->config(), "auto_up") && entry.vm->state() == VmState::stopped) pending.push_back(entry.vm);
    }
    for (const auto& target : pending) {
        if (shutting_down_->load()) {
            context_.warn("the daemon is going down; abandoning the rest of the auto-start sweep");
            return;
        }
        if (target->state() != VmState::stopped) continue;
        if (!target->start())
            context_.warn("Failed to auto-start VM " + config::string(target->config(), "name") + " [" + target->id() + "]");
    }
}
Json::Value VmService::boot_scan(const CallContext& caller, const std::string& image) const {
    access(caller);
    return vm::scan_boot_entries(context_.lbx, image);
}
void VmService::set_app_config(const CallContext& caller, Json::Value value) {
    access(caller);
    if (!value.isObject()) throw std::invalid_argument("config is not an object");
    {
        std::lock_guard lock(app_mutex_);
        app_config_ = value;
    }
    // The ACM pool is standing state driven by this config; failures only log.
    if (context_.acm) context_.acm->apply_config(value);
}
Json::Value VmService::app_config() const {
    std::lock_guard lock(app_mutex_);
    return app_config_;
}
void VmService::stop_all() {
    shutting_down_->store(true);
    {
        // The sweep reads the flag before each start; one inside start() finishes its handoff.
        std::lock_guard lock(sweep_mutex_);
        if (sweep_.joinable() && sweep_.get_id() != std::this_thread::get_id()) sweep_.join();
    }
    std::vector<std::shared_ptr<vm::VmRuntime>> targets;
    { std::lock_guard lock(mutex_); for (const auto& entry : entries_) targets.push_back(entry.vm); }
    for (auto& target : targets) if (target->state() != VmState::stopped) target->stop();
    for (auto& target : targets) target->shutdown();
    // VMInstanceStore.stopAll ends with clear(); the store accepts no starts afterwards.
    std::lock_guard lock(mutex_);
    entries_.clear();
}
}
