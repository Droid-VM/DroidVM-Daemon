// SPDX-License-Identifier: GPL-3.0-or-later
#include "configuration.h"
#include "vm.h"
#include "network.h"
#include "tasks.h"
#include "common/identity.h"
#include "store/network_config.h"
#include "store/disk_config.h"
#include "store/vm_ownership.h"
#include "vm/command_common.h"
#include "pkg/plan.h"
#include <map>
#include <set>

namespace droidvm {
namespace {
void access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || caller.principal.empty()) throw ServiceError(ErrorCode::permission_denied, "Administrator permission required");
}
bool references(const Json::Value& nic, const std::string& id) {
    if (!nic.isObject() || !nic["network_id"].isString()) return false;
    Json::Value target; target["id"] = nic["network_id"];
    try { return config::uuid(target) == id; } catch (const std::invalid_argument&) { return false; }
}
}
ConfigurationService::ConfigurationService(int directory, uid_t owner, std::shared_ptr<ConfigurationGate> gate,
        VmService& inventory, TaskService& events, config::ConfigTransaction::Observer observer, bool manage_disks)
    : gate_(std::move(gate)), inventory_(inventory), events_(events) {
    if (!gate_ || inventory.context_.configuration_gate != gate_ || events.config_gate_ != gate_)
        throw std::invalid_argument("Configuration participants must share one gate");
    auto exclusive = gate_->transaction();
    exclusive.require_available();
    {
        std::lock_guard lock(inventory.mutex_);
        if (inventory.config_managed_ || !inventory.entries_.empty())
            throw std::invalid_argument("Configuration must attach before inventory loading");
    }
    // Any failed construction leaves startup unavailable. Never expose services
    // loaded from just one side of an interrupted transaction.
    exclusive.require_recovery();
    config::claim_vm_config(directory, owner);
    config::claim_network_config(directory, owner);
    if (manage_disks) config::claim_disk_config(directory, owner);
    auto targets = std::vector<std::string>{"vms.json", "networks.json"};
    if (manage_disks) targets.push_back("disks.json");
    journal_ = std::make_unique<config::ConfigTransaction>(directory, owner, std::move(observer),
        std::move(targets));
    networks_ = std::make_unique<NetworkConfigService>(directory, owner, config::JsonFile::Observer{}, &events, true, gate_);
    if (manage_disks) {
        inventory.context_.validate_start = std::make_shared<std::function<void(const Json::Value&)>>();
        inventory.context_.acquire_disks = std::make_shared<vm::RuntimeContext::AcquireDisks>();
        inventory.context_.validate_disks = std::make_shared<vm::RuntimeContext::ValidateDisks>();
        disk_files_ = std::make_shared<config::DiskFileLeases>();
    }
    vms_ = std::make_shared<VmConfigService>(directory, owner, config::JsonFile::Observer{},
        [&inventory](const Json::Value& document) { return inventory.prepare_config(document); }, &events, gate_);
    if (manage_disks) {
        disks_ = std::make_shared<DiskConfigService>(directory, owner, config::JsonFile::Observer{}, gate_,
            [this](const Json::Value& before, const Json::Value& after) -> std::unique_ptr<ConfigurationCommit> {
                validate_disk_change(before, after);
                return {};
            }, &events);
        disks_->coordinated_ = true;
        *inventory.context_.validate_start = [vms = std::weak_ptr<VmConfigService>(vms_), disks = std::weak_ptr<DiskConfigService>(disks_)](const Json::Value& vm) {
            const auto vm_service = vms.lock(); const auto disk_service = disks.lock();
            if (!vm_service || !disk_service) throw std::runtime_error("Configuration owner is unavailable");
            const CallContext internal{"vm-start-validation", true, true, true};
            config::validate_disk_start(vm, vm_service->snapshot(internal)->document, disk_service->snapshot(internal)->document);
        };
        *inventory.context_.acquire_disks = [disks = std::weak_ptr<DiskConfigService>(disks_), files = disk_files_](const Json::Value& vm) {
            const auto service = disks.lock();
            if (!service) throw std::runtime_error("Disk configuration owner is unavailable");
            const CallContext internal{"vm-disk-leases", true, true, true};
            return files->acquire(config::disk_start_files(vm, service->snapshot(internal)->document));
        };
        vm::HostFacts host; host.data_dir = inventory.context_.data_dir;
        const auto tool = vm::command::data_dir(host) + "/usr/bin/qemu-img";
        *inventory.context_.validate_disks = [disks = std::weak_ptr<DiskConfigService>(disks_), tool](
                const Json::Value& vm, const config::DiskFileLeases::Lease& lease, const std::function<bool()>& cancelled) {
            const auto service = disks.lock();
            if (!service) throw std::runtime_error("Disk configuration owner is unavailable");
            const CallContext internal{"vm-image-validation", true, true, true};
            const auto parents = config::disk_start_parents(vm, service->snapshot(internal)->document);
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
            vm::RuntimeContext::DiskImages images;
            for (const auto& [path, parent] : parents) {
                const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
                if (cancelled() || remaining.count() <= 0) throw std::runtime_error("Disk image validation cancelled or timed out");
                images.emplace(path, pkg::Images(tool, cancelled, remaining).validate_backing(lease, path, parent));
            }
            lease.verify();
            return images;
        };
    }
    networks_->coordinated_removal_ = true;
    vms_->validate_change_ = [this](const Json::Value& before, const Json::Value& after) {
        validate_vm_networks(before, after);
        if (disks_) validate_vm_disks(before, after);
    };
    exclusive.recovered();
}
bool ConfigurationService::recovery_required() const {
    return gate_->recovery_required() || networks_->state()->durability_uncertain;
}
ConfigurationService::Snapshot ConfigurationService::snapshot(const CallContext& caller) const {
    access(caller);
    if (!disks_) throw ServiceError(ErrorCode::unavailable, "Disk configuration is unavailable");
    auto admission = ConfigurationGate::enter(gate_);
    std::lock_guard vm_writer(vms_->writer_mutex_);
    std::lock_guard network_writer(networks_->writer_mutex_);
    std::lock_guard disk_writer(disks_->writer_mutex_);
    const auto networks = networks_->state();
    return {vms_->state(), disks_->state(), {networks->document, networks->revision}};
}
void ConfigurationService::with_unreferenced_disk_path(const CallContext& caller, const std::string& path,
        const std::function<void()>& publish) {
    access(caller);
    if (!disks_) throw ServiceError(ErrorCode::unavailable, "Disk configuration is unavailable");
    if (!publish || path.empty() || path.front() != '/' || path.size() > 4096 || path.find('\0') != std::string::npos)
        throw ServiceError(ErrorCode::invalid_argument, "Invalid image publication target");
    auto exclusive = gate_->transaction(); exclusive.require_available();
    std::lock_guard vm_writer(vms_->writer_mutex_);
    std::lock_guard disk_writer(disks_->writer_mutex_);
    const auto target = pkg::canonical_path(path);
    const auto reject_reference = [&](const std::string& reference) {
        if (!reference.empty() && (reference == path || pkg::canonical_path(reference) == target))
            throw ServiceError(ErrorCode::conflict, "Image target is already referenced by a disk or virtual machine");
    };
    const auto disks = disks_->state();
    for (const auto& row : disks->document["disks"]) reject_reference(config::disk_path(row));
    const auto vms = vms_->state();
    for (const auto& vm : vms->document["vms"]) {
        const auto& slots = config::member(vm, "disks");
        if (slots.isArray()) for (const auto& slot : slots) reject_reference(config::string(slot, "path"));
    }
    publish();
}
void ConfigurationService::validate_vm_disks(const Json::Value& before, const Json::Value& after) const {
    const auto registry = disks_->state();
    validate_vm_disks(before, after, registry->document, registry->document);
}
void ConfigurationService::validate_vm_disks(const Json::Value& before, const Json::Value& after,
        const Json::Value& old_disks, const Json::Value& new_disks, const void* owner) const {
    check_reference_reservations(before, after, owner);
    const auto old_paths = config::valid_disk_paths(old_disks), new_paths = config::valid_disk_paths(new_disks);
    const auto old_readonly = config::disk_references(before, old_disks), new_readonly = config::disk_references(after, new_disks);
    auto unresolved = [&](const Json::Value& slot, const auto& paths, const auto& readonly) {
        const auto& path = config::member(slot, "path");
        if (path.isNull() || (path.isString() && path.asString().empty())) return false;
        return !path.isString() || !paths.contains(path.asString())
            || ((readonly.bases.contains(path.asString()) || readonly.holders.at(path.asString()) > 1)
                && !config::boolean(slot, "readonly"));
    };
    auto not_worse = [&](const Json::Value& slot) {
        const auto path = config::string(slot, "path");
        const auto old_count = old_readonly.holders.find(path), new_count = new_readonly.holders.find(path);
        return (!old_paths.contains(path) || new_paths.contains(path))
            && (!new_readonly.bases.contains(path) || old_readonly.bases.contains(path))
            && (new_count == new_readonly.holders.end() || (old_count != old_readonly.holders.end() && new_count->second <= old_count->second));
    };
    std::map<std::string, std::multiset<Json::Value>> historical;
    for (const auto& vm : before["vms"]) {
        const auto& slots = config::member(vm, "disks");
        if (slots.isArray()) for (const auto& slot : slots) if (unresolved(slot, old_paths, old_readonly))
            historical[config::uuid(vm)].insert(slot);
    }
    for (const auto& vm : after["vms"]) {
        const auto& slots = config::member(vm, "disks");
        if (!slots.isArray()) continue;
        auto& allowed = historical[config::uuid(vm)];
        for (const auto& slot : slots) if (unresolved(slot, new_paths, new_readonly)) {
            const auto found = allowed.find(slot);
            if (found == allowed.end() || !not_worse(slot))
                throw ServiceError(ErrorCode::conflict, "VM disk reference is unresolved or requires read-only access; reload disks before saving");
            allowed.erase(found);
        }
    }
}
void ConfigurationService::validate_disk_change(const Json::Value& before, const Json::Value& after) const {
    try { config::validate_disk_transition(before, after); }
    catch (const std::invalid_argument& error) { throw ServiceError(ErrorCode::conflict, error.what()); }
    check_reservations(before, after, nullptr);
    // Disk writes hold the exclusive gate, so no VM writer/start can pass this
    // check concurrently. Registry-only uploads cannot detach referenced images
    // or alter a referenced row's metadata; those require a coordinated operation.
    const auto vms = vms_->state();
    std::set<std::string> referenced;
    for (const auto& vm : vms->document["vms"]) {
        const auto& slots = config::member(vm, "disks");
        if (slots.isArray()) for (const auto& slot : slots) {
            const auto& path = config::member(slot, "path");
            if (path.isString() && !path.asString().empty()) referenced.insert(path.asString());
        }
    }
    std::map<std::string, Json::Value> old_rows, new_rows;
    for (const auto& row : before["disks"]) old_rows.emplace(config::uuid(row), row);
    for (const auto& row : after["disks"]) new_rows.emplace(config::uuid(row), row);
    auto protected_relatives = [&](const auto& rows) {
        std::map<std::string, std::vector<std::string>> children;
        std::map<std::string, std::string> parents;
        std::vector<std::string> queue;
        std::set<std::string> visited, descendants;
        for (const auto& [id, row] : rows) {
            if (referenced.contains(config::disk_path(row))) { queue.push_back(id); visited.insert(id); }
            Json::Value parent; parent["id"] = config::member(row, "parent");
            try {
                const auto target = config::uuid(parent);
                children[target].push_back(id); parents.emplace(id, target);
            }
            catch (const std::invalid_argument&) {}
        }
        std::set<std::string> ancestors_seen;
        for (const auto& seed : queue) {
            auto id = seed;
            while (ancestors_seen.insert(id).second) {
                const auto parent = parents.find(id);
                if (parent == parents.end()) break;
                id = parent->second; descendants.insert(id);
            }
        }
        for (size_t i = 0; i < queue.size(); ++i) {
            const auto found = children.find(queue[i]);
            if (found == children.end()) continue;
            for (const auto& child : found->second) {
                descendants.insert(child);
                if (visited.insert(child).second) queue.push_back(child);
            }
        }
        return descendants;
    };
    const auto old_protected = protected_relatives(old_rows), new_protected = protected_relatives(new_rows);
    for (const auto& [id, row] : old_rows) {
        const auto next = new_rows.find(id);
        if ((referenced.contains(config::disk_path(row)) || old_protected.contains(id))
                && (next == new_rows.end() || next->second != row))
            throw ServiceError(ErrorCode::conflict, "Referenced disk requires a coordinated update");
    }
    for (const auto& [id, row] : new_rows) {
        const auto old = old_rows.find(id);
        if (new_protected.contains(id) && (old == old_rows.end() || old->second != row))
            throw ServiceError(ErrorCode::conflict, "Changing ancestry or descendants of a referenced disk requires a coordinated update");
    }
}
void ConfigurationService::validate_vm_networks(const Json::Value& before, const Json::Value& after,
        const NetworkConfigService::State* projected) const {
    // Caller holds VM writer + admission. Deletion must drain that admission;
    // all other network writes preserve existing IDs. Do not re-enter the gate
    // or take network writer/inventory locks here (a transaction may be draining).
    const auto observed = networks_->state();
    const auto* networks = projected ? projected : observed.get();
    auto unresolved = [&](const Json::Value& nic) {
        const auto& value = config::member(nic, "network_id");
        if (value.isNull() || (value.isString() && value.asString().empty())) return false;
        Json::Value identity; identity["id"] = value;
        try { return !networks->ids.contains(config::uuid(identity)); }
        catch (const std::invalid_argument&) { return true; }
    };
    // Preserve historical unresolved NICs only in their original VM, with exact
    // content and multiplicity. Repair/removal and unrelated edits remain possible;
    // copying, retargeting or editing an unresolved NIC requires a live network.
    std::map<std::string, std::multiset<Json::Value>> historical;
    for (const auto& vm : before["vms"]) {
        const auto& nics = config::member(vm, "networks");
        if (!nics.isArray()) continue;
        for (const auto& nic : nics) if (unresolved(nic))
            historical[config::uuid(vm)].insert(nic);
    }
    for (const auto& vm : after["vms"]) {
        const auto& nics = config::member(vm, "networks");
        if (!nics.isArray()) continue;
        auto& allowed = historical[config::uuid(vm)];
        for (const auto& nic : nics) if (unresolved(nic)) {
            const auto found = allowed.find(nic);
            if (found == allowed.end())
                throw ServiceError(ErrorCode::conflict, "VM network reference is missing or inactive; reload networks before saving");
            allowed.erase(found);
        }
    }
}
void ConfigurationService::publish_pending() {
    if (pending_vm_) vms_->publish(pending_vm_);
    if (pending_network_) networks_->publish(pending_network_);
    if (pending_disk_) disks_->publish(pending_disk_);
}
VmConfigService::Snapshot ConfigurationService::remove_network(const CallContext& caller, const std::string& vm_revision,
        const Json::Value& expected_network, NetworkService* lifecycle) {
    access(caller);
    if (lifecycle && &lifecycle->configs_ != networks_.get())
        throw ServiceError(ErrorCode::invalid_argument, "Network lifecycle configuration does not match");
    if (vm_revision.empty() || vm_revision.size() > 128 || !expected_network.isObject())
        throw ServiceError(ErrorCode::invalid_argument, "Configuration confirmation is required");
    std::string id;
    try { id = config::uuid(expected_network); }
    catch (const std::invalid_argument&) { throw ServiceError(ErrorCode::invalid_argument, "Invalid network confirmation"); }
    auto exclusive = gate_->transaction();
    exclusive.require_available();
    std::lock_guard vm_writer(vms_->writer_mutex_);
    std::lock_guard network_writer(networks_->writer_mutex_);
    const auto vm_before = vms_->state();
    const auto network_before = networks_->state();
    if (vm_before->revision != vm_revision) throw ServiceError(ErrorCode::conflict, "VM configuration changed; reload before deleting");
    const auto found = network_before->ids.find(id);
    if (found == network_before->ids.end()) throw ServiceError(ErrorCode::not_found, "Network not found");
    if (network_before->document["networks"][found->second] != expected_network)
        throw ServiceError(ErrorCode::conflict, "Network configuration changed; reload before deleting");
    if (!lifecycle) networks_->require_stopped(id);
    auto vm_next = std::make_shared<VmConfigSnapshot>();
    vm_next->document = vm_before->document;
    for (auto& vm : vm_next->document["vms"]) {
        const auto& nics = config::member(vm, "networks");
        if (!nics.isArray()) continue;
        Json::Value kept(Json::arrayValue);
        for (const auto& nic : nics) if (!references(nic, id)) kept.append(nic);
        if (kept.size() != nics.size()) vm["networks"] = std::move(kept);
    }
    const auto encoded = config::encode_json(vm_next->document, VmConfigService::max_bytes);
    vm_next->encoded = std::make_shared<const std::string>(encoded.data(), encoded.size());
    vm_next->revision = random_id(true); vm_next->persisted = true;
    auto network_document = network_before->document;
    Json::Value kept(Json::arrayValue);
    for (Json::ArrayIndex i = 0; i < network_document["networks"].size(); ++i)
        if (i != found->second) kept.append(network_document["networks"][i]);
    network_document["networks"] = std::move(kept);
    auto network_next = networks_->decode(std::move(network_document), false);
    // Freeze all changed VM runtimes and allocate their replacements before IO.
    auto runtime = vms_->prepare_(vm_next->document);
    const std::vector<config::ConfigTransaction::Update> updates{
        {"vms.json", vm_next->document}, {"networks.json", network_next->document}};
    // Admission is drained, all target comparisons passed, changed VMs are
    // frozen and all replacements are prepared. No concurrent network start or
    // watchdog can run between cleanup and the durable decision.
    if (lifecycle) lifecycle->stop_for_delete(id);
    networks_->require_stopped(id);
    pending_vm_ = vm_next; pending_network_ = network_next;
    commit_pending(updates, *runtime, exclusive);
    return vm_next;
}
void ConfigurationService::commit_pending(const std::vector<config::ConfigTransaction::Update>& updates,
        ConfigurationCommit& runtime, ConfigurationGate::Transaction& exclusive) {
    exclusive.require_recovery();
    try { journal_->commit(updates); }
    catch (const config::TransactionError& error) {
        if (!error.decided) {
            pending_vm_.reset(); pending_network_.reset(); pending_disk_.reset();
            // Staging cleanup can itself have failed. Only reopen the gate after
            // the journal confirms no unresolved intent or leftovers remain.
            try { journal_->recover(); exclusive.recovered(); } catch (...) {}
            throw ServiceError(ErrorCode::io_error, "Configuration transaction was not committed");
        }
        if (pending_vm_) pending_vm_->durability_uncertain = true;
        if (pending_network_) pending_network_->durability_uncertain = true;
        if (pending_disk_) pending_disk_->durability_uncertain = true;
        runtime.commit(); // Retire old handles; gate forbids new starts until redo.
        publish_pending();
        throw ServiceError(ErrorCode::commit_uncertain, "Configuration transaction requires recovery before further access");
    }
    runtime.commit();
    publish_pending();
    pending_vm_.reset(); pending_network_.reset(); pending_disk_.reset();
    exclusive.recovered();
}
namespace {
std::map<std::string, Json::Value> disk_rows(const Json::Value& document) {
    std::map<std::string, Json::Value> rows;
    for (const auto& row : document["disks"]) {
        try { rows.emplace(config::uuid(row), row); } catch (const std::invalid_argument&) {}
    }
    return rows;
}
}
void ConfigurationService::check_reservations(const Json::Value& before, const Json::Value& after, const void* owner) const {
    std::lock_guard lock(reservation_state_->mutex);
    const auto& reservations_ = reservation_state_->rows;
    if (reservations_.empty()) return;
    const auto old_rows = disk_rows(before), new_rows = disk_rows(after);
    for (const auto& [id, held] : reservations_) {
        const bool foreign = (held.writer && held.writer != owner)
            || std::any_of(held.readers.begin(), held.readers.end(), [&](const auto& reader) { return reader.first != owner; });
        if (!foreign) continue;
        const auto old_row = old_rows.find(id), new_row = new_rows.find(id);
        if (old_row != old_rows.end() && (new_row == new_rows.end() || new_row->second != old_row->second))
            throw ServiceError(ErrorCode::conflict, "A disk operation is using this disk; wait for it to finish");
    }
    for (const auto& [id, row] : new_rows) {
        const auto old_row = old_rows.find(id);
        if (old_row != old_rows.end() && old_row->second == row) continue;
        const auto& parent = config::member(row, "parent");
        if (!parent.isString()) continue;
        const auto held = reservations_.find(parent.asString());
        if (held != reservations_.end() && held->second.writer && held->second.writer != owner)
            throw ServiceError(ErrorCode::conflict, "A disk operation is rewriting the parent disk; wait for it to finish");
    }
}
void ConfigurationService::check_reference_reservations(const Json::Value& before, const Json::Value& after, const void* owner) const {
    const auto references = [](const Json::Value& document, const std::set<std::string>& paths) {
        Json::Value result(Json::objectValue);
        for (const auto& vm : document["vms"]) {
            const auto& slots = config::member(vm, "disks");
            if (!slots.isArray()) continue;
            for (Json::ArrayIndex i = 0; i < slots.size(); ++i) {
                if (!paths.contains(config::string(slots[i], "path"))) continue;
                Json::Value entry; entry["index"] = i; entry["slot"] = slots[i];
                result[config::uuid(vm)].append(std::move(entry));
            }
        }
        return result;
    };
    std::lock_guard lock(reservation_state_->mutex);
    for (const auto& [holder, paths] : reservation_state_->references)
        if (holder != owner && references(before, paths) != references(after, paths))
            throw ServiceError(ErrorCode::conflict, "A disk operation protects these VM attachments; wait for it to finish");
}
ConfigurationService::DiskReservation ConfigurationService::reserve_disks(const std::string& disk_revision,
        const std::set<std::string>& exclusive, const std::set<std::string>& shared, const std::string& vm_revision) {
    if (!disks_) throw ServiceError(ErrorCode::unavailable, "Disk coordination is not enabled");
    // Exclusive admission orders this against registry commits: a reservation
    // either sees the committed revision or blocks the later edit.
    auto transaction = gate_->transaction(); transaction.require_available();
    std::lock_guard disk_writer(disks_->writer_mutex_);
    if (disks_->state()->revision != disk_revision)
        throw ServiceError(ErrorCode::conflict, "Disk configuration changed; reload before starting the operation");
    if (!vm_revision.empty() && vms_->state()->revision != vm_revision)
        throw ServiceError(ErrorCode::conflict, "VM references changed; reload before starting the operation");
    struct Holder {
        std::shared_ptr<ReservationState> state;
        std::set<std::string> exclusive, shared;
        ~Holder() {
            std::lock_guard lock(state->mutex);
            state->references.erase(this);
            for (const auto& id : exclusive) {
                auto found = state->rows.find(id);
                if (found == state->rows.end()) continue;
                if (found->second.writer == this) found->second.writer = nullptr;
                if (!found->second.writer && found->second.readers.empty()) state->rows.erase(found);
            }
            for (const auto& id : shared) {
                auto found = state->rows.find(id);
                if (found == state->rows.end()) continue;
                auto reader = found->second.readers.find(this);
                if (reader != found->second.readers.end() && !--reader->second) found->second.readers.erase(reader);
                if (!found->second.writer && found->second.readers.empty()) state->rows.erase(found);
            }
        }
    };
    auto holder = std::make_shared<Holder>();
    holder->state = reservation_state_;
    std::lock_guard lock(reservation_state_->mutex);
    auto& reservations_ = reservation_state_->rows;
    for (const auto& id : exclusive) {
        const auto found = reservations_.find(id);
        if (shared.contains(id) || (found != reservations_.end() && (found->second.writer || !found->second.readers.empty())))
            throw ServiceError(ErrorCode::conflict, "Another disk operation is using this disk");
    }
    for (const auto& id : shared) {
        const auto found = reservations_.find(id);
        if (found != reservations_.end() && found->second.writer)
            throw ServiceError(ErrorCode::conflict, "Another disk operation is rewriting this disk");
    }
    // No allocation failure may leave a partial reservation behind. The holder
    // is released after this lock if publication fails.
    holder->exclusive = exclusive; holder->shared = shared;
    auto next = reservations_;
    for (const auto& id : exclusive) next[id].writer = holder.get();
    for (const auto& id : shared) ++next[id].readers[holder.get()];
    if (!vm_revision.empty()) {
        std::set<std::string> paths;
        for (const auto& row : disks_->state()->document["disks"])
            if (exclusive.contains(config::uuid(row)) || shared.contains(config::uuid(row))) paths.insert(config::disk_path(row));
        reservation_state_->references.emplace(holder.get(), std::move(paths));
    }
    reservations_.swap(next);
    return holder;
}
ConfigurationService::VmDiskResult ConfigurationService::replace_vm_disks(const CallContext& caller,
        const std::string& vm_revision, const std::string& disk_revision, Json::Value vms, Json::Value disks) {
    return replace_vm_disks(caller, vm_revision, disk_revision, std::move(vms), std::move(disks), nullptr);
}
ConfigurationService::VmDiskResult ConfigurationService::replace_vm_disks(const CallContext& caller,
        const std::string& vm_revision, const std::string& disk_revision, Json::Value vms, Json::Value disks,
        const DiskReservation& owner) {
    return replace_vm_disks_impl(caller, vm_revision, disk_revision, std::move(vms), std::move(disks), owner, {}, nullptr);
}
ConfigurationService::VmDiskResult ConfigurationService::import_vm_disks_networks(const CallContext& caller,
        const std::string& vm_revision, const std::string& disk_revision, const std::string& network_revision,
        Json::Value vm, Json::Value disks, Json::Value added_networks) {
    access(caller);
    if (network_revision.empty() || network_revision.size() > 128 || !vm.isObject()
        || !added_networks.isArray() || added_networks.size() > 1024)
        throw ServiceError(ErrorCode::invalid_argument, "Invalid package configuration import");
    auto current = vms_->snapshot(caller);
    if (current->revision != vm_revision)
        throw ServiceError(ErrorCode::conflict, "VM configuration changed before import");
    auto document = current->document;
    document["vms"].append(std::move(vm));
    return replace_vm_disks_impl(caller, vm_revision, disk_revision, std::move(document), std::move(disks),
        nullptr, network_revision, &added_networks);
}
ConfigurationService::VmDiskResult ConfigurationService::replace_vm_disks_impl(const CallContext& caller,
        const std::string& vm_revision, const std::string& disk_revision, Json::Value vms, Json::Value disks,
        const DiskReservation& owner, const std::string& network_revision, const Json::Value* added_networks) {
    access(caller);
    if (!disks_) throw ServiceError(ErrorCode::unavailable, "Disk coordination is not enabled");
    if (vm_revision.empty() || vm_revision.size() > 128 || disk_revision.empty() || disk_revision.size() > 128)
        throw ServiceError(ErrorCode::invalid_argument, "VM and disk revisions are required");
    auto exclusive = gate_->transaction(); exclusive.require_available();
    std::lock_guard vm_writer(vms_->writer_mutex_);
    std::unique_lock<std::mutex> network_writer;
    if (added_networks) network_writer = std::unique_lock(networks_->writer_mutex_);
    std::lock_guard disk_writer(disks_->writer_mutex_);
    const auto vm_before = vms_->state(); const auto disk_before = disks_->state();
    if (vm_before->revision != vm_revision || disk_before->revision != disk_revision)
        throw ServiceError(ErrorCode::conflict, "VM or disk configuration changed; reload before applying the operation");
    auto vm_next = std::make_shared<VmConfigSnapshot>();
    auto disk_next = std::make_shared<DiskConfigSnapshot>();
    vm_next->document = VmConfigService::normalize(std::move(vms));
    disk_next->document = DiskConfigService::normalize(std::move(disks));
    std::shared_ptr<NetworkConfigService::State> network_next;
    if (added_networks) {
        const auto network_before = networks_->state();
        if (network_before->revision != network_revision)
            throw ServiceError(ErrorCode::conflict, "Network configuration changed before import");
        // This endpoint only adds package resources. Existing rows/extensions
        // cannot be edited as a side effect of importing another VM.
        auto retained = disk_next->document;
        auto& rows = retained["disks"];
        const auto& old_rows = disk_before->document["disks"];
        if (rows.size() < old_rows.size())
            throw ServiceError(ErrorCode::conflict, "Import cannot remove existing disks");
        rows.resize(old_rows.size());
        if (retained != disk_before->document)
            throw ServiceError(ErrorCode::conflict, "Import cannot replace existing disks");
        auto network_document = network_before->document;
        std::set<std::string> ids, names;
        for (const auto& row : network_document["networks"]) {
            try { ids.insert(config::uuid(row)); } catch (const std::invalid_argument&) {}
            names.insert(config::string(row, "name"));
        }
        for (auto row : *added_networks) {
            try {
                if (!row.isObject() || config::schema(row) != 2)
                    throw std::invalid_argument("Expected network schema 2");
                config::validate_network(row);
                if (!ids.insert(config::uuid(row)).second || !names.insert(config::string(row, "name")).second)
                    throw ServiceError(ErrorCode::conflict, "Imported network identity is already reserved");
            } catch (const std::invalid_argument& error) {
                throw ServiceError(ErrorCode::invalid_argument, error.what());
            }
            network_document["networks"].append(std::move(row));
        }
        if (!added_networks->empty()) {
            network_next = networks_->decode(std::move(network_document), false);
            try { config::encode_json(network_next->document, config::JsonFile::max_bytes); }
            catch (const std::exception&) {
                throw ServiceError(ErrorCode::resource_exhausted, "Imported network configuration storage limit exceeded");
            }
        }
    }
    try { config::validate_disk_transition(disk_before->document, disk_next->document); }
    catch (const std::invalid_argument& error) { throw ServiceError(ErrorCode::conflict, error.what()); }
    check_reservations(disk_before->document, disk_next->document, owner.get());
    validate_vm_networks(vm_before->document, vm_next->document, network_next.get());
    validate_vm_disks(vm_before->document, vm_next->document, disk_before->document, disk_next->document, owner.get());
    if (vm_next->document == vm_before->document && disk_next->document == disk_before->document
            && vm_before->persisted && disk_before->persisted && !vm_before->recovered && !disk_before->recovered
            && !vm_before->durability_uncertain && !disk_before->durability_uncertain)
        return {vm_before, disk_before};
    const auto affected = config::affected_disk_paths(disk_before->document, disk_next->document);
    std::set<std::string> freeze;
    for (const auto& vm : vm_before->document["vms"]) {
        const auto& slots = config::member(vm, "disks");
        if (slots.isArray()) for (const auto& slot : slots) {
            const auto& path = config::member(slot, "path");
            if (path.isString() && affected.contains(path.asString())) freeze.insert(config::uuid(vm));
        }
    }
    auto vm_bytes = config::encode_json(vm_next->document, VmConfigService::max_bytes);
    auto disk_bytes = config::encode_json(disk_next->document, DiskConfigService::max_bytes);
    vm_next->encoded = std::make_shared<const std::string>(vm_bytes.data(), vm_bytes.size());
    disk_next->encoded = std::make_shared<const std::string>(disk_bytes.data(), disk_bytes.size());
    vm_next->revision = random_id(true); disk_next->revision = random_id(true);
    vm_next->persisted = true; disk_next->persisted = true;
    // Even unchanged VM definitions must admit stopped replacement when their
    // disk family changes. Unrelated runtime handles remain untouched.
    auto runtime = inventory_.prepare_config(vm_next->document, freeze);
    std::vector<config::ConfigTransaction::Update> updates{
        {"vms.json", vm_next->document}, {"disks.json", disk_next->document}};
    if (network_next) updates.push_back({"networks.json", network_next->document});
    pending_vm_ = vm_next; pending_disk_ = disk_next; pending_network_ = network_next;
    commit_pending(updates, *runtime, exclusive);
    return {vm_next, disk_next};
}
void ConfigurationService::recover(const CallContext& caller) {
    access(caller);
    auto exclusive = gate_->transaction();
    exclusive.require_recovery();
    std::lock_guard vm_writer(vms_->writer_mutex_);
    std::lock_guard network_writer(networks_->writer_mutex_);
    std::unique_lock<std::mutex> disk_writer;
    if (disks_) disk_writer = std::unique_lock(disks_->writer_mutex_);
    try {
        journal_->recover();
        if (pending_vm_) {
            auto vm = std::make_shared<VmConfigSnapshot>(*pending_vm_);
            vm->durability_uncertain = false; pending_vm_ = std::move(vm);
        }
        if (pending_network_) {
            auto network = std::make_shared<NetworkConfigService::State>(*pending_network_);
            network->durability_uncertain = false; pending_network_ = std::move(network);
        }
        if (pending_disk_) {
            auto disk = std::make_shared<DiskConfigSnapshot>(*pending_disk_);
            disk->durability_uncertain = false; pending_disk_ = std::move(disk);
        }
        publish_pending();
        pending_vm_.reset(); pending_network_.reset(); pending_disk_.reset();
        exclusive.recovered();
    } catch (const std::exception&) { throw ServiceError(ErrorCode::unavailable, "Configuration recovery failed; further access remains disabled"); }
}
}
