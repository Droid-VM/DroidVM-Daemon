// SPDX-License-Identifier: GPL-3.0-or-later
#include "configuration.h"
#include "vm.h"
#include "tasks.h"
#include "common/identity.h"
#include "store/network_config.h"
#include "store/vm_ownership.h"

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
        VmService& inventory, TaskService& events, config::ConfigTransaction::Observer observer) : gate_(std::move(gate)) {
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
    journal_ = std::make_unique<config::ConfigTransaction>(directory, owner, std::move(observer),
        std::vector<std::string>{"vms.json", "networks.json"});
    networks_ = std::make_unique<NetworkConfigService>(directory, owner, config::JsonFile::Observer{}, &events, true, gate_);
    vms_ = std::make_unique<VmConfigService>(directory, owner, config::JsonFile::Observer{},
        [&inventory](const Json::Value& document) { return inventory.prepare_config(document); }, &events, gate_);
    exclusive.recovered();
}
void ConfigurationService::publish_pending() {
    vms_->publish(pending_vm_);
    networks_->publish(pending_network_);
}
VmConfigService::Snapshot ConfigurationService::remove_network(const CallContext& caller, const std::string& vm_revision,
        const Json::Value& expected_network) {
    access(caller);
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
    networks_->require_stopped(id);
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
    exclusive.require_recovery();
    try { journal_->commit(updates); }
    catch (const config::TransactionError& error) {
        if (!error.decided) {
            // Staging cleanup can itself have failed. Only reopen the gate after
            // the journal confirms no unresolved intent or leftovers remain.
            try { journal_->recover(); exclusive.recovered(); } catch (...) {}
            throw ServiceError(ErrorCode::io_error, "Configuration transaction was not committed");
        }
        vm_next->durability_uncertain = true;
        network_next->durability_uncertain = true;
        pending_vm_ = vm_next; pending_network_ = network_next;
        runtime->commit(); // Retire old handles; gate forbids new starts until redo.
        publish_pending();
        throw ServiceError(ErrorCode::commit_uncertain, "Configuration transaction requires recovery before further access");
    }
    pending_vm_ = vm_next; pending_network_ = network_next;
    runtime->commit();
    publish_pending();
    pending_vm_.reset(); pending_network_.reset();
    exclusive.recovered();
    return vm_next;
}
void ConfigurationService::recover(const CallContext& caller) {
    access(caller);
    auto exclusive = gate_->transaction();
    exclusive.require_recovery();
    std::lock_guard vm_writer(vms_->writer_mutex_);
    std::lock_guard network_writer(networks_->writer_mutex_);
    try {
        journal_->recover();
        if (pending_vm_) {
            auto vm = std::make_shared<VmConfigSnapshot>(*pending_vm_);
            auto network = std::make_shared<NetworkConfigService::State>(*pending_network_);
            vm->durability_uncertain = false; network->durability_uncertain = false;
            pending_vm_ = std::move(vm); pending_network_ = std::move(network);
            publish_pending();
            pending_vm_.reset(); pending_network_.reset();
        }
        exclusive.recovered();
    } catch (const std::exception&) { throw ServiceError(ErrorCode::unavailable, "Configuration recovery failed; further access remains disabled"); }
}
}
