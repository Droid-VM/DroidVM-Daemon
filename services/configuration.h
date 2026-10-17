// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "network_config.h"
#include "disk_config.h"
#include "vm_config.h"
#include "store/config_transaction.h"

namespace droidvm {
class VmService;
class NetworkService;
// Construct before serving, under the daemon Instance lock. Inventory must be
// empty; inventory, events and this service must share the SAME gate. The owner
// keeps inventory/events alive until this coordinator is destroyed.
// Claims participating ownership gates and replays the journal BEFORE loading.
// Disk participation is opt-in until registry/header/runtime coordination is complete.
class ConfigurationService {
public:
    ConfigurationService(int directory, uid_t owner, std::shared_ptr<ConfigurationGate> gate,
        VmService& inventory, TaskService& events, config::ConfigTransaction::Observer observer = {}, bool manage_disks = false);
    VmConfigService& vms() { return *vms_; }
    NetworkConfigService& networks() { return *networks_; }
    DiskConfigService* disks() { return disks_.get(); }
    VmService& inventory() { return inventory_; }
    TaskService& events() { return events_; }
    // Every affected VM must admit a stopped edit. With a matching lifecycle
    // service, stop the network after validation/preparation and before commit.
    // A later IO failure may leave it stopped; configuration is still atomic.
    // One exact VM revision and exact network config protect the confirmation.
    VmConfigService::Snapshot remove_network(const CallContext& caller, const std::string& vm_revision,
        const Json::Value& expected_network, NetworkService* lifecycle = nullptr);
    struct VmDiskResult { VmConfigService::Snapshot vms; DiskConfigService::Snapshot disks; };
    // Internal registry transaction: no image create/rebase/unlink is authorized.
    // File-operation callers must add header/file leases before exposing an API.
    VmDiskResult replace_vm_disks(const CallContext& caller, const std::string& vm_revision,
        const std::string& disk_revision, Json::Value vms, Json::Value disks);
    // Only an administrator may retry durable redo; this does not resubmit a
    // deletion against a newer baseline. Failure keeps the common gate closed.
    void recover(const CallContext& caller);
private:
    std::shared_ptr<ConfigurationGate> gate_;
    VmService& inventory_;
    TaskService& events_;
    std::unique_ptr<config::ConfigTransaction> journal_;
    std::unique_ptr<NetworkConfigService> networks_;
    std::unique_ptr<VmConfigService> vms_;
    std::unique_ptr<DiskConfigService> disks_;
    std::shared_ptr<VmConfigSnapshot> pending_vm_;
    std::shared_ptr<NetworkConfigService::State> pending_network_;
    std::shared_ptr<DiskConfigSnapshot> pending_disk_;
    void publish_pending();
    void commit_pending(const std::vector<config::ConfigTransaction::Update>& updates,
        ConfigurationCommit& runtime, ConfigurationGate::Transaction& exclusive);
    void validate_vm_networks(const Json::Value& before, const Json::Value& after) const;
    void validate_vm_disks(const Json::Value& before, const Json::Value& after) const;
    void validate_vm_disks(const Json::Value& before, const Json::Value& after,
        const Json::Value& old_disks, const Json::Value& new_disks) const;
    void validate_disk_change(const Json::Value& before, const Json::Value& after) const;
};
}
