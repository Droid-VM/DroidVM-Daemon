// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "format.h"
#include "store/disk_config.h"
#include <json/json.h>
#include <functional>
#include <chrono>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace droidvm::pkg {
// ImageUtils over <data>/usr/bin/qemu-img.
class Images {
public:
    explicit Images(std::string qemu_img, std::function<bool()> cancelled = {},
        std::chrono::milliseconds inspection_timeout = std::chrono::minutes(2))
        : qemu_img_(std::move(qemu_img)), cancelled_(std::move(cancelled)), inspection_timeout_(inspection_timeout) {}
    // backingOf: canonical backing path, or none. Throws Error for an
    // unreadable qcow2 or a backing file that is not there.
    std::optional<std::string> backing_of(const std::string& path) const;
    // Inspect the held inode. Resolve relative header names against path, not
    // /proc/self/fd; failed/malformed inspection never means "no backing".
    // The returned parent still needs its own lease before it is inspected/read.
    std::optional<std::string> backing_of(const config::DiskFileLeases::Lease& lease, const std::string& path) const;
    config::DiskImageInfo validate_backing(const config::DiskFileLeases::Lease& lease, const std::string& path,
        const std::optional<std::string>& expected) const;
    // rebaseBacking: qemu-img rebase -u -b <backing> -F <format> <overlay>.
    void rebase(const std::string& overlay, const std::string& backing) const;
    // Modify the retained overlay inode while storing the durable backing path.
    void rebase(const RetainedFile& overlay, const RetainedFile& backing) const;
private:
    std::string qemu_img_;
    std::function<bool()> cancelled_;
    std::chrono::milliseconds inspection_timeout_;
    Json::Value info(const std::string& path, std::vector<int> fds = {}) const; // throws std::runtime_error
    config::DiskImageInfo inspect_leased(const config::DiskFileLeases::Lease& lease, const std::string& path) const;
};

// DiskChainPlan: every file the selected disks need, child before parent,
// one entry per file and unique archive names.
inline constexpr int max_chain = 64;
struct ChainMember {
    std::string path, archive_path;
    std::optional<DiskRef> attachment;
    std::string backing_archive;
};
using BackingLookup = std::function<std::optional<std::string>(const std::string& path)>;
std::vector<ChainMember> plan_disks(const std::vector<DiskRef>& tops, const BackingLookup& lookup);
DiskEntry disk_entry(const ChainMember& member); // DiskEntry.of

// NetworkImportPlan, the parts the import task runs.
inline constexpr const char* network_ref_key = "pkg_network_ref";
enum class NetworkAction { join, create, skip };
struct NetworkPlanEntry {
    std::string ref;
    NetworkAction action = NetworkAction::create;
    std::optional<std::string> network_id;
    std::optional<Json::Value> config;
};
// Entries that cannot be read are dropped, as NetworkImportPlan.parse.
std::vector<NetworkPlanEntry> parse_network_plan(const Json::Value& array);
const NetworkPlanEntry* find_ref(const std::vector<NetworkPlanEntry>& plan, const std::string& ref);
class NetworkImportPlan {
public:
    explicit NetworkImportPlan(const Json::Value& existing);
    Json::Value prepare_create(const Json::Value& packaged);
    // A free id and still-free name/bridge name; claims what it hands out.
    Json::Value adopt(Json::Value config);
private:
    std::set<std::string> names_, bridges_, ids_;
    std::string unique_name(const std::string& base) const;
    std::string unique_bridge(const std::string& base) const;
};

// NicLeaseOffsets.
inline constexpr int64_t first_lease_offset = 64;
enum class Family { ipv4, ipv6 };
void add_offsets(std::set<int64_t>& used, const Json::Value& vm, const Json::Value& network, const Json::Value& vlan,
                 Family family, const Json::Value* exclude = nullptr);
int64_t resolve_offset(int64_t wanted, const std::set<int64_t>& used, const Json::Value& vlan, Family family);
bool vlan_dhcp_enabled(const Json::Value& vlan, Family family);
int vlan_id(const Json::Value& vlan);
std::string random_mac(); // NetUtils.generateRandomMac
std::string random_uuid();
}
