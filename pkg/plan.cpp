// SPDX-License-Identifier: GPL-3.0-or-later
#include "plan.h"
#include "common/identity.h"
#include "runtime/child.h"
#include "store/network_config.h"
#include "vm/nic.h"
#include <sys/random.h>
#include <cerrno>
#include <climits>
#include <map>

namespace droidvm::pkg {
Json::Value Images::info(const std::string& path, std::vector<int> fds) const {
    ChildOptions options;
    options.argv = {qemu_img_, "info", "--output=json", path};
    options.preserve_fds = std::move(fds);
    const auto result = Child(options).communicate({}, std::chrono::minutes(2), 8u << 20, cancelled_);
    if (result.exit_code != 0 || result.timed_out || result.cancelled || result.truncated)
        throw std::runtime_error("Failed to get image info with " + std::to_string(result.exit_code));
    return parse_object(result.output);
}
std::optional<std::string> Images::backing_of(const std::string& path) const {
    Json::Value details;
    try { details = info(path); }
    catch (const std::exception&) {
        if (disk_format_of(path) != "QCOW2") return std::nullopt;
        throw Error("cannot read " + path + " - its backing image may be missing");
    }
    auto backing = opt_string(details, "full-backing-filename", opt_string(details, "backing-filename", ""));
    if (backing.empty()) return std::nullopt;
    if (backing.front() != '/') backing = path_join(dirname(path), backing);
    backing = canonical_path(backing);
    if (!is_file(backing)) throw Error("missing backing image: " + backing);
    return backing;
}
std::optional<std::string> Images::backing_of(const config::DiskFileLeases::Lease& lease, const std::string& path) const {
    const int fd = lease.read_fd(path);
    const auto details = info("/proc/self/fd/" + std::to_string(fd), {fd});
    lease.verify();
    if (!details["format"].isString() || details["format"].asString().empty())
        throw Error("Cannot determine leased image format");
    const auto& value = details["backing-filename"];
    if (value.isNull()) {
        if (!details["full-backing-filename"].isNull())
            throw Error("Leased image is missing its original backing filename");
        return std::nullopt;
    }
    if (!value.isString()) throw Error("Invalid leased image backing filename");
    auto backing = value.asString();
    if (backing.empty() || backing.find('\0') != std::string::npos)
        throw Error("Invalid leased image backing filename");
    // qemu-img's full-backing-filename is relative to the descriptor pseudo-path
    // and therefore cannot be used to reconstruct the original backing chain.
    if (backing.front() != '/') backing = path_join(dirname(path), backing);
    backing = canonical_path(backing);
    if (!is_file(backing)) throw Error("missing backing image: " + backing);
    lease.verify();
    return backing;
}
void Images::rebase(const std::string& overlay, const std::string& backing) const {
    std::string format;
    try { format = opt_string(info(backing), "format", "qcow2"); } catch (const std::exception&) { format = "qcow2"; }
    ChildOptions options;
    options.argv = {qemu_img_, "rebase", "-u", "-b", backing, "-F", format, overlay};
    const auto result = Child(options).communicate({}, std::chrono::minutes(2), 1u << 20, cancelled_);
    if (result.exit_code == 0 && !result.timed_out && !result.cancelled) return;
    throw Error("qemu-img rebase failed for " + basename(overlay) + ": " + std::to_string(result.exit_code));
}
void Images::rebase(const RetainedFile& overlay, const RetainedFile& backing) const {
    overlay.verify(); backing.verify();
    const auto descriptor_path = [](int fd) { return "/proc/self/fd/" + std::to_string(fd); };
    // Never guess qcow2 on a failed inspection: that would persist a false backing format.
    const auto details = info(descriptor_path(backing.fd()), {backing.fd()});
    if (!details["format"].isString() || details["format"].asString().empty())
        throw Error("Cannot determine imported backing format");
    overlay.verify(); backing.verify();
    ChildOptions options;
    options.argv = {qemu_img_, "rebase", "-u", "-b", backing.path(), "-F", details["format"].asString(), descriptor_path(overlay.fd())};
    options.preserve_fds = {overlay.fd()};
    const auto result = Child(options).communicate({}, std::chrono::minutes(2), 1u << 20, cancelled_);
    overlay.verify(); backing.verify();
    if (result.exit_code == 0 && !result.timed_out && !result.cancelled && !result.truncated) return;
    throw Error("qemu-img rebase failed for imported image: " + std::to_string(result.exit_code));
}

namespace {
std::string unique_archive(std::set<std::string>& taken, const std::string& name) {
    const auto base = safe_file_name(name, "disk.img");
    if (taken.insert(base).second) return base;
    const auto dot = base.rfind('.');
    const bool split = dot != std::string::npos && dot > 0;
    const auto stem = split ? base.substr(0, dot) : base;
    const auto ext = split ? base.substr(dot) : std::string();
    for (int i = 1;; ++i) {
        auto candidate = stem + "_" + std::to_string(i) + ext;
        if (taken.insert(candidate).second) return candidate;
    }
}
}
std::vector<ChainMember> plan_disks(const std::vector<DiskRef>& tops, const BackingLookup& lookup) {
    std::vector<ChainMember> order;
    std::map<std::string, size_t> by_path;
    std::set<std::string> archives;
    auto add = [&](const std::string& path) {
        order.push_back({path, unique_archive(archives, basename(path)), std::nullopt, {}});
        by_path[path] = order.size() - 1;
        return order.size() - 1;
    };
    for (const auto& top : tops) {
        if (top.path.empty()) continue;
        size_t member;
        const auto known = by_path.find(top.path);
        if (known == by_path.end()) member = add(top.path);
        else if (!order[known->second].attachment) member = known->second;
        else {
            // The same file in two slots gets its own copy rather than a lost disk.
            order.push_back({top.path, unique_archive(archives, basename(top.path)), std::nullopt, {}});
            member = order.size() - 1;
        }
        order[member].attachment = top;
        std::set<std::string> seen{order[member].path};
        auto child = member;
        bool ended = false;
        for (int depth = 0; depth < max_chain; ++depth) {
            const auto backing = lookup(order[child].path);
            if (!backing || backing->empty()) { ended = true; break; }
            if (!seen.insert(*backing).second)
                throw Error("backing chain of " + basename(order[member].path) + " loops at " + *backing);
            const auto found = by_path.find(*backing);
            const bool reused = found != by_path.end();
            const auto parent = reused ? found->second : add(*backing);
            order[child].backing_archive = order[parent].archive_path;
            if (reused) { ended = true; break; }
            child = parent;
        }
        if (!ended) throw Error("backing chain of " + basename(order[member].path) + " is deeper than " + std::to_string(max_chain) + " images");
    }
    return order;
}
DiskEntry disk_entry(const ChainMember& member) {
    DiskEntry entry;
    if (member.attachment) entry.ref = *member.attachment;
    else entry.ref = {DiskEntry::index_backing, member.path, true, "VIRTIO"};
    entry.attached = member.attachment.has_value();
    entry.backing_archive = member.backing_archive;
    entry.name = file_name(entry.ref.path);
    entry.archive_path = member.archive_path;
    entry.format = disk_format_of(entry.name);
    entry.size = file_length(entry.ref.path);
    return entry;
}

std::vector<NetworkPlanEntry> parse_network_plan(const Json::Value& array) {
    std::vector<NetworkPlanEntry> plan;
    if (!array.isArray()) return plan;
    for (const auto& row : array) {
        if (!row.isObject()) continue;
        NetworkPlanEntry entry;
        if (row.isMember("config") && row["config"].isObject()) {
            if (opt_int(row["config"], "schema", 0) != 2) continue;
            entry.config = row["config"];
        }
        const auto id = opt_string(row, "network_id", "");
        if (!id.empty()) entry.network_id = id;
        entry.ref = opt_string(row, "ref", "");
        const auto action = opt_string(row, "action", "");
        entry.action = action == "join" ? NetworkAction::join : action == "skip" ? NetworkAction::skip : NetworkAction::create;
        if (!entry.ref.empty()) plan.push_back(std::move(entry));
    }
    return plan;
}
const NetworkPlanEntry* find_ref(const std::vector<NetworkPlanEntry>& plan, const std::string& ref) {
    for (const auto& entry : plan) if (entry.ref == ref) return &entry;
    return nullptr;
}
NetworkImportPlan::NetworkImportPlan(const Json::Value& existing) {
    for (const auto& network : existing) {
        const auto& name = config::member(network, "name");
        if (name.isString()) names_.insert(name.asString());
        const auto bridge = config::string(network, "bridge_name");
        if (!bridge.empty()) bridges_.insert(bridge);
        const auto id = config::string(network, "id");
        if (!id.empty()) ids_.insert(id);
    }
}
Json::Value NetworkImportPlan::prepare_create(const Json::Value& packaged) {
    auto config = packaged;
    config.removeMember(network_ref_key);
    config.removeMember("id");
    return adopt(std::move(config));
}
Json::Value NetworkImportPlan::adopt(Json::Value config) {
    auto id = config::string(config, "id");
    if (id.empty() || ids_.contains(id)) {
        id = random_uuid();
        config["id"] = id;
    }
    ids_.insert(id);
    const auto& current = config::member(config, "name");
    const auto name = unique_name(current.isString() ? current.asString() : std::string());
    config["name"] = name;
    names_.insert(name);
    const auto bridge = config::string(config, "bridge_name");
    if (!bridge.empty()) {
        const auto unique = unique_bridge(bridge);
        config["bridge_name"] = unique;
        bridges_.insert(unique);
    }
    return config;
}
std::string NetworkImportPlan::unique_name(const std::string& base) const {
    const auto name = java_trim(base).empty() ? std::string("network") : base;
    if (!names_.contains(name)) return name;
    for (int i = 1;; ++i) {
        auto candidate = name + "_" + std::to_string(i);
        if (!names_.contains(candidate)) return candidate;
    }
}
std::string NetworkImportPlan::unique_bridge(const std::string& base) const {
    constexpr int max_bridge_name = 12; // NetworkConfigValidator.MAX_BRIDGE_NAME_LEN
    if (!bridges_.contains(base)) return base;
    for (int i = 1; i < 100000; ++i) {
        const auto suffix = std::to_string(i);
        const int room = max_bridge_name - static_cast<int>(suffix.size());
        const auto head = static_cast<int>(base.size()) > room ? base.substr(0, static_cast<size_t>(std::max(1, room))) : base;
        auto candidate = head + suffix;
        if (!bridges_.contains(candidate)) return candidate;
    }
    return base;
}

namespace {
const Json::Value& section(const Json::Value& vlan, Family family) { return config::member(vlan, family == Family::ipv4 ? "ipv4" : "ipv6"); }
bool pd(const Json::Value& vlan) { return config::string(section(vlan, Family::ipv6), "source") == "dhcp_pd"; }
std::string cidr(const Json::Value& vlan, Family family) { return config::string(section(vlan, family), "cidr"); }
bool has_ipv6(const Json::Value& vlan) { return pd(vlan) || !cidr(vlan, Family::ipv6).empty(); }
const char* lease_key(Family family) { return family == Family::ipv4 ? "dhcp4_lease" : "dhcp6_lease"; }
int64_t max_offset(const Json::Value& vlan, Family family) {
    if (family == Family::ipv4) {
        const auto text = cidr(vlan, family);
        if (text.empty()) return -1;
        try { return (int64_t(1) << (32 - config::NetworkPrefix::parse(text, false).prefix())) - 2; }
        catch (const std::exception&) { return -1; }
    }
    const auto text = cidr(vlan, family);
    std::optional<int> prefix;
    if (!pd(vlan) && !text.empty()) try { prefix = config::NetworkPrefix::parse(text, true).prefix(); } catch (const std::exception&) {}
    if (!prefix) return has_ipv6(vlan) ? INT64_MAX - 1 : -1;
    const int bits = 128 - *prefix;
    if (bits >= 63) return INT64_MAX - 1;
    return (int64_t(1) << bits) - 2;
}
bool has_offset(const Json::Value& nic, Family family) {
    const auto& lease = config::member(nic, lease_key(family));
    if (!lease.isObject() || !config::boolean(lease, "enabled")) return false;
    const auto& offset = config::member(lease, "offset");
    return (offset.type() == Json::intValue || offset.type() == Json::uintValue) && offset.isInt64() && offset.asInt64() > 0;
}
}
bool vlan_dhcp_enabled(const Json::Value& vlan, Family family) {
    const bool served = family == Family::ipv4 ? !cidr(vlan, family).empty() : has_ipv6(vlan);
    return served && config::boolean(config::member(section(vlan, family), "dhcp"), "enabled");
}
int vlan_id(const Json::Value& vlan) {
    return static_cast<int>(static_cast<uint32_t>(static_cast<uint64_t>(config::integer(vlan, "vlan_id", 0))));
}
void add_offsets(std::set<int64_t>& used, const Json::Value& vm, const Json::Value& network, const Json::Value& vlan,
                 Family family, const Json::Value* exclude) {
    const auto id = config::string(network, "id");
    if (id.empty()) return;
    const auto& nics = config::member(vm, "networks");
    if (!nics.isArray()) return;
    for (const auto& nic : nics) {
        if (!nic.isObject() || &nic == exclude) continue;
        if (config::string(nic, "network_id") != id || !has_offset(nic, family)) continue;
        const auto* nic_vlan = vm::nic_dhcp_vlan(nic, network);
        if (!nic_vlan || vlan_id(*nic_vlan) != vlan_id(vlan)) continue;
        used.insert(config::integer(config::member(nic, lease_key(family)), "offset", 64));
    }
}
int64_t resolve_offset(int64_t wanted, const std::set<int64_t>& used, const Json::Value& vlan, Family family) {
    const auto max = max_offset(vlan, family);
    if (max < first_lease_offset) return -1;
    const auto& dhcp = config::member(section(vlan, family), "dhcp");
    const auto pool_start = config::integer(dhcp, "offset_start", 128);
    const auto pool_end = config::integer(dhcp, "offset_end", 192);
    const auto span = max - first_lease_offset + 1;
    const auto probes = std::min<int64_t>(span, int64_t(1) << 16);
    const auto start = wanted < first_lease_offset || wanted > max ? first_lease_offset : wanted;
    for (int64_t i = 0; i < probes; ++i) {
        const auto candidate = first_lease_offset + ((start - first_lease_offset + i) % span);
        if (candidate >= pool_start && candidate <= pool_end) continue;
        if (used.contains(candidate)) continue;
        return candidate;
    }
    return -1;
}
std::string random_mac() {
    unsigned char bytes[6];
    size_t offset = 0;
    while (offset < sizeof(bytes)) {
        const auto count = getrandom(bytes + offset, sizeof(bytes) - offset, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw std::runtime_error("getrandom failed");
        offset += static_cast<size_t>(count);
    }
    bytes[0] = 0x02;
    char text[18];
    std::snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
    return text;
}
std::string random_uuid() { return random_id(true); }
}
