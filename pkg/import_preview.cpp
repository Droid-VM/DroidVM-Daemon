// SPDX-License-Identifier: GPL-3.0-or-later
#include "import_preview.h"
#include "services/context.h"
#include "store/network_config.h"
#include "common/wire.h"
#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <cctype>
#include <sys/stat.h>

namespace droidvm::pkg {
Json::Value observe_package_file(int fd) {
    struct stat info{};
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size < 0)
        throw ServiceError(ErrorCode::io_error, "Cannot observe package source");
    Json::Value result;
    result["device"] = std::to_string(info.st_dev);
    result["inode"] = std::to_string(info.st_ino);
    result["size"] = std::to_string(info.st_size);
    result["mtime_sec"] = std::to_string(info.st_mtim.tv_sec);
    result["mtime_nsec"] = std::to_string(info.st_mtim.tv_nsec);
    result["ctime_sec"] = std::to_string(info.st_ctim.tv_sec);
    result["ctime_nsec"] = std::to_string(info.st_ctim.tv_nsec);
    return result;
}
namespace {
[[noreturn]] void invalid() { throw ServiceError(ErrorCode::invalid_argument, "Invalid package import plan"); }
std::string bridge(const Json::Value& value) { return config::string(value, "bridge_type") == "gvisor" ? "gvisor" : "linux"; }
std::string mode(const Json::Value& value) { return config::string(value, "uplink_mode") == "l2" ? "l2" : "l3"; }
std::string lower(std::string value) {
    value = java_trim(value);
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}
bool ref_valid(const std::string& value) {
    return !value.empty() && value.size() <= 128 && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
    });
}
void label(const std::string& value) { if (value.size() > 1024 || !valid_utf8(value) || value.find('\0') != std::string::npos) invalid(); }
struct Prefix { std::array<unsigned char, 16> bytes{}; int bits = 0, width = 0; };
std::optional<Prefix> prefix(const std::string& value, bool ipv6) {
    if (value.empty()) return {};
    try {
        const auto parsed = config::NetworkPrefix::parse(value, ipv6);
        Prefix result;
        result.bits = parsed.prefix(); result.width = ipv6 ? 128 : 32;
        const auto cidr = parsed.network();
        const auto address = cidr.substr(0, cidr.find('/'));
        if (inet_pton(ipv6 ? AF_INET6 : AF_INET, address.c_str(), result.bytes.data()) != 1) return {};
        return result;
    } catch (const std::invalid_argument&) { return {}; }
}
int common_bits(const Prefix& a, const Prefix& b) {
    for (int i = 0; i < a.width; ++i)
        if ((a.bytes[static_cast<size_t>(i / 8)] ^ b.bytes[static_cast<size_t>(i / 8)]) & (0x80u >> (i % 8))) return i;
    return a.width;
}
std::vector<Prefix> prefixes(const Json::Value& network, bool ipv6, bool primary_only = false) {
    std::vector<Prefix> result;
    if (mode(network) != "l3") return result;
    const auto& vlans = config::member(config::member(network, "l3"), "vlans");
    if (!vlans.isArray()) return result;
    for (const auto& vlan : vlans) {
        const auto& family = config::member(vlan, ipv6 ? "ipv6" : "ipv4");
        if (!ipv6 || config::string(family, "source") != "dhcp_pd")
            if (auto value = prefix(config::string(family, "cidr"), ipv6)) {
                if (primary_only && config::integer(vlan, "vlan_id") == 0) return {*value};
                result.push_back(*value);
            }
        if (primary_only) continue;
        const auto& secondary = config::member(vlan, ipv6 ? "ipv6_secondary" : "ipv4_secondary");
        if (secondary.isArray()) for (const auto& cidr : secondary)
            if (cidr.isString()) if (auto value = prefix(cidr.asString(), ipv6)) result.push_back(*value);
    }
    return result;
}
int distance(const Json::Value& source, const Json::Value& target) {
    if (mode(source) == "l2") {
        const auto& left = config::member(config::member(source, "l2"), "uplink");
        const auto& right = config::member(config::member(target, "l2"), "uplink");
        if (!left.isString() || !right.isString()) return 1000;
        const auto a = lower(left.asString()), b = lower(right.asString());
        if (a == b) return 0;
        size_t matched = 0;
        while (matched < std::min(a.size(), b.size()) && a[matched] == b[matched]) ++matched;
        return 1000 - static_cast<int>(matched);
    }
    for (bool ipv6 : {false, true}) {
        const auto mine = prefixes(source, ipv6, true);
        if (mine.empty()) continue;
        const auto theirs = prefixes(target, ipv6, true);
        return theirs.empty() ? 1000 : mine[0].width - common_bits(mine[0], theirs[0]);
    }
    return 500;
}
void validate_manifest(const Manifest& manifest) {
    if (manifest.disks.size() > 1024 || manifest.boots.size() > 16 || manifest.networks.size() > 1024) invalid();
    label(config::string(manifest.vm, "name")); label(manifest.app_version);
    if (manifest.app_version.size() > 128) invalid();
    std::set<std::string> archives;
    auto archive = [&](const std::string& name) {
        if (name.empty() || name == manifest_name || !archives.insert(name).second) invalid();
    };
    for (const auto& disk : manifest.disks) { label(disk.name); if (disk.size < 0) invalid(); archive(disk.archive_path); }
    for (const auto& boot : manifest.boots) {
        label(boot.name); label(boot.kind);
        if (boot.kind.size() > 128 || boot.size < 0) invalid();
        archive(boot.archive_path);
    }
    std::set<std::string> refs;
    for (const auto& network : manifest.networks) {
        const auto ref = config::string(network, network_ref_key);
        if (!ref_valid(ref) || !refs.insert(ref).second || config::schema(network) != 2) invalid();
        label(config::string(network, "name"));
    }
    const auto& nics = config::member(manifest.vm, "networks");
    if (nics.isArray()) for (const auto& nic : nics) {
        const auto ref = config::string(nic, network_ref_key);
        if (!ref.empty() && !refs.contains(ref)) invalid();
    }
}
}
ImportSource::ImportSource(std::shared_ptr<config::DiskFileLeases> pool, const std::string& path,
        const Json::Value* expected) : pool_(std::move(pool)), master_(canonical_path(master_of(path))) {
    if (!pool_) throw ServiceError(ErrorCode::unavailable, "Package source leases are unavailable");
    FileSource input(open(master_));
    char bytes[header_size];
    read_fully(input, bytes, sizeof(bytes));
    header_ = Header::parse(bytes);
    manifest_ = read_manifest(input, header_);
    validate_manifest(manifest_);
    if (header_.volume_count > 0) volumes_ = VolumeSet::discover(master_, [this](const std::string& file) { return open(file); });
    verify();
    if (expected && observation() != *expected)
        throw ServiceError(ErrorCode::conflict, "Package source changed; preview it again");
}
Fd ImportSource::open(const std::string& path) {
    auto found = files_.find(path);
    if (found == files_.end()) {
        auto lease = pool_->acquire({{path, false}});
        auto observed = observe_package_file(lease->read_fd(path));
        found = files_.emplace(path, File{std::move(lease), std::move(observed)}).first;
    }
    found->second.lease->verify();
    if (observe_package_file(found->second.lease->read_fd(path)) != found->second.observed)
        throw ServiceError(ErrorCode::conflict, "Package source changed; preview it again");
    return found->second.lease->open_file(path);
}
Json::Value ImportSource::observation() const {
    Json::Value result(Json::arrayValue);
    for (const auto& [path, file] : files_) { auto row = file.observed; row["path"] = path; result.append(std::move(row)); }
    return result;
}
void ImportSource::verify() const {
    for (const auto& [path, file] : files_) {
        file.lease->verify();
        if (observe_package_file(file.lease->read_fd(path)) != file.observed)
            throw ServiceError(ErrorCode::conflict, "Package source changed; preview it again");
    }
}
std::unique_ptr<Source> ImportSource::open_logical() {
    verify();
    return volumes_ ? volumes_->open_logical() : std::make_unique<FileSource>(open(master_));
}
bool import_same_kind(const Json::Value& a, const Json::Value& b) { return bridge(a) == bridge(b) && mode(a) == mode(b); }
std::string import_network_conflict(const Json::Value& network, const Json::Value& existing) {
    for (const auto& other : existing) {
        if (!import_same_kind(network, other)) continue;
        if (mode(network) == "l2") {
            const auto& mine = config::member(config::member(network, "l2"), "uplink");
            const auto& theirs = config::member(config::member(other, "l2"), "uplink");
            if (mine.isString() && theirs.isString() && lower(mine.asString()) == lower(theirs.asString())) return "uplink";
            continue;
        }
        for (bool ipv6 : {false, true}) {
            const auto mine = prefixes(network, ipv6), theirs = prefixes(other, ipv6);
            for (const auto& a : mine) for (const auto& b : theirs)
                if (common_bits(a, b) >= std::min(a.bits, b.bits)) return ipv6 ? "ipv6" : "ipv4";
        }
    }
    return {};
}
Json::Value import_preview(const ImportSource& source, const Json::Value& existing) {
    const auto& manifest = source.manifest();
    Json::Value result;
    result["source_path"] = source.master(); result["vm_name"] = config::string(manifest.vm, "name");
    result["app_version"] = manifest.app_version; result["manifest_version"] = manifest.manifest_version;
    result["compression"] = compression_name(manifest.compression); result["volume_count"] = source.volume_count();
    auto text = [&](const char* key, size_t maximum) {
        const auto& raw = config::member(manifest.vm, key);
        if (!raw.isString()) return;
        const auto value = raw.asString();
        if (value.size() <= maximum && valid_utf8(value) && value.find('\0') == std::string::npos) result[key] = value;
    };
    auto count = [&](const char* key, const char* output, int64_t maximum) {
        const auto& raw = config::member(manifest.vm, key);
        if ((raw.type() != Json::intValue && raw.type() != Json::uintValue) || !raw.isInt64()) return;
        const auto value = raw.asInt64();
        if (value >= 0 && value <= maximum) result[output] = Json::UInt(value);
    };
    text("backend", 128); text("notes", 8192);
    count("cpu_count", "cpu_count", 1024); count("memory_mb", "memory_mib", INT32_MAX);
    result["disks"] = Json::Value(Json::arrayValue);
    for (const auto& disk : manifest.disks) {
        Json::Value row;
        row["name"] = disk.name; row["size_bytes"] = std::to_string(disk.size);
        row["attached"] = disk.attached; row["readonly"] = disk.ref.readonly;
        result["disks"].append(std::move(row));
    }
    result["boots"] = Json::Value(Json::arrayValue);
    for (const auto& boot : manifest.boots) {
        Json::Value row;
        row["name"] = boot.name; row["kind"] = boot.kind; row["size_bytes"] = std::to_string(boot.size);
        result["boots"].append(std::move(row));
    }
    result["networks"] = Json::Value(Json::arrayValue);
    for (const auto& network : manifest.networks) {
        Json::Value row;
        row["ref"] = config::string(network, network_ref_key); row["name"] = config::string(network, "name");
        row["bridge_type"] = bridge(network); row["uplink_mode"] = mode(network);
        const auto conflict = import_network_conflict(network, existing);
        row["create_allowed"] = conflict.empty(); row["conflict_kind"] = conflict;
        std::vector<Json::Value> candidates;
        for (const auto& candidate : existing) if (import_same_kind(network, candidate)) candidates.push_back(candidate);
        std::stable_sort(candidates.begin(), candidates.end(), [&](const Json::Value& a, const Json::Value& b) {
            const auto da = distance(network, a), db = distance(network, b);
            return da != db ? da < db : config::string(a, "name") < config::string(b, "name");
        });
        row["candidates"] = Json::Value(Json::arrayValue);
        for (const auto& candidate : candidates) {
            Json::Value item; item["id"] = config::uuid(candidate); item["name"] = config::string(candidate, "name");
            label(item["name"].asString()); row["candidates"].append(std::move(item));
        }
        result["networks"].append(std::move(row));
        // Refuse an oversized plan while accumulating candidate lists rather
        // than constructing an unbounded result before TaskService encodes it.
        wire::stringify_bounded(result, import_plan_bytes);
    }
    result["_confirmation"]["files"] = source.observation();
    result["_confirmation"]["manifest"] = manifest.json();
    return result;
}
std::vector<NetworkPlanEntry> checked_network_plan(const Manifest& manifest, const Json::Value& decisions,
        const Json::Value& existing) {
    if (!decisions.isArray() || decisions.size() != manifest.networks.size()) invalid();
    std::map<std::string, const Json::Value*> by_ref;
    for (const auto& network : manifest.networks) by_ref.emplace(config::string(network, network_ref_key), &network);
    std::set<std::string> seen;
    std::vector<NetworkPlanEntry> result;
    NetworkImportPlan names(existing);
    auto future = existing;
    for (const auto& row : decisions) {
        if (!row.isObject()) invalid();
        for (const auto& key : row.getMemberNames()) if (key != "ref" && key != "action" && key != "network_id") invalid();
        if (!row["ref"].isString() || !row["action"].isString()) invalid();
        const auto ref = row["ref"].asString(), action = row["action"].asString();
        const auto found = by_ref.find(ref);
        if (found == by_ref.end() || !seen.insert(ref).second) invalid();
        NetworkPlanEntry entry;
        entry.ref = ref;
        if (action == "join") {
            if (!row["network_id"].isString()) invalid();
            const auto id = row["network_id"].asString();
            bool matched = false;
            for (const auto& network : existing) if (config::uuid(network) == id && import_same_kind(*found->second, network)) { matched = true; break; }
            if (!matched) invalid();
            entry.action = NetworkAction::join; entry.network_id = id;
        } else {
            if (row.isMember("network_id")) invalid();
            if (action == "skip") entry.action = NetworkAction::skip;
            else if (action == "create") {
                auto prepared = names.prepare_create(*found->second);
                try { config::validate_network(prepared); } catch (const std::invalid_argument&) { invalid(); }
                if (!import_network_conflict(prepared, future).empty())
                    throw ServiceError(ErrorCode::conflict, "Imported network conflicts with another network");
                future.append(prepared); entry.action = NetworkAction::create; entry.config = std::move(prepared);
            } else invalid();
        }
        result.push_back(std::move(entry));
    }
    return result;
}
}
