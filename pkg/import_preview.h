// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "plan.h"
#include <map>

namespace droidvm::pkg {
inline constexpr size_t import_plan_bytes = 256u << 10;
// Regular-file identity and change observation, never a content digest.
Json::Value observe_package_file(int fd);
// A preview records metadata, not a content hash. A checked import reacquires
// matching observations and retains these read leases until its final commit.
class ImportSource {
public:
    ImportSource(std::shared_ptr<config::DiskFileLeases> pool, const std::string& path,
        const Json::Value* expected = nullptr);
    const std::string& master() const { return master_; }
    const Manifest& manifest() const { return manifest_; }
    int volume_count() const { return header_.volume_count; }
    int64_t data_size() const { return volumes_ ? volumes_->data_size() : header_.data_size; }
    Json::Value observation() const;
    void verify() const;
    std::unique_ptr<Source> open_logical();
private:
    struct File { std::shared_ptr<config::DiskFileLeases::Lease> lease; Json::Value observed; };
    std::shared_ptr<config::DiskFileLeases> pool_;
    std::string master_;
    std::map<std::string, File> files_;
    Header header_;
    Manifest manifest_;
    std::optional<VolumeSet> volumes_;
    Fd open(const std::string& path);
};
bool import_same_kind(const Json::Value& a, const Json::Value& b);
std::string import_network_conflict(const Json::Value& network, const Json::Value& existing);
Json::Value import_preview(const ImportSource& source, const Json::Value& existing_networks);
// Strict checked parser: every packaged ref occurs once, no unknown options,
// join targets retain the packaged network kind, and creates are conflict-free.
std::vector<NetworkPlanEntry> checked_network_plan(const Manifest& manifest,
    const Json::Value& decisions, const Json::Value& existing_networks);
}
