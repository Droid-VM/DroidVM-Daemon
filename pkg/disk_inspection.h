// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "services/config_snapshot.h"
#include "services/context.h"
#include <mutex>
#include <optional>

namespace droidvm { class ConfigurationService; }
namespace droidvm::pkg {
struct DiskInspection {
    DiskConfigSnapshot disks;
    VmConfigSnapshot vms;
    std::string state = "unavailable";
    Json::Value image;
    std::optional<std::string> effective_compression;
};
// On-demand, bounded image metadata. Uses the same reservations, retained
// descriptors and image runner as native disk operations; never changes files.
class DiskInspectionService {
public:
    DiskInspectionService(ConfigurationService& configuration, std::string tool)
        : configuration_(configuration), tool_(std::move(tool)) {}
    DiskInspection read(const CallContext& caller, const std::string& id, bool inspect_compression = false);
private:
    ConfigurationService& configuration_;
    std::string tool_;
    std::mutex mutex_;
};
}
