// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "configuration.h"
#include <atomic>

namespace droidvm {
// App-compatible configuration backup. This does not copy image files or
// runtime state. Imports deliberately retain App's network-then-VM/disk order.
class ConfigurationBackup {
public:
    static constexpr size_t max_export_bytes = 33u << 20;
    explicit ConfigurationBackup(ConfigurationService& configuration) : configuration_(configuration) {}
    // The last owner of these immutable bytes releases the single export slot,
    // including when the HTTP connection disappears before completing a read.
    std::shared_ptr<const std::string> export_file(const CallContext& caller);
    Json::Value preview(const CallContext& caller, std::string_view bytes);
    Json::Value commit(const CallContext& caller, std::string_view bytes, const Json::Value& preview);
private:
    ConfigurationService& configuration_;
    std::shared_ptr<std::atomic<bool>> exporting_ = std::make_shared<std::atomic<bool>>(false);
    // Serialize parsed import working sets; upload raw bytes remain charged to
    // ConfigUploads until this operation and all persistence have completed.
    std::mutex import_mutex_;
};
}
