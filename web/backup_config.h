// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "staged_configuration.h"

namespace droidvm::web {
inline constexpr size_t backup_import_limit = 31u << 20;
inline constexpr size_t backup_export_limit = 33u << 20;
struct BackupConfigBindings {
    std::function<std::string(const CallContext&, size_t)> begin;
    std::function<size_t(const CallContext&, const std::string&, size_t, std::string_view)> append;
    std::function<Json::Value(const CallContext&, const std::string&)> preview;
    std::function<Json::Value(const CallContext&, const std::string&, const std::string&)> commit;
    std::function<void(const CallContext&, const std::string&)> abort;
    // Native source reserves bounded retained storage before encoding one fixed
    // three-domain snapshot; the returned reader owns that reservation.
    std::function<std::shared_ptr<HttpStreamBody>(const CallContext&)> export_file;
};
ConfigurationBackupOperations backup_configuration(TaskService& tasks, BackupConfigBindings bindings);
Json::Value project_configuration_backup(const Json::Value& value);
}
