// SPDX-License-Identifier: GPL-3.0-or-later
#include "host_preferences_store.h"
#include "store/json_file.h"

namespace droidvm {
HostPreferencesOptions host_preferences_store(int directory, uid_t owner, HostPreferenceDomain domain) {
    const bool disks = domain == HostPreferenceDomain::disk_operations;
    auto file = std::make_shared<config::JsonFile>(directory, disks ? "disk-defaults.json" : "host-preferences.json", owner,
        config::JsonFile::Observer{}, disks ? 16u << 10 : 4096, config::JsonSyntax::strict);
    HostPreferencesOptions options;
    options.domain = domain;
    options.load = [file]() -> std::optional<HostPreferencesLoaded> {
        auto loaded = file->load();
        if (!loaded) return std::nullopt;
        return HostPreferencesLoaded{std::move(loaded->value), loaded->recovered};
    };
    options.save = [file](const Json::Value& document) {
        try { file->save(document); return HostPreferencesSave::saved; }
        catch (const config::CommitError& error) {
            return error.installed ? HostPreferencesSave::installed_uncertain : HostPreferencesSave::not_saved;
        }
        // JsonFile validates/loads before entering the installation transaction;
        // all exceptions after entering it are CommitError with installed state.
        catch (const std::exception&) { return HostPreferencesSave::not_saved; }
    };
    return options;
}
}
