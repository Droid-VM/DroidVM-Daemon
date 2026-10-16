// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "common/fd.h"
#include <json/json.h>
#include <functional>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/types.h>

namespace droidvm::config {
// JSONObject emits integral doubles as signed integer tokens when representable.
// Preserve this on-disk behavior because DataItem's optLong is type-strict.
std::string encode_json(const Json::Value& value, size_t max_bytes = 8u << 20);
class CommitError : public std::runtime_error {
public:
    CommitError(std::string message, bool installed) : std::runtime_error(std::move(message)), installed(installed) {}
    // The primary rename succeeded, but the following directory sync failed.
    // Callers must reconcile the installed value, not report an uncommitted edit.
    const bool installed;
};
struct LoadedJson {
    Json::Value value;
    bool recovered = false;
};
enum class JsonSyntax { compatible, strict };
// One service owns a file under the daemon's already-held Instance lock.
// Call from a worker: filesystem operations can block. Existing JSON shape and
// all unknown fields are retained; schema migration belongs to the service.
class JsonFile {
public:
    static constexpr size_t max_bytes = 8u << 20;
    // Optional fault observer allows crash/write failure testing at durable
    // boundaries without replacing persistence with a second implementation.
    using Observer = std::function<void(const char* stage)>;
    // VM inventory historically allows 16 MiB; other stores keep the 8 MiB
    // default. This changes file capacity, never a transport frame limit.
    JsonFile(int directory, std::string name, uid_t owner, Observer observer = {}, size_t byte_limit = max_bytes,
        JsonSyntax syntax = JsonSyntax::compatible);
    std::optional<LoadedJson> load();
    void save(const Json::Value& value);
private:
    struct Read { std::optional<std::string> bytes; bool corrupt = false; };
    Fd directory_;
    std::string name_;
    uid_t owner_;
    Observer observer_;
    size_t byte_limit_;
    JsonSyntax syntax_;
    std::mutex mutex_;
    Read read(const std::string& name);
    std::optional<LoadedJson> load_unlocked(Read* primary = nullptr);
    std::string temporary(std::string_view bytes);
    void point(const char* stage) { if (observer_) observer_(stage); }
};
}
