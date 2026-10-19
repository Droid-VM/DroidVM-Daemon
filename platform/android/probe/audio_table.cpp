// SPDX-License-Identifier: GPL-3.0-or-later
#include "audio_table.h"
#include "service_manager.h"
#include "broadcast.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>

void run_audio_probe(Json::Value& report);

namespace droidvm::platform {
namespace {
constexpr const char* default_table = "0\tout\tDEFAULT|system default\t0\t0\t1\n0\tin\tDEFAULT|system default\t0\t0\t6\n";
void publish(int directory, const std::string& table) {
    const auto temporary = ".audio_devices." + std::to_string(getpid()) + ".new";
    const int file = openat(directory, temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (file < 0) throw std::runtime_error(std::strerror(errno));
    size_t offset = 0;
    bool done = true;
    while (offset < table.size()) {
        const auto written = write(file, table.data() + offset, table.size() - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) { done = false; break; }
        offset += static_cast<size_t>(written);
    }
    done = done && fsync(file) == 0;
    close(file);
    if (!done || renameat(directory, temporary.c_str(), directory, "audio_devices") != 0) {
        unlinkat(directory, temporary.c_str(), 0);
        throw std::runtime_error("audio table write failed");
    }
    fsync(directory);
}
}
AudioTable::~AudioTable() { stop(); }
bool AudioTable::start(int run_directory, Log log) {
    stop();
    if (!start_binder_pool()) return false;
    directory_ = fcntl(run_directory, F_DUPFD_CLOEXEC, 0);
    if (directory_ < 0) return false;
    log_ = std::move(log);
    { std::lock_guard lock(mutex_); stopping_ = false; }
    worker_ = std::thread(&AudioTable::run, this);
    return true;
}
void AudioTable::stop() {
    { std::lock_guard lock(mutex_); stopping_ = true; available_ = false; devices_.clear(); }
    wake_.notify_all();
    if (worker_.joinable()) worker_.join();
    if (directory_ >= 0) { close(directory_); directory_ = -1; }
}
Json::Value AudioTable::snapshot() const {
    std::lock_guard lock(mutex_);
    Json::Value result;
    result["available"] = available_ && !stopping_ &&
        std::chrono::steady_clock::now() - refreshed_ <= std::chrono::seconds(5);
    result["devices"] = result["available"].asBool() ? devices_ : Json::Value(Json::arrayValue);
    return result;
}
void AudioTable::run() {
    ServiceManager manager;
    ndk::SpAIBinder previous_service;
    std::string previous_table, last_error;
    unsigned previous_generation = 0;
    bool previous_available = false, pending = true;
    for (;;) {
        auto service = manager.available() ? manager.find("media.audio_policy") : ndk::SpAIBinder();
        const bool service_changed = service.get() && service.get() != previous_service.get();
        Json::Value snapshot(Json::objectValue);
        bool available = false;
        std::string error;
        if (service.get()) {
            try { run_audio_probe(snapshot); available = true; }
            catch (const std::exception& failure) { error = failure.what(); }
        } else error = "media.audio_policy unavailable";
        const auto table = available ? snapshot["audio_table"].asString() : std::string(default_table);
        const auto generation = available ? snapshot["generation"].asUInt() : 0u;
        // A failed write stays pending until a later poll lands it.
        pending = pending || available != previous_available || table != previous_table || generation != previous_generation || service_changed;
        if (pending) {
            try { publish(directory_, table); ++publications_; pending = false; }
            catch (const std::exception& failure) { error = failure.what(); }
        }
        if (log_ && error != last_error && !error.empty()) log_("audio table: " + error);
        last_error = error;
        previous_service = service;
        previous_table = table;
        previous_generation = generation;
        previous_available = available;
        std::unique_lock lock(mutex_);
        available_ = available && !pending && !stopping_;
        devices_ = available_ ? snapshot["devices"] : Json::Value(Json::arrayValue);
        refreshed_ = std::chrono::steady_clock::now();
        if (wake_.wait_for(lock, std::chrono::milliseconds(250), [&] { return stopping_; })) return;
    }
}
}
