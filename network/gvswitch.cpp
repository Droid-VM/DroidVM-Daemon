// SPDX-License-Identifier: GPL-3.0-or-later
#include "gvswitch.h"
#include "helper_config.h"
#include "store/json_file.h"
#include "store/network_config.h"
#include "common/identity.h"
#include "common/wire.h"
#include "runtime/helper_identity.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <system_error>

namespace droidvm::network {
namespace {
void require(bool ok, const char* detail) { if (!ok) throw std::system_error(errno, std::generic_category(), detail); }
}
Gvswitch::Gvswitch(std::string executable, int directory)
    : executable_(std::move(executable)), parent_(fcntl(directory, F_DUPFD_CLOEXEC, 3)) {
    require(parent_.get() >= 0, "hold network runtime directory");
    if (executable_.empty() || executable_[0] != '/' || executable_.find('\0') != std::string::npos)
        throw std::invalid_argument("gvswitch executable must be an absolute path");
}
Gvswitch::~Gvswitch() { try { stop(); } catch (...) {} }
bool Gvswitch::healthy() const { return ready_ && process_.status().running; }
void Gvswitch::start(const Json::Value& config) {
    if (!directory_name_.empty() || directory_.get() >= 0 || process_.status().running) throw std::logic_error("gvswitch requires cleanup before start");
    if (config::string(config, "bridge_type") != "gvisor") throw std::invalid_argument("gvswitch requires a gvisor network");
    const auto generated = gvswitch_config(config);
    struct stat parent{};
    require(fstat(parent_.get(), &parent) == 0 && S_ISDIR(parent.st_mode), "stat network runtime directory");
    const auto name = "gv-" + random_id(false);
    require(mkdirat(parent_.get(), name.c_str(), 0700) == 0, "create private switch directory");
    directory_name_ = name;
    directory_ = Fd(openat(parent_.get(), directory_name_.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (directory_.get() < 0) {
        const auto saved = errno;
        if (unlinkat(parent_.get(), directory_name_.c_str(), AT_REMOVEDIR) == 0) directory_name_.clear();
        throw std::system_error(saved, std::generic_category(), "open private switch directory");
    }
    require(fchown(directory_.get(), parent.st_uid, parent.st_gid) == 0, "own private switch directory");
    require(fchmod(directory_.get(), 0700) == 0, "protect private switch directory");
    require(fsync(parent_.get()) == 0, "sync switch directory entry");
    config::JsonFile file(directory_.get(), "config.json", parent.st_uid);
    file.save(generated);
    // Both processes resolve the daemon's pinned FD, not a replaceable or
    // potentially overlong app-data path. The FD remains open until stop.
    const auto path = "/proc/" + std::to_string(getpid()) + "/fd/" + std::to_string(directory_.get());
    const auto token = random_id(false);
    client_ = std::make_unique<ControlHttp>(path + "/s", token);
    ChildOptions options;
    options.argv = {executable_, "-listen", path + "/s", "-auth-token", token, "-config", path + "/config.json"};
    if (config::boolean(config, "stp")) options.argv.push_back("-stp");
    HelperIdentity identity(directory_.get(), parent.st_uid);
    identity.arm(options);
    process_.start(options);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        if (!process_.status().running) throw std::runtime_error("gvswitch exited before readiness");
        try {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
            if (remaining.count() <= 0) break;
            const auto response = client_->request(HttpMethod::get, "/api/v1/ports", {},
                {std::min(remaining, std::chrono::milliseconds(200)), {}});
            if (response.success() && wire::parse(response.body).isArray() && process_.status().running) {
                ready_ = true; return;
            }
            if (!response.success()) throw std::runtime_error("gvswitch readiness API rejected request");
        } catch (const ControlError& error) {
            if (error.reason != ControlFailure::io && error.reason != ControlFailure::timeout) throw;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    throw std::runtime_error("gvswitch readiness deadline exceeded");
}
void Gvswitch::recover(const Json::Value& config) {
    if (healthy()) return;
    stop(); start(config);
}
void Gvswitch::remove_directory() {
    if (directory_.get() < 0) {
        if (!directory_name_.empty()) throw std::runtime_error("unresolved switch directory without held identity");
        return;
    }
    struct stat held{}, named{};
    require(fstat(directory_.get(), &held) == 0, "stat held switch directory");
    require(fstatat(parent_.get(), directory_name_.c_str(), &named, AT_SYMLINK_NOFOLLOW) == 0, "locate switch directory");
    if (held.st_dev != named.st_dev || held.st_ino != named.st_ino || !S_ISDIR(named.st_mode))
        throw std::runtime_error("switch runtime directory identity changed");
    for (const char* file : {"s", "config.json", "config.json.bak", "config.json.corrupt",
                            "helper.json", "helper.json.bak", "helper.json.corrupt", "helper.identity"})
        require(unlinkat(directory_.get(), file, 0) == 0 || errno == ENOENT, "remove switch runtime file");
    // Never recursively remove unknown files. Keep the held identity on error
    // so the service remains FAILED and a later stop can retry cleanup.
    require(unlinkat(parent_.get(), directory_name_.c_str(), AT_REMOVEDIR) == 0, "remove switch runtime directory");
    directory_ = Fd(); directory_name_.clear();
}
void Gvswitch::stop() {
    ready_ = false;
    process_.stop(); client_.reset();
    if (process_.status().running) throw std::runtime_error("gvswitch did not stop");
    remove_directory();
}
}
