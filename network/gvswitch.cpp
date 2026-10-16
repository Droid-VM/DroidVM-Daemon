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
Gvswitch::Gvswitch(std::string executable, SwitchRuntime& runtime)
    : executable_(std::move(executable)), runtime_(runtime) {
    if (executable_.empty() || executable_[0] != '/' || executable_.find('\0') != std::string::npos)
        throw std::invalid_argument("gvswitch executable must be an absolute path");
}
Gvswitch::~Gvswitch() { try { stop(); } catch (...) {} }
bool Gvswitch::healthy() const { return ready_ && process_.status().running; }
void Gvswitch::start(const Json::Value& config) {
    if (!allocation_.name.empty() || process_.status().running) throw std::logic_error("gvswitch requires cleanup before start");
    if (config::string(config, "bridge_type") != "gvisor") throw std::invalid_argument("gvswitch requires a gvisor network");
    const auto generated = gvswitch_config(config);
    runtime_.allocate(config::uuid(config), allocation_);
    config::JsonFile file(allocation_.directory.get(), "config.json", runtime_.owner());
    file.save(generated);
    // Both processes resolve the daemon's pinned FD, not a replaceable or
    // potentially overlong app-data path. The FD remains open until stop.
    const auto path = "/proc/" + std::to_string(getpid()) + "/fd/" + std::to_string(allocation_.directory.get());
    const auto token = random_id(false);
    client_ = std::make_unique<ControlHttp>(path + "/s", token);
    ChildOptions options;
    options.argv = {executable_, "-listen", path + "/s", "-auth-token", token, "-config", path + "/config.json"};
    if (config::boolean(config, "stp")) options.argv.push_back("-stp");
    HelperIdentity identity(allocation_.directory.get(), runtime_.owner());
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
    if (allocation_.name.empty()) return;
    runtime_.cleanup(allocation_.name);
    allocation_.directory = Fd(); allocation_.name.clear();
}
void Gvswitch::stop() {
    ready_ = false;
    process_.stop(); client_.reset();
    if (process_.status().running) throw std::runtime_error("gvswitch did not stop");
    remove_directory();
}
}
