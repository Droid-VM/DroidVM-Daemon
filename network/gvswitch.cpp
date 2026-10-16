// SPDX-License-Identifier: GPL-3.0-or-later
#include "gvswitch.h"
#include "helper_config.h"
#include "helper_ready.h"
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
Json::Value Gvswitch::tools() const {
    Json::Value result(Json::arrayValue), tool;
    const auto status = process_.status();
    tool["key"] = "gvswitch"; tool["running"] = status.running;
    tool["generation"] = std::to_string(status.generation);
    result.append(std::move(tool)); return result;
}
Json::Value Gvswitch::tool_log(const std::string& key) const {
    if (key != "gvswitch") return {};
    Json::Value result(Json::arrayValue);
    for (const auto& line : process_.log()) result.append(line.text);
    return result;
}
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
    await_helper(process_, *client_, "/api/v1/ports", [](const Json::Value& ports) { return ports.isArray(); });
    ready_ = true;
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
