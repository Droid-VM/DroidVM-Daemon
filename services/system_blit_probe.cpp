// SPDX-License-Identifier: GPL-3.0-or-later
#include "system_blit_probe.h"
#include "vm/vulkan_blit_probe.h"
#include "runtime/child.h"
#include "common/wire.h"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <set>
#include <sstream>

namespace droidvm {
namespace {
constexpr std::string_view prefix = "DROIDVM_VKPROBE_V1 ";
bool valid(const Json::Value& value) {
    if (!value.isObject() || value.size() != 1 || !value.isMember("missingExtensions")) return false;
    const auto& missing = value["missingExtensions"];
    if (missing.isNull()) return true;
    if (!missing.isArray() || missing.size() > vm::blit_extensions.size()) return false;
    std::set<std::string> seen;
    for (const auto& extension : missing) {
        if (!extension.isString()) return false;
        const auto name = extension.asString();
        if (std::find(vm::blit_extensions.begin(), vm::blit_extensions.end(), name) == vm::blit_extensions.end() || !seen.insert(name).second) return false;
    }
    return true;
}
}
SystemBlitProbe::SystemBlitProbe() {
    value_["state"] = "pending";
    value_["missingExtensions"] = Json::Value();
    value_["checkedAtMs"] = Json::Value();
}
SystemBlitProbe::~SystemBlitProbe() {
    stopping_ = true;
    if (worker_.joinable()) worker_.join();
}
Json::Value SystemBlitProbe::snapshot() {
    std::lock_guard lock(mutex_);
    if (!started_) {
        started_ = true;
        try { worker_ = std::thread([this] { run(); }); }
        catch (...) { value_["state"] = "unknown"; }
    }
    return value_;
}
void SystemBlitProbe::run() noexcept {
    Json::Value missing;
    try {
        ChildOptions options;
        options.argv = {"/proc/self/exe", "--probe-vulkan-blit"};
        options.limits.push_back({RLIMIT_CORE, 0, 0});
        Child child(options);
        const auto output = child.communicate({}, std::chrono::seconds(5), 32768, [this] { return stopping_.load(); });
        if (!output.timed_out && !output.cancelled && !output.truncated && output.exit_code == 0) {
            std::istringstream lines(output.output);
            std::string line;
            Json::Value result;
            size_t records = 0;
            while (std::getline(lines, line)) {
                if (!line.starts_with(prefix)) continue;
                ++records;
                result = wire::parse(line.substr(prefix.size()));
            }
            if (records == 1 && valid(result)) missing = result["missingExtensions"];
        }
    } catch (...) {}
    try {
        std::lock_guard lock(mutex_);
        value_["state"] = missing.isArray() ? "known" : "unknown";
        value_["missingExtensions"] = std::move(missing);
        value_["checkedAtMs"] = Json::Int64(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    } catch (...) {}
}
int SystemBlitProbe::child_main() {
    Json::Value result;
    result["missingExtensions"] = Json::Value();
    try {
        if (const auto missing = vm::missing_system_blit_extensions()) {
            result["missingExtensions"] = Json::Value(Json::arrayValue);
            for (const auto& extension : *missing) result["missingExtensions"].append(extension);
        }
    } catch (...) {}
    std::cout << prefix << wire::stringify(result) << std::endl;
    return 0;
}
}
