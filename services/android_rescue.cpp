// SPDX-License-Identifier: GPL-3.0-or-later
#include "android_rescue.h"
#include "android_display.h"
#include <chrono>
#include <limits>
#include <optional>
#include <stdexcept>
#include <utility>

namespace droidvm {
namespace {
using namespace std::chrono_literals;
constexpr uint64_t boot_window_ms = 600000;
constexpr const char* module_hash = "4533611de83fa462db64b2bacab2c0e497535f4acd96c0ba4444db0e44b1f193";
void require(bool ok, const std::string& reason) {
    if (!ok) throw std::runtime_error("RescueParty: " + reason);
}
uint64_t number(const std::string& value, bool empty = false) {
    if (empty && value.empty()) return 0;
    require(!value.empty() && value.find_first_not_of("0123456789") == std::string::npos, "invalid boot accounting property");
    try { return std::stoull(value); }
    catch (...) { throw std::runtime_error("RescueParty: boot accounting overflow"); }
}
bool truth(const std::string& value) { return value == "1" || value == "true"; }
void validate(const std::function<std::string(const std::string&)>& property) {
    require(number(property(rescue_count)) < static_cast<uint64_t>(std::numeric_limits<int>::max()) / 2, "invalid boot count");
    (void)number(property(rescue_start), true);
    require(!truth(property("crashrecovery.attempting_reboot")) &&
            !truth(property("crashrecovery.attempting_factory_reset")), "system recovery is already pending");
}
}

AndroidRescueStatus android_rescue_probe(const std::function<bool(const std::string&)>& exists,
    const std::function<std::string(const std::string&)>& sha256,
    const std::function<std::string(const std::string&)>& property) {
    try {
        const bool module = exists(rescue_module);
        const bool modern = !property(rescue_count).empty();
        const bool legacy = !property("sys.rescue_boot_count").empty();
        if (!module && !modern && !legacy) return {};
        require(module && modern && !legacy, "boot-loop accounting implementation is not adapted");
        require(sha256(rescue_module) == module_hash, "crash recovery module version is not verified");
        validate(property);
        return {rescue_adapter, {}};
    } catch (const std::exception& error) { return {{}, error.what()}; }
}

AndroidRescueRestart::AndroidRescueRestart(const AndroidDisplayIo& io, const std::string& adapter) : io_(io) {
    const auto current = io_.rescue_status();
    require(current.reason.empty(), current.reason);
    require(current.adapter == adapter, "implementation changed during handoff");
    enabled_ = !adapter.empty();
}
AndroidRescueRestart::~AndroidRescueRestart() {
    // Best effort only as a final backstop; explicit reconciliation reports errors.
    if (armed_) { try { reconcile(false); } catch (...) {} }
}
void AndroidRescueRestart::verify_access() {
    if (!enabled_) return;
    validate(io_.property);
    require(number(io_.property(rescue_start), true) <= io_.uptime_ms(), "boot accounting window is in the future");
    const auto count = io_.property(rescue_count);
    io_.set_property(rescue_count, count);
    require(io_.property(rescue_count) == count, "boot accounting is not writable/stable");
}
void AndroidRescueRestart::cancel() { if (armed_) reconcile(false); }
void AndroidRescueRestart::arm() {
    if (!enabled_) return;
    require(!armed_, "restart accounting already armed");
    validate(io_.property);
    original_count_ = io_.property(rescue_count);
    original_start_ = io_.property(rescue_start);
    const auto start = number(original_start_, true);
    const auto now = io_.uptime_ms();
    require(start <= now, "boot accounting window is in the future");
    // Expired history would also be discarded by the verified noteBoot().
    history_ = now - start < boot_window_ms ? static_cast<int>(number(original_count_)) : 0;
    armed_ = true; // even an ambiguous setter failure must be reconciled
    try {
        io_.set_property(rescue_count, "0");
        require(io_.property(rescue_count) == "0", "cannot arm one controlled restart");
    } catch (...) {
        if (io_.property(rescue_count) == original_count_ && io_.property(rescue_start) == original_start_) armed_ = false;
        else cancel();
        throw;
    }
}
void AndroidRescueRestart::reconcile(bool expected_boot) {
    if (!armed_) return;
    const auto current_text = io_.property(rescue_count);
    const auto current = number(current_text);
    const auto start_text = io_.property(rescue_start);
    const auto start = number(start_text, true);
    require(current < static_cast<uint64_t>(std::numeric_limits<int>::max()) / 2, "unexpected boot count overflow");
    auto return_count = [&](const std::string& target) {
        try { io_.set_property(rescue_count, target); }
        catch (...) {
            // A setter can report an error after committing. Never add the old
            // history a second time if cancellation/destruction runs afterwards.
            if (io_.property(rescue_count) == target) armed_ = false;
            throw;
        }
        armed_ = false;
        require(io_.property(rescue_count) == target, "cannot reconcile boot count; concurrent change retained");
    };
    if (!expected_boot && current == 0) {
        // init never launched the framework (or it has not reached noteBoot).
        require(start_text == original_start_, "boot window changed without a boot registration");
        return_count(original_count_);
    } else {
        require(current > 0, "new framework did not register its boot");
        const auto now = io_.uptime_ms();
        require(start <= now, "invalid new boot window");
        const bool same_window = start_text == original_start_ && now - start < boot_window_ms;
        // Remove only our one controlled boot. Additional boots remain failures;
        // never repeatedly reset the counter during an actual crash loop.
        const auto adjusted = (same_window ? history_ : 0) + current - 1;
        return_count(std::to_string(adjusted));
    }
    armed_ = false;
    if (expected_boot) require(current == 1, "unexpected extra framework restart; retained its failure count");
}
void AndroidRescueRestart::finish(int old_pid, const std::string& old_start) {
    if (!enabled_ || !armed_) return;
    const auto deadline = io_.wall_ms() + 30000;
    std::optional<std::pair<int, std::string>> first;
    bool changed = false;
    try {
        for (;;) {
            const auto servers = io_.processes("system_server");
            require(servers.size() <= 1, "multiple system_server processes during controlled restart");
            if (!servers.empty()) {
                if (const auto ticks = io_.start_ticks(servers[0])) {
                    require(servers[0] != old_pid || *ticks != old_start, "old framework survived restart");
                    const std::pair identity{servers[0], *ticks};
                    if (!first) first = identity;
                    else if (*first != identity) changed = true;
                }
            } else if (first) changed = true;
            if (number(io_.property(rescue_count)) > 0) {
                require(first.has_value(), "boot registration has no framework process");
                reconcile(true);
                require(!changed, "framework identity changed during boot registration");
                return;
            }
            require(io_.wall_ms() < deadline, "framework boot registration timed out");
            io_.sleep(50ms);
        }
    } catch (...) {
        if (armed_) reconcile(false);
        throw;
    }
}
}
