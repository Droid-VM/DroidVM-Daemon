// SPDX-License-Identifier: GPL-3.0-or-later
#include "host_watch.h"
#include "host_discovery.h"
#include "services/tasks.h"
#include "runtime/helper_identity.h"
#include "common/wire.h"
#include <optional>
#include <poll.h>
#include <set>

namespace droidvm::network {
namespace {
std::optional<std::vector<std::string>> addresses(const Json::Value& value) {
    if (!value.isArray()) return {};
    std::vector<std::string> result;
    for (const auto& address : value) {
        if (!address.isString()) return {};
        result.push_back(address.asString());
    }
    return result;
}
std::set<std::string> unordered(const std::vector<std::string>& values) { return {values.begin(), values.end()}; }
}
HostIpv4Watch::HostIpv4Watch(const Netbox& netbox, SwitchRuntime& runtime, Apply apply, Now now)
    : netbox_(netbox), runtime_(runtime), apply_(std::move(apply)), now_(std::move(now)) {
    if (!apply_ || !now_) throw std::invalid_argument("host IPv4 watch dependencies missing");
}
HostIpv4Watch::~HostIpv4Watch() { try { stop(); } catch (...) {} }
void HostIpv4Watch::schedule(TaskService& workers) {
    {
        std::lock_guard lock(state_);
        if (stopped_ || pending_) return;
        bool due = now_() >= next_poll_;
        if (!due) { pollfd event{monitor_.event_fd(), POLLIN, 0}; due = poll(&event, 1, 0) > 0; }
        if (!due) return;
        pending_ = true;
    }
    try {
        workers.post({"host-ipv4-watch", true, true, true}, [this](bool discarded) {
            try { if (!discarded) tick(); } catch (...) {}
            std::lock_guard lock(state_); pending_ = false;
        });
    } catch (...) { std::lock_guard lock(state_); pending_ = false; throw; }
}
void HostIpv4Watch::tick() {
    std::lock_guard work(work_);
    { std::lock_guard lock(state_); if (stopped_) return; }
    const auto now = now_();
    std::optional<std::vector<std::string>> fresh;
    auto output = monitor_.take_output();
    bool resync = output.resync_required;
    for (const auto& line : output.lines) {
        if (line.stream != ProcessStream::output || line.text.empty() || line.text.front() != '{') continue;
        try {
            if (auto next = addresses(wire::parse(line.text)["v4"])) fresh = std::move(next);
            else resync = true;
        } catch (const std::exception&) { resync = true; }
    }
    bool poll_due;
    { std::lock_guard lock(state_); poll_due = resync || now >= next_poll_; }
    if (poll_due) {
        // Restarts are paced by the backstop, never by the exit event itself.
        if (!output.status.running) {
            try {
                release_monitor();
                runtime_.allocate("host-ipv4", allocation_, SwitchRuntime::Kind::monitor);
                auto options = netbox_.monitor(host_interface_prefixes(), pbridge_offload_metric);
                HelperIdentity identity(allocation_.directory.get(), runtime_.owner()); identity.arm(options);
                monitor_.start(options);
            } catch (const std::exception&) {}
        }
        // A transient query failure keeps the previous set: an empty one
        // would withdraw every forward until the next poll.
        try { fresh = addresses(netbox_.host_ips(host_interface_prefixes(), pbridge_offload_metric)["v4"]); } catch (const std::exception&) {}
        std::lock_guard lock(state_); next_poll_ = now + std::chrono::seconds(5);
    }
    std::vector<std::string> target;
    {
        std::lock_guard lock(state_);
        if (fresh && unordered(*fresh) != unordered(current_)) { current_ = std::move(*fresh); dirty_ = true; }
        if (!dirty_) return;
        target = current_;
    }
    try { apply_(target); } catch (const std::exception&) { return; } // retried by the next backstop
    std::lock_guard lock(state_); if (current_ == target) dirty_ = false;
}
void HostIpv4Watch::release_monitor() {
    monitor_.stop(std::chrono::milliseconds(500));
    if (monitor_.status().running) throw std::runtime_error("host address monitor did not stop");
    if (!allocation_.name.empty()) {
        runtime_.cleanup(allocation_.name);
        allocation_.directory = Fd(); allocation_.name.clear();
    }
}
void HostIpv4Watch::stop() {
    std::lock_guard work(work_);
    { std::lock_guard lock(state_); stopped_ = true; }
    release_monitor();
}
std::vector<std::string> HostIpv4Watch::current() const { std::lock_guard lock(state_); return current_; }
}
