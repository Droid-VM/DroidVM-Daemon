// SPDX-License-Identifier: GPL-3.0-or-later
#include "forwarding.h"
#include "common/fd.h"
#include "store/network_config.h"
#include "services/context.h"
#include <fcntl.h>
#include <mutex>
#include <set>
#include <system_error>

namespace droidvm::network {
namespace {
void require(bool condition, const char* detail) {
    if (!condition) throw std::system_error(errno, std::generic_category(), detail);
}
bool enabled(const char* path) {
    Fd file(open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    require(file.get() >= 0, "open forwarding sysctl for read");
    char bytes[16];
    ssize_t count;
    do { count = read(file.get(), bytes, sizeof(bytes)); } while (count < 0 && errno == EINTR);
    require(count >= 0, "read forwarding sysctl");
    const std::string_view value(bytes, static_cast<size_t>(count));
    if (value != "0\n" && value != "1\n")
        throw ServiceError(ErrorCode::io_error, "invalid forwarding sysctl value");
    return value == "1\n";
}
void enable(const char* path) {
    Fd file(open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
    require(file.get() >= 0, "open forwarding sysctl for write");
    ssize_t count;
    // The IPv6 forwarding handler can consume only the numeric byte when a
    // newline is supplied. A single-byte write is unambiguous on both families.
    do { count = write(file.get(), "1", 1); } while (count < 0 && errno == EINTR);
    if (count >= 0 && count != 1) errno = EIO;
    require(count == 1, "enable forwarding sysctl");
    if (!enabled(path)) throw ServiceError(ErrorCode::unavailable, "forwarding was reset during verification");
}
}
struct Forwarding::State {
    std::mutex mutex;
    std::set<std::string> owners;
    bool stopped = false;
    Observer observer;
    void assert_enabled() {
        std::string errors;
        // Try both families even when one operation fails. Partial success is
        // never readiness, but is not rolled back over another user's demand.
        for (const bool ipv6 : {false, true}) {
            try {
                const char* path = ipv6 ? "/proc/sys/net/ipv6/conf/all/forwarding" : "/proc/sys/net/ipv4/ip_forward";
                if (enabled(path)) continue;
                if (observer) observer(ipv6 ? "before_ipv6_write" : "before_ipv4_write");
                enable(path);
                if (observer) observer(ipv6 ? "ipv6_written" : "ipv4_written");
            } catch (const std::exception& error) {
                if (!errors.empty()) errors += "; ";
                errors += std::string(ipv6 ? "IPv6: " : "IPv4: ") + error.what();
            }
        }
        if (!errors.empty()) throw ServiceError(ErrorCode::io_error, "forwarding unavailable: " + errors);
    }
};
Forwarding::Forwarding(Observer observer) : state_(std::make_shared<State>()) { state_->observer = std::move(observer); }
Forwarding::~Forwarding() { shutdown(); }
Forwarding::Lease::~Lease() {
    if (state_) { std::lock_guard lock(state_->mutex); state_->owners.erase(owner_); }
}
std::unique_ptr<Forwarding::Lease> Forwarding::acquire(Json::Value network) {
    config::validate_network(network);
    const auto owner = config::uuid(network);
    auto lease = std::unique_ptr<Lease>(new Lease(owner));
    std::lock_guard lock(state_->mutex);
    if (state_->stopped) throw ServiceError(ErrorCode::unavailable, "forwarding manager is stopped");
    if (config::string(network, "bridge_type") == "gvisor" || config::string(network, "uplink_mode") == "l2") return {};
    if (state_->owners.contains(owner)) throw ServiceError(ErrorCode::conflict, "network already holds forwarding demand");
    if (state_->owners.size() >= 1024) throw ServiceError(ErrorCode::resource_exhausted, "forwarding demand exceeds budget");
    state_->owners.insert(owner);
    try { state_->assert_enabled(); }
    catch (...) { state_->owners.erase(owner); throw; }
    lease->state_ = state_;
    return lease;
}
void Forwarding::refresh() {
    std::lock_guard lock(state_->mutex);
    if (!state_->stopped && !state_->owners.empty()) state_->assert_enabled();
}
void Forwarding::shutdown() {
    std::lock_guard lock(state_->mutex);
    state_->stopped = true;
    state_->owners.clear();
}
}
