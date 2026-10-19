// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "services/context.h"
#include <json/json.h>
#include <chrono>
#include <atomic>
#include <memory>
#include <functional>
#include <mutex>
#include <optional>
#include <string_view>
#include <vector>

namespace droidvm::web {
struct SessionLimits {
    size_t pairings = 4;
    size_t sessions = 32;
    size_t exchanges_per_minute = 16;
    std::chrono::seconds pairing_ttl{300};
    std::chrono::seconds idle_ttl{1800};
    std::chrono::seconds absolute_ttl{43200};
};
struct PairingGrant { std::string token; };
struct SessionView {
    std::string id; // Public session identifier, never the cookie credential.
    CallContext caller;
    std::string csrf;
    bool remembered = false;
    bool lan_only = false;
};
struct SessionGrant { std::string token; SessionView session; };
struct SessionPersistence {
    std::function<Json::Value()> load;
    std::function<void(const Json::Value&)> save;
    // SHA-256 of a credential. The adapter supplies the existing crypto provider.
    std::function<std::string(std::string_view)> digest;
};

// Transport-independent, thread-safe identity store. Only the trusted local
// adapter can issue pairings/revoke another browser; HTTP never supplies a role.
// Remembered credentials are persisted as digests; transient credentials and
// CSRF secrets never survive a service generation.
class SessionStore {
public:
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;
    using Random = std::function<std::string()>;
    using WallClock = std::chrono::system_clock;
    using WallNow = std::function<WallClock::time_point()>;
    static constexpr std::chrono::hours remember_ttl{24 * 30};
    explicit SessionStore(SessionLimits limits = {}, Now now = Clock::now, Random random = {},
                          SessionPersistence persistence = {}, WallNow wall_now = WallClock::now);
    PairingGrant issue_pairing(const CallContext& local_admin);
    SessionGrant exchange(std::string_view pairing_token, bool remember = false);
    // Only the transport may invoke this, after verifying the LAN opt-in and peer.
    SessionGrant grant_local();
    bool can_remember();
    void revoke_local();
    // csrf=nullopt for reads; mutations must supply the actual header (including
    // an empty value when missing). WS liveness checks use touch=false.
    SessionView authenticate(std::string_view token, std::optional<std::string_view> csrf = std::nullopt,
                             bool touch = true, bool trusted_lan = false);
    void logout(std::string_view token, std::string_view csrf);
    void revoke(const CallContext& local_admin, std::string_view session_id);
    std::vector<std::string> session_ids(const CallContext& local_admin);
    void clear();
    // Retire this generation, retaining remembered authorization on disk.
    void shutdown();
    // An owning quota slot, not a new credential/session registry. Revocation
    // still happens through authenticate(); detached slots release safely.
    std::shared_ptr<void> reserve_display(std::string_view token);
private:
    struct Pairing { std::string token; CallContext caller; Clock::time_point expiry; };
    struct Session {
        std::string token; SessionView view; Clock::time_point created, activity;
        std::shared_ptr<std::atomic<size_t>> displays = std::make_shared<std::atomic<size_t>>(0);
        WallClock::time_point expiry{};
    };
    SessionLimits limits_;
    Now now_;
    Random random_;
    SessionPersistence persistence_;
    WallNow wall_now_;
    bool retired_ = false;
    std::mutex mutex_;
    std::vector<Pairing> pairings_;
    std::vector<Session> sessions_;
    Clock::time_point attempt_window_;
    size_t attempts_ = 0;
    void expire(Clock::time_point now);
    void check_active() const;
    void throttle(Clock::time_point now);
    void persist();
    void restore();
    std::string digest(std::string_view token) const;
    std::string secret(std::string_view exclude = {});
    static void require_local_admin(const CallContext& caller);
    static bool equal(std::string_view left, std::string_view right);
    static bool valid(std::string_view value);
    Session& find(std::string_view token);
};
}
