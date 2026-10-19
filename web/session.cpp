// SPDX-License-Identifier: GPL-3.0-or-later
#include "session.h"
#include "common/identity.h"
#include <algorithm>

namespace droidvm::web {
namespace {
[[noreturn]] void denied() { throw ServiceError(ErrorCode::unauthenticated, "Browser session is invalid or expired"); }
}
SessionStore::SessionStore(SessionLimits limits, Now now, Random random,
                           SessionPersistence persistence, WallNow wall_now)
    : limits_(limits), now_(std::move(now)), random_(random ? std::move(random) : random_secret),
      persistence_(std::move(persistence)), wall_now_(std::move(wall_now)) {
    if (!now_ || !wall_now_ || !limits_.pairings || limits_.pairings > 32 || !limits_.sessions || limits_.sessions > 128 ||
        !limits_.exchanges_per_minute || limits_.exchanges_per_minute > 256 ||
        limits_.pairing_ttl <= std::chrono::seconds::zero() || limits_.pairing_ttl > std::chrono::hours(1) ||
        limits_.idle_ttl <= std::chrono::seconds::zero() || limits_.absolute_ttl < limits_.idle_ttl ||
        limits_.absolute_ttl > std::chrono::hours(24 * 7))
        throw std::invalid_argument("Invalid browser session limits");
    attempt_window_ = now_();
    if (persistence_.load || persistence_.save || persistence_.digest) {
        if (!persistence_.load || !persistence_.save || !persistence_.digest)
            throw std::invalid_argument("Incomplete browser session persistence");
        try { restore(); }
        catch (...) {
            // A corrupt/unavailable journal cannot restore authorization, but
            // temporary pairing and explicitly enabled LAN access remain usable.
            sessions_.clear();
            persistence_ = {};
        }
    }
}
void SessionStore::check_active() const {
    if (retired_) throw ServiceError(ErrorCode::unavailable, "Browser session store is unavailable");
}
std::string SessionStore::digest(std::string_view token) const {
    if (!persistence_.digest)
        throw ServiceError(ErrorCode::unavailable, "Remembered browser sessions are unavailable");
    auto result = persistence_.digest(token);
    if (!valid(result)) throw ServiceError(ErrorCode::internal, "Invalid credential digest provider");
    return result;
}
void SessionStore::persist() {
    if (!persistence_.save) return;
    try {
        Json::Value value(Json::objectValue);
        value["version"] = 1;
        value["sessions"] = Json::Value(Json::arrayValue);
        for (const auto& session : sessions_) {
            if (!session.view.remembered) continue;
            Json::Value item(Json::objectValue);
            item["digest"] = session.token;
            item["id"] = session.view.id;
            item["manage_tasks"] = session.view.caller.manage_tasks;
            item["administrator"] = session.view.caller.administrator;
            item["expires_at"] = Json::Int64(std::chrono::duration_cast<std::chrono::seconds>(
                session.expiry.time_since_epoch()).count());
            value["sessions"].append(std::move(item));
        }
        persistence_.save(value);
    }
    catch (...) {
        // A failed/uncertain commit must never leave active credentials whose
        // disk state disagrees with the result reported to the caller.
        retired_ = true;
        pairings_.clear(); sessions_.clear();
        throw ServiceError(ErrorCode::io_error, "Cannot save browser authorization; service restart required");
    }
}
void SessionStore::restore() {
    const auto value = persistence_.load();
    if (value.isNull()) return;
    auto invalid = [] { throw ServiceError(ErrorCode::io_error, "Invalid saved browser authorization"); };
    if (!value.isObject() || !value["version"].isInt() || value["version"].asInt() != 1 ||
        !value["sessions"].isArray() || value["sessions"].size() > limits_.sessions) invalid();
    const auto now = now_();
    const auto wall = wall_now_();
    const auto wall_seconds = std::chrono::duration_cast<std::chrono::seconds>(wall.time_since_epoch()).count();
    for (const auto& item : value["sessions"]) {
        if (!item.isObject() || !item["digest"].isString() || !valid(item["digest"].asString()) ||
            !item["id"].isString() || !valid(item["id"].asString()) ||
            !item["manage_tasks"].isBool() || !item["administrator"].isBool() ||
            !item["expires_at"].isInt64()) invalid();
        const auto expiry = item["expires_at"].asInt64();
        if (expiry <= wall_seconds) continue;
        if (expiry - wall_seconds > std::chrono::duration_cast<std::chrono::seconds>(remember_ttl).count()) invalid();
        const auto id = item["id"].asString(), hash = item["digest"].asString();
        if (std::any_of(sessions_.begin(), sessions_.end(), [&](const Session& s) {
            return equal(s.token, hash) || equal(s.view.id, id);
        })) invalid();
        CallContext caller{"web:" + id, true, item["manage_tasks"].asBool(), item["administrator"].asBool()};
        SessionView view{id, std::move(caller), {}, true, false};
        Session session{hash, std::move(view), now, now};
        session.expiry = WallClock::time_point(std::chrono::seconds(expiry));
        sessions_.push_back(std::move(session));
        sessions_.back().view.csrf = secret();
    }
}
bool SessionStore::valid(std::string_view value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
bool SessionStore::equal(std::string_view left, std::string_view right) {
    if (left.size() != right.size()) return false;
    unsigned int difference = 0;
    for (size_t i = 0; i < left.size(); ++i)
        difference |= static_cast<unsigned char>(left[i]) ^ static_cast<unsigned char>(right[i]);
    return difference == 0;
}
void SessionStore::require_local_admin(const CallContext& caller) {
    if (!caller.authenticated || caller.principal.empty()) denied();
    // The local adapter's identity is never issued to browser sessions.
    if (!caller.administrator || caller.principal != "local-admin")
        throw ServiceError(ErrorCode::permission_denied, "Local administration is required");
}
std::vector<std::string> SessionStore::session_ids(const CallContext& caller) {
    require_local_admin(caller);
    std::lock_guard lock(mutex_); expire(now_());
    std::vector<std::string> result;
    for (const auto& session : sessions_) result.push_back(session.view.id);
    return result;
}
void SessionStore::expire(Clock::time_point now) {
    check_active();
    const auto wall = wall_now_();
    std::erase_if(pairings_, [now](const Pairing& item) { return now >= item.expiry; });
    std::erase_if(sessions_, [this, now, wall](const Session& item) {
        if (item.view.remembered) return wall >= item.expiry;
        return now - item.activity >= limits_.idle_ttl || now - item.created >= limits_.absolute_ttl;
    });
}
std::string SessionStore::secret(std::string_view exclude) {
    for (int attempt = 0; attempt < 8; ++attempt) {
        auto value = random_();
        if (!valid(value)) throw ServiceError(ErrorCode::internal, "Invalid random secret provider");
        if (equal(value, exclude)) continue;
        const bool used = std::any_of(pairings_.begin(), pairings_.end(), [&](const Pairing& p) {
            return equal(value, p.token) || equal(value, p.caller.principal.substr(4));
        }) || std::any_of(sessions_.begin(), sessions_.end(), [&](const Session& s) {
            return equal(s.view.remembered ? digest(value) : value, s.token) ||
                equal(value, s.view.csrf) || equal(value, s.view.id);
        });
        if (!used) return value;
    }
    throw ServiceError(ErrorCode::internal, "Random secret collision limit");
}
PairingGrant SessionStore::issue_pairing(const CallContext& local_admin) {
    require_local_admin(local_admin);
    std::lock_guard lock(mutex_);
    const auto now = now_();
    expire(now);
    if (pairings_.size() >= limits_.pairings)
        throw ServiceError(ErrorCode::resource_exhausted, "Pairing limit reached");
    auto token = secret();
    // Public principal is independent of the pairing/session credentials.
    auto identity = secret(token);
    CallContext browser{"web:" + identity, true, local_admin.manage_tasks, true};
    pairings_.push_back({token, std::move(browser), now + limits_.pairing_ttl});
    return {std::move(token)};
}
void SessionStore::throttle(Clock::time_point now) {
    if (now - attempt_window_ >= std::chrono::minutes(1)) { attempt_window_ = now; attempts_ = 0; }
    if (attempts_ >= limits_.exchanges_per_minute)
        throw ServiceError(ErrorCode::resource_exhausted, "Pairing exchange rate exceeded");
    ++attempts_;
}
SessionGrant SessionStore::exchange(std::string_view pairing_token, bool remember) {
    std::lock_guard lock(mutex_);
    const auto now = now_();
    expire(now);
    throttle(now);
    if (!valid(pairing_token)) denied();
    const auto pairing = std::find_if(pairings_.begin(), pairings_.end(), [&](const Pairing& item) {
        return equal(item.token, pairing_token);
    });
    if (pairing == pairings_.end()) denied();
    if (sessions_.size() >= limits_.sessions)
        throw ServiceError(ErrorCode::resource_exhausted, "Browser session limit reached");
    auto token = secret();
    auto csrf = secret(token);
    SessionView view{pairing->caller.principal.substr(4), pairing->caller, std::move(csrf), remember, false};
    // Generate and install before consuming the grant, including allocation failure.
    SessionGrant result{token, view};
    Session session{remember ? digest(token) : std::move(token), std::move(view), now, now};
    if (remember) session.expiry = std::chrono::time_point_cast<std::chrono::seconds>(wall_now_() + remember_ttl);
    sessions_.push_back(std::move(session));
    pairings_.erase(pairing);
    if (remember) persist();
    return result;
}
SessionGrant SessionStore::grant_local() {
    std::lock_guard lock(mutex_);
    const auto now = now_();
    expire(now);
    throttle(now);
    if (sessions_.size() >= limits_.sessions)
        throw ServiceError(ErrorCode::resource_exhausted, "Browser session limit reached");
    auto token = secret();
    auto identity = secret(token);
    // Reserve the public identity before generating the third independent secret.
    SessionView view{identity, {"web:" + identity, true, true, true}, {}, false, true};
    sessions_.push_back({token, std::move(view), now, now});
    try { sessions_.back().view.csrf = secret(); }
    catch (...) { sessions_.pop_back(); throw; }
    return {std::move(token), sessions_.back().view};
}
SessionStore::Session& SessionStore::find(std::string_view token) {
    if (!valid(token)) denied();
    const auto hash = persistence_.digest ? digest(token) : std::string{};
    const auto session = std::find_if(sessions_.begin(), sessions_.end(), [&](const Session& item) {
        return equal(item.token, item.view.remembered ? std::string_view(hash) : token);
    });
    if (session == sessions_.end()) denied();
    return *session;
}
SessionView SessionStore::authenticate(std::string_view token, std::optional<std::string_view> csrf, bool touch,
                                       bool trusted_lan) {
    std::lock_guard lock(mutex_);
    const auto now = now_();
    expire(now);
    auto& session = find(token);
    if (session.view.lan_only && !trusted_lan) denied();
    if (csrf && (!valid(*csrf) || !equal(*csrf, session.view.csrf)))
        throw ServiceError(ErrorCode::permission_denied, "Invalid CSRF token");
    auto result = session.view;
    if (touch) session.activity = now;
    return result;
}
void SessionStore::logout(std::string_view token, std::string_view csrf) {
    std::lock_guard lock(mutex_);
    expire(now_());
    const auto& session = find(token);
    if (!valid(csrf) || !equal(csrf, session.view.csrf))
        throw ServiceError(ErrorCode::permission_denied, "Invalid CSRF token");
    const auto id = session.view.id;
    const bool remembered = session.view.remembered;
    std::erase_if(sessions_, [&](const Session& item) { return item.view.id == id; });
    if (remembered) persist();
}
std::shared_ptr<void> SessionStore::reserve_display(std::string_view token) {
    std::lock_guard lock(mutex_);
    expire(now_());
    auto& session = find(token);
    if (!session.view.caller.administrator) throw ServiceError(ErrorCode::permission_denied, "Display permission required");
    auto count = session.displays;
    if (count->load() >= 2) throw ServiceError(ErrorCode::resource_exhausted, "Display session limit reached");
    count->fetch_add(1);
    return std::shared_ptr<void>(count.get(), [count](void*) { count->fetch_sub(1); });
}
void SessionStore::revoke(const CallContext& local_admin, std::string_view session_id) {
    require_local_admin(local_admin);
    std::lock_guard lock(mutex_);
    expire(now_());
    const bool remembered = std::any_of(sessions_.begin(), sessions_.end(), [&](const Session& item) {
        return item.view.id == session_id && item.view.remembered;
    });
    std::erase_if(sessions_, [&](const Session& item) { return item.view.id == session_id; });
    if (remembered) persist();
}
void SessionStore::clear() {
    std::lock_guard lock(mutex_);
    check_active();
    pairings_.clear();
    sessions_.clear();
    persist();
    // Preserve the rate window; administrative clear must not bypass throttling.
}
void SessionStore::shutdown() {
    std::lock_guard lock(mutex_);
    retired_ = true;
    pairings_.clear(); sessions_.clear();
}
bool SessionStore::can_remember() {
    std::lock_guard lock(mutex_);
    return !retired_ && static_cast<bool>(persistence_.save);
}
void SessionStore::revoke_local() {
    std::lock_guard lock(mutex_);
    std::erase_if(sessions_, [](const Session& session) { return session.view.lan_only; });
}
}
