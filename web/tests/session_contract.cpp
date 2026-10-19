// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/session.h"
#include "common/identity.h"
#include <atomic>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>

using namespace droidvm;
using namespace droidvm::web;
using namespace std::chrono_literals;
namespace {
const CallContext local{"local-admin", true, true, true};
void require(bool condition) { if (!condition) throw std::runtime_error("Contract assertion failed"); }
template<class Function> void rejects(ErrorCode code, Function function) {
    try { function(); } catch (const ServiceError& error) { require(error.code() == code); return; }
    throw std::runtime_error("Expected service error");
}
struct Fixture {
    SessionStore::Clock::time_point time{};
    uint64_t sequence = 0;
    bool fail_random = false;
    SessionLimits limits;
    SessionStore store;
    explicit Fixture(SessionLimits value = {}) : limits(value), store(limits, [this] { return time; }, [this] {
        if (fail_random) throw std::runtime_error("Injected RNG failure");
        std::ostringstream out;
        out << std::hex << std::setw(64) << std::setfill('0') << ++sequence;
        return out.str();
    }) {}
    SessionGrant login() { return store.exchange(store.issue_pairing(local).token); }
};
struct RememberFixture {
    SessionStore::Clock::time_point time{};
    SessionStore::WallClock::time_point wall{std::chrono::seconds(1800000000)};
    Json::Value disk;
    uint64_t sequence = 0;
    bool fail_save = false;
    std::unique_ptr<SessionStore> store;
    RememberFixture() { restart(); }
    void restart() {
        if (store) store->shutdown();
        SessionPersistence persistence;
        persistence.load = [&] { return disk; };
        persistence.save = [&](const Json::Value& value) {
            if (fail_save) throw std::runtime_error("Injected persistence failure");
            disk = value;
        };
        // Deterministic digest double; production injects SHA-256.
        persistence.digest = [](std::string_view value) {
            auto result = std::string(value);
            for (auto& c : result) c = "fedcba9876543210"[std::string_view("0123456789abcdef").find(c)];
            return result;
        };
        store = std::make_unique<SessionStore>(SessionLimits{}, [&] { return time; }, [&] {
            std::ostringstream out;
            out << std::hex << std::setw(64) << std::setfill('0') << ++sequence;
            return out.str();
        }, std::move(persistence), [&] { return wall; });
    }
    SessionGrant login(bool remember = true) { return store->exchange(store->issue_pairing(local).token, remember); }
    void advance(std::chrono::seconds elapsed) { time += elapsed; wall += elapsed; }
};
size_t passed = 0;
template<class Function> void test(const char* name, Function function) {
    function(); ++passed; std::cout << "PASS " << name << '\n';
}
}
int main() {
    try {
        test("OS random provider preserves legacy IDs and generates independent 256-bit secrets", [] {
            const auto compact = random_id(false), uuid = random_id(true);
            require(compact.size() == 32 && compact[12] == '4');
            require(uuid.size() == 36 && uuid[8] == '-' && uuid[14] == '4');
            const auto first = random_secret(), second = random_secret();
            require(first.size() == 64 && second.size() == 64 && first != second);
        });
        test("only trusted local administration can issue pairing", [] {
            Fixture f;
            rejects(ErrorCode::unauthenticated, [&] { f.store.issue_pairing({}); });
            rejects(ErrorCode::permission_denied, [&] { f.store.issue_pairing({"local-admin", true, true, false}); });
            rejects(ErrorCode::permission_denied, [&] { f.store.issue_pairing({"web:someone", true, true, true}); });
        });
        test("pairing establishes isolated browser identity and independent CSRF", [] {
            Fixture f;
            auto pairing = f.store.issue_pairing(local);
            auto grant = f.store.exchange(pairing.token);
            require(grant.token != pairing.token && grant.token != grant.session.csrf && grant.token != grant.session.id);
            const auto view = f.store.authenticate(grant.token);
            require(view.caller.authenticated && view.caller.administrator && view.caller.manage_tasks);
            require(view.caller.principal == "web:" + view.id && view.caller.principal != "local-admin");
            rejects(ErrorCode::unauthenticated, [&] { f.store.authenticate(pairing.token); });
            rejects(ErrorCode::unauthenticated, [&] { f.store.authenticate(view.id); });
            rejects(ErrorCode::permission_denied, [&] { f.store.issue_pairing(view.caller); });
        });
        test("pairing is single-use", [] {
            Fixture f;
            const auto pairing = f.store.issue_pairing(local);
            f.store.exchange(pairing.token);
            rejects(ErrorCode::unauthenticated, [&] { f.store.exchange(pairing.token); });
        });
        test("pairing expires at exact deadline", [] {
            Fixture f;
            const auto pairing = f.store.issue_pairing(local);
            f.time += f.limits.pairing_ttl;
            rejects(ErrorCode::unauthenticated, [&] { f.store.exchange(pairing.token); });
        });
        test("idle expiration follows authenticated activity", [] {
            SessionLimits limits; limits.idle_ttl = 10s; limits.absolute_ttl = 60s;
            Fixture f(limits); const auto grant = f.login();
            f.time += 9s; f.store.authenticate(grant.token);
            f.time += 9s; f.store.authenticate(grant.token, std::nullopt, false);
            f.time += 1s;
            rejects(ErrorCode::unauthenticated, [&] { f.store.authenticate(grant.token); });
        });
        test("absolute expiration cannot be extended by activity", [] {
            SessionLimits limits; limits.idle_ttl = 5s; limits.absolute_ttl = 12s;
            Fixture f(limits); const auto grant = f.login();
            for (int i = 0; i < 5; ++i) { f.time += 2s; f.store.authenticate(grant.token); }
            f.time += 2s;
            rejects(ErrorCode::unauthenticated, [&] { f.store.authenticate(grant.token); });
        });
        test("CSRF failure never extends idle timeout", [] {
            SessionLimits limits; limits.idle_ttl = 10s;
            Fixture f(limits); const auto grant = f.login();
            f.time += 9s;
            rejects(ErrorCode::permission_denied, [&] { f.store.authenticate(grant.token, ""); });
            rejects(ErrorCode::permission_denied, [&] { f.store.authenticate(grant.token, grant.token); });
            f.time += 1s;
            rejects(ErrorCode::unauthenticated, [&] { f.store.authenticate(grant.token); });
        });
        test("CSRF is scoped to the session", [] {
            Fixture f; const auto first = f.login(), second = f.login();
            rejects(ErrorCode::permission_denied, [&] { f.store.authenticate(first.token, second.session.csrf); });
            require(f.store.authenticate(first.token, first.session.csrf).id == first.session.id);
        });
        test("logout requires CSRF and revokes immediately", [] {
            Fixture f; const auto grant = f.login();
            rejects(ErrorCode::permission_denied, [&] { f.store.logout(grant.token, ""); });
            f.store.authenticate(grant.token);
            f.store.logout(grant.token, grant.session.csrf);
            rejects(ErrorCode::unauthenticated, [&] { f.store.authenticate(grant.token); });
        });
        test("local revoke is idempotent and only affects target", [] {
            Fixture f; const auto first = f.login(), second = f.login();
            rejects(ErrorCode::permission_denied, [&] { f.store.revoke(first.session.caller, second.session.id); });
            f.store.revoke(local, first.session.id); f.store.revoke(local, first.session.id);
            rejects(ErrorCode::unauthenticated, [&] { f.store.authenticate(first.token); });
            f.store.authenticate(second.token);
        });
        test("clear revokes pairings and sessions", [] {
            Fixture f; const auto session = f.login(); const auto pairing = f.store.issue_pairing(local);
            f.store.clear();
            rejects(ErrorCode::unauthenticated, [&] { f.store.authenticate(session.token); });
            rejects(ErrorCode::unauthenticated, [&] { f.store.exchange(pairing.token); });
        });
        test("pairing capacity is recovered after expiry", [] {
            SessionLimits limits; limits.pairings = 1;
            Fixture f(limits); f.store.issue_pairing(local);
            rejects(ErrorCode::resource_exhausted, [&] { f.store.issue_pairing(local); });
            f.time += limits.pairing_ttl; f.store.issue_pairing(local);
        });
        test("session quota rejection preserves unconsumed pairing", [] {
            SessionLimits limits; limits.sessions = 1;
            Fixture f(limits); const auto first = f.login(); const auto pairing = f.store.issue_pairing(local);
            rejects(ErrorCode::resource_exhausted, [&] { f.store.exchange(pairing.token); });
            f.store.logout(first.token, first.session.csrf);
            f.store.exchange(pairing.token);
        });
        test("global pairing throttle has fixed bounded window", [] {
            SessionLimits limits; limits.exchanges_per_minute = 2;
            Fixture f(limits);
            for (int i = 0; i < 2; ++i) rejects(ErrorCode::unauthenticated, [&] { f.store.exchange("bad"); });
            f.store.clear();
            rejects(ErrorCode::resource_exhausted, [&] { f.store.exchange("bad"); });
            f.time += 60s;
            f.login();
        });
        test("random failure does not consume pairing", [] {
            Fixture f; const auto pairing = f.store.issue_pairing(local);
            f.fail_random = true;
            bool failed = false;
            try { f.store.exchange(pairing.token); } catch (const std::runtime_error&) { failed = true; }
            require(failed);
            f.fail_random = false; f.store.exchange(pairing.token);
        });
        test("bad random providers fail closed and collisions terminate", [] {
            SessionStore invalid({}, SessionStore::Clock::now, [] { return "short"; });
            rejects(ErrorCode::internal, [&] { invalid.issue_pairing(local); });
            SessionStore collision({}, SessionStore::Clock::now, [] { return std::string(64, 'a'); });
            rejects(ErrorCode::internal, [&] { collision.issue_pairing(local); });
        });
        test("concurrent exchange consumes one grant exactly once", [] {
            Fixture f; const auto pairing = f.store.issue_pairing(local);
            std::atomic<int> successes{0}, failures{0}, unexpected{0};
            std::vector<std::thread> threads;
            for (int i = 0; i < 8; ++i) threads.emplace_back([&] {
                try { f.store.exchange(pairing.token); ++successes; }
                catch (const ServiceError& e) { if (e.code() == ErrorCode::unauthenticated) ++failures; else ++unexpected; }
                catch (...) { ++unexpected; }
            });
            for (auto& thread : threads) thread.join();
            require(successes == 1 && failures == 7 && unexpected == 0);
        });
        test("invalid limits rejected before use", [] {
            SessionLimits limits; limits.sessions = 0;
            bool rejected = false;
            try { SessionStore store(limits); } catch (const std::invalid_argument&) { rejected = true; }
            require(rejected);
        });
        test("remembered pairing restores only authorization with fresh CSRF", [] {
            RememberFixture f;
            const auto remembered = f.login(), transient = f.login(false);
            require(remembered.session.remembered && !transient.session.remembered);
            require(f.disk["sessions"].size() == 1);
            const auto serialized = f.disk.toStyledString();
            require(serialized.find(remembered.token) == std::string::npos);
            require(serialized.find(remembered.session.csrf) == std::string::npos);
            f.advance(24h);
            f.store->authenticate(remembered.token);
            f.restart();
            const auto view = f.store->authenticate(remembered.token);
            require(view.id == remembered.session.id && view.caller.principal == remembered.session.caller.principal);
            require(view.remembered && !view.lan_only && view.csrf != remembered.session.csrf);
            rejects(ErrorCode::permission_denied, [&] { f.store->authenticate(remembered.token, remembered.session.csrf); });
            rejects(ErrorCode::unauthenticated, [&] { f.store->authenticate(transient.token); });
            require(f.store->session_ids(local) == std::vector<std::string>{remembered.session.id});
        });
        test("remembered pairing has a fixed thirty day deadline", [] {
            RememberFixture f; const auto grant = f.login();
            f.advance(SessionStore::remember_ttl - 1s);
            f.store->authenticate(grant.token);
            f.restart();
            f.store->authenticate(grant.token);
            f.advance(1s);
            rejects(ErrorCode::unauthenticated, [&] { f.store->authenticate(grant.token); });
            f.restart();
            rejects(ErrorCode::unauthenticated, [&] { f.store->authenticate(grant.token); });
        });
        test("logout local revoke and explicit clear persist across restart", [] {
            RememberFixture f;
            const auto logged_out = f.login(), revoked = f.login(), retained = f.login();
            f.store->logout(logged_out.token, logged_out.session.csrf);
            f.restart();
            f.store->revoke(local, revoked.session.id);
            f.restart();
            rejects(ErrorCode::unauthenticated, [&] { f.store->authenticate(logged_out.token); });
            rejects(ErrorCode::unauthenticated, [&] { f.store->authenticate(revoked.token); });
            f.store->authenticate(retained.token);
            f.store->clear();
            f.restart();
            rejects(ErrorCode::unauthenticated, [&] { f.store->authenticate(retained.token); });
        });
        test("LAN authorization is temporary and requires trusted peer on every authentication", [] {
            RememberFixture f; const auto grant = f.store->grant_local();
            require(grant.session.lan_only && !grant.session.remembered);
            rejects(ErrorCode::unauthenticated, [&] { f.store->authenticate(grant.token); });
            f.store->authenticate(grant.token, grant.session.csrf, true, true);
            rejects(ErrorCode::unauthenticated, [&] { f.store->authenticate(grant.token, std::nullopt, false, false); });
            f.store->revoke_local();
            rejects(ErrorCode::unauthenticated, [&] { f.store->authenticate(grant.token, std::nullopt, true, true); });
            const auto temporary = f.store->grant_local();
            f.restart();
            rejects(ErrorCode::unauthenticated, [&] { f.store->authenticate(temporary.token, std::nullopt, true, true); });
        });
        test("failed remember or revoke commits retire all active credentials", [] {
            RememberFixture f;
            const auto grant = f.login();
            f.fail_save = true;
            rejects(ErrorCode::io_error, [&] { f.store->logout(grant.token, grant.session.csrf); });
            rejects(ErrorCode::unavailable, [&] { f.store->authenticate(grant.token); });
            rejects(ErrorCode::unavailable, [&] { f.store->issue_pairing(local); });
            RememberFixture other;
            const auto pairing = other.store->issue_pairing(local);
            other.fail_save = true;
            rejects(ErrorCode::io_error, [&] { other.store->exchange(pairing.token, true); });
            rejects(ErrorCode::unavailable, [&] { other.store->grant_local(); });
        });
        test("shutdown invalidates an old generation without forgetting authorization", [] {
            RememberFixture f; const auto grant = f.login();
            f.store->shutdown();
            rejects(ErrorCode::unavailable, [&] { f.store->authenticate(grant.token); });
            f.restart();
            f.store->authenticate(grant.token);
        });
        test("malformed persistence and absent storage never silently enable remembered sessions", [] {
            RememberFixture f;
            require(f.store->can_remember());
            f.disk["version"] = 2;
            f.restart();
            require(!f.store->can_remember());
            f.login(false);
            Fixture transient;
            const auto pairing = transient.store.issue_pairing(local);
            rejects(ErrorCode::unavailable, [&] { transient.store.exchange(pairing.token, true); });
            transient.store.exchange(pairing.token);
        });
        std::cout << passed << " session contract groups passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n'; return 1;
    }
}
