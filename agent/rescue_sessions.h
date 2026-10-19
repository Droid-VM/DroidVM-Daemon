// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "agent/runner.h"
#include "services/context.h"
#include "vm/console_history.h"
#include "vm/observation.h"
#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace droidvm::agent {
// Trusted owner of the SAME managed VM, reservation and retained disk leases
// used by the operation. Never reconstruct ownership by reopening a disk path.
// No caller except this registry may issue console I/O after publication.
class RescueTarget {
public:
    // Destruction must only release handles/orphan ownership, never call a
    // potentially destroyed service, stop a VM, or perform blocking implicit IO.
    virtual ~RescueTarget() noexcept = default;
    virtual vm::Observation observation() = 0;
    virtual vm::LogSlice read(const vm::Observation& expected,
        const std::optional<vm::LogCursor>& cursor, bool tail) = 0;
    // Must enforce expected atomically with the actual bounded write. An
    // exception may follow an unknown amount of progress and is never retried.
    virtual size_t write(const vm::Observation& expected, std::string_view bytes) = 0;
    // Idempotent, bounded cleanup. A failed attempt retains ownership for retry.
    // removed=true requires stopped=true; disk_synced is evidence, not inferred.
    virtual CleanupReport close() = 0;
};

struct RescueSessionView {
    std::string id, disk_id;
    vm::Observation expected;
    RunnerDeadline created, expires;
    bool closing = false, expired = false;
    // Absent while a cleanup attempt holds the entry lock or before any attempt.
    std::optional<CleanupReport> cleanup;
};

class RescueSessions {
public:
    struct Limits {
        size_t capacity = 2;
        std::chrono::milliseconds ttl = std::chrono::minutes(15);
    };
    using Now = std::function<RunnerDeadline()>;
    RescueSessions();
    explicit RescueSessions(Limits limits, Now now = [] { return RunnerClock::now(); });
    // The caller MUST call shutdown while native services are still alive.
    // The destructor does no cleanup IO; remaining managed targets become orphans.
    ~RescueSessions();
    RescueSessions(const RescueSessions&) = delete;
    RescueSessions& operator=(const RescueSessions&) = delete;

    // Strong exception guarantee: any throw leaves no published record. IDs
    // are independently random, never the VM ID. No TTL refresh on any access.
    std::string publish(const CallContext& caller, std::string disk_id, std::shared_ptr<RescueTarget> target);
    RescueSessionView view(const CallContext& caller, const std::string& id) const;
    std::vector<RescueSessionView> list(const CallContext& caller) const;
    // Live permission/expiry/incarnation check without consuming console history.
    // Terminal liveness must use this even while waiting for an output ACK.
    vm::Observation observe(const CallContext& caller, const std::string& id) const;
    vm::LogSlice read(const CallContext& caller, const std::string& id, const vm::Observation& expected,
        const std::optional<vm::LogCursor>& cursor = {}, bool tail = false);
    size_t write(const CallContext& caller, const std::string& id, const vm::Observation& expected,
        std::string_view bytes);
    CleanupReport close(const CallContext& caller, const std::string& id);
    // Explicit calls from an existing worker; no timers or threads are created.
    // Failed cleanup remains closing and is retried by later calls. shutdown
    // permanently rejects publications, even if some targets cannot be removed.
    void expire();
    void shutdown();
    // Internal teardown check across all owners; never an authorization bypass
    // for reading sessions. Call after workers have joined and shutdown ran.
    bool empty() const;
private:
    struct Entry;
    const Limits limits_;
    const Now now_;
    mutable std::mutex mutex_;
    std::map<std::string, std::shared_ptr<Entry>> entries_;
    std::atomic<bool> stopping_{false};
    static void access(const CallContext& caller);
    std::shared_ptr<Entry> find(const CallContext& caller, const std::string& id) const;
    std::vector<std::shared_ptr<Entry>> snapshot() const;
    RescueSessionView project(const std::shared_ptr<Entry>& entry, RunnerDeadline now) const;
    void require_live(const Entry& entry, const vm::Observation& expected) const;
    CleanupReport close_entry(const std::shared_ptr<Entry>& entry);
};
}
