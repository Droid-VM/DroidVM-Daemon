// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstdint>
#include <optional>
#include <string>

namespace droidvm::vm {
struct Observation {
    std::string instance;
    uint64_t revision = 0;
    bool operator==(const Observation&) const = default;
};
// A value owned by one VmRuntime, protected by its existing state mutex.
// It owns no locks, threads, VM state or registry. An incarnation distinguishes
// delete/recreate with the same VM ID; the revision also prevents state ABA.
class RuntimeVersion {
public:
    RuntimeVersion();
    RuntimeVersion(const RuntimeVersion&) = delete;
    RuntimeVersion& operator=(const RuntimeVersion&) = delete;
    Observation observe() const;
    void require(const std::optional<Observation>& expected) const;
    // Called under both lifecycle and state locks, before a command can affect
    // resources. Legacy commands consume a revision too, without a precondition.
    void admit(const std::optional<Observation>& expected);
    void changed() noexcept; // asynchronous transition; saturates, never wraps
private:
    const std::string instance_;
    uint64_t revision_ = 0;
};
}
