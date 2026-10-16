// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "netbox.h"
#include "switch_runtime.h"
#include "runtime/managed_process.h"
#include <chrono>
#include <functional>
#include <mutex>

namespace droidvm { class TaskService; }
namespace droidvm::network {
// Legacy DefaultRouterWatcher host-IPv4 half for DNAT scoping: a netbox
// monitor-addr stream applied as it arrives, plus a five second host-ips
// backstop that also restarts a dead monitor. A failed query keeps the
// previous set; a failed apply retries on the next tick. The monitor holds a
// recoverable helper identity, so startup reclaims one orphaned by SIGKILL.
class HostIpv4Watch {
public:
    using Apply = std::function<void(const std::vector<std::string>&)>;
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;
    HostIpv4Watch(const Netbox& netbox, SwitchRuntime& runtime, Apply apply, Now now = [] { return Clock::now(); });
    ~HostIpv4Watch();
    void schedule(TaskService& workers); // event-loop side, no tool I/O
    void tick(); // worker side
    void stop(); // after the workers drained; apply never runs afterwards
    std::vector<std::string> current() const;
    bool signal_monitor(int number) { return monitor_.signal(number); }
private:
    const Netbox& netbox_;
    SwitchRuntime& runtime_;
    SwitchRuntime::Allocation allocation_;
    Apply apply_;
    Now now_;
    ManagedProcess monitor_;
    std::mutex work_;
    mutable std::mutex state_;
    bool pending_ = false, stopped_ = false, dirty_ = false;
    Clock::time_point next_poll_{};
    std::vector<std::string> current_;
    void release_monitor();
};
}
