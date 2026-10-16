// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <functional>
#include <memory>
#include <string>

namespace droidvm::network {
// Global forwarding is shared with netd/tethering, not an exclusively owned
// resource. Assert it while Linux L3 has demand; never restore a guessed old
// value on release (another system user may now require forwarding).
class Forwarding {
    struct State;
public:
    using Observer = std::function<void(const char*)>;
    class Lease {
    public:
        ~Lease();
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
    private:
        friend class Forwarding;
        explicit Lease(std::string owner) : owner_(std::move(owner)) {}
        std::string owner_;
        std::shared_ptr<State> state_;
    };
    explicit Forwarding(Observer observer = {});
    ~Forwarding();
    Forwarding(const Forwarding&) = delete;
    Forwarding& operator=(const Forwarding&) = delete;
    // A running backend retains this beside its configuration lease. L2 and
    // gvisor return no lease and do not read or write host sysctls.
    std::unique_ptr<Lease> acquire(Json::Value config);
    void refresh(); // shared worker; no I/O when no demand or after shutdown
    void shutdown(); // rejects new demand and prevents late reassertion
private:
    std::shared_ptr<State> state_;
};
}
