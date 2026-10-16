// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <string>
#include <stdexcept>

namespace droidvm::network {
// Called serially on a worker for one network. start/recover return only after
// the data path is ready; stop throws if any owned resource remains unresolved.
class Backend {
public:
    virtual ~Backend() = default;
    virtual void start(const Json::Value& config) = 0;
    virtual bool healthy() const = 0;
    // Bounded periodic I/O on the same worker/operation lease as start/stop.
    // Refresh live routing/PD state or verify the helper control plane here.
    // A throw retains the backend and its config lease for retry. Mark the
    // backend unhealthy only if recovery must rebuild it, rather than retrying
    // a transient reconciliation failure against the existing data path.
    virtual void refresh() {}
    virtual void recover(const Json::Value& config) = 0;
    virtual void stop() = 0;
    virtual Json::Value tools() const { return Json::Value(Json::arrayValue); }
    // VM NIC attachment of a sanitized, validated NIC config. A throw leaves
    // no TAP behind; per-forward failures are recorded, never thrown.
    virtual void attach(const Json::Value&, const std::string&) { throw std::runtime_error("VM attachment is not supported by this network"); }
    virtual void detach(const Json::Value&, const std::string&) {}
    virtual Json::Value forward_failures() const { return Json::Value(Json::objectValue); }
    virtual Json::Value tool_log(const std::string&) const { return {}; }
};
}
