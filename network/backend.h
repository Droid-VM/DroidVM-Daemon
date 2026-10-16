// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <string>

namespace droidvm::network {
// Called serially on a worker for one network. start/recover return only after
// the data path is ready; stop throws if any owned resource remains unresolved.
class Backend {
public:
    virtual ~Backend() = default;
    virtual void start(const Json::Value& config) = 0;
    virtual bool healthy() const = 0;
    virtual void recover(const Json::Value& config) = 0;
    virtual void stop() = 0;
    virtual Json::Value tools() const { return Json::Value(Json::arrayValue); }
    virtual Json::Value tool_log(const std::string&) const { return {}; }
};
}
