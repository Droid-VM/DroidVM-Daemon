// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>

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
};
}
