// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <functional>
#include <optional>

namespace droidvm::vm {
struct AcmDesired {
    bool enabled = false;
    int ports = 4;
    bool operator==(const AcmDesired&) const = default;
};
// Portable transaction interface. Production holds AcmPool's own slot mutex
// throughout admission, persistence, desired binding and configfs application.
class AcmTransaction {
public:
    virtual ~AcmTransaction() = default;
    virtual Json::Value live(const AcmDesired&) const = 0;
    virtual void admit(const AcmDesired&) const = 0;
    // null means not initialized or installation unknown: new acquisitions fail.
    virtual void bind(std::optional<AcmDesired>) = 0;
    virtual void apply() = 0;
};
class AcmControl {
public:
    virtual ~AcmControl() = default;
    virtual void transaction(const std::function<void(AcmTransaction&)>&) = 0;
};
}
