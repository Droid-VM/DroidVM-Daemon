// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "services/context.h"

namespace droidvm::vm {
// Only a read-only console observation that made no progress may use this
// signal. A writer must report its accepted bytes or fail without being retried.
class ConsoleBusy final : public ServiceError {
public:
    ConsoleBusy() : ServiceError(ErrorCode::unavailable, "VM console observation is busy") {}
};
}
