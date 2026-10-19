// SPDX-License-Identifier: GPL-3.0-or-later
#include "observation.h"
#include "common/identity.h"
#include "services/context.h"
#include <limits>

namespace droidvm::vm {
RuntimeVersion::RuntimeVersion() : instance_(random_id(false)) {}
Observation RuntimeVersion::observe() const { return {instance_, revision_}; }
void RuntimeVersion::require(const std::optional<Observation>& expected) const {
    if (expected && (expected->instance != instance_ || expected->revision != revision_))
        throw ServiceError(ErrorCode::conflict, "VM instance or lifecycle changed; reload before acting");
    if (revision_ == std::numeric_limits<uint64_t>::max())
        throw ServiceError(ErrorCode::resource_exhausted, "VM lifecycle revision exhausted");
}
void RuntimeVersion::admit(const std::optional<Observation>& expected) { require(expected); ++revision_; }
void RuntimeVersion::changed() noexcept {
    if (revision_ != std::numeric_limits<uint64_t>::max()) ++revision_;
}
}
