// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace droidvm {
// Prepared domain participants retain leases until after snapshot publication.
// Prepare performs allocation/validation; commit cannot fail after disk rename.
struct ConfigurationCommit {
    virtual ~ConfigurationCommit() = default;
    virtual void commit() noexcept = 0;
};
}
