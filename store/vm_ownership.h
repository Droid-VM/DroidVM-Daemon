// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <sys/types.h>

namespace droidvm::config {
// Same inode and byte-range as Java VmConfigOwnership. Never unlink/reset it.
// Instance still excludes concurrent native daemons. This gate serializes the
// one-way transition with legacy App writes and records ownership across exits.
void claim_vm_config(int directory, uid_t owner);
void require_legacy_vm_config(int directory, uid_t owner);
}
