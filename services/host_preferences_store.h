// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "host_preferences.h"
#include <sys/types.h>

namespace droidvm {
HostPreferencesOptions host_preferences_store(int files_directory, uid_t owner, HostPreferenceDomain domain = HostPreferenceDomain::vm_start);
}
