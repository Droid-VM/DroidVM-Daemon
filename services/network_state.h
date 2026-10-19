// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace droidvm {
// Portable domain state shared by native services and transport adapters.
enum class NetworkState { stopped, starting, running, recovering, stopping, failed };
const char* network_state_name(NetworkState state);
}
