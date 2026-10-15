// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <string>

namespace droidvm::network {
enum class BridgeFlag { stp, isolated, locked };
// Narrow workaround for the bundled netbox's broken positional bool parser.
// Uses public Linux UAPI, not OEM ip/bridge binaries or a shell.
void bridge_flag(const std::string& name, BridgeFlag flag, bool enabled);
}
