// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "common/fd.h"
#include <cstdint>
#include <string>

namespace droidvm::network {
enum class BridgeFlag { stp, isolated, locked };
// Narrow workaround for the bundled netbox's broken positional bool parser.
// Uses public Linux UAPI, not OEM ip/bridge binaries or a shell.
void bridge_flag(const std::string& name, BridgeFlag flag, bool enabled);
// The bundled CLI cannot create with an ownership alias or delete by identity.
// Keep these lifecycle operations in the same small Linux UAPI adapter.
struct CreationMark { std::string name; uint32_t group; };
CreationMark creation_mark(const std::string& tag);
void create_marked_bridge(const std::string& name, const std::string& tag);
void create_marked_vlan(const std::string& name, const std::string& tag, uint32_t parent, uint16_t vid);
void clear_creation_group(uint32_t index);
void rename_owned_link(uint32_t index, const std::string& name);
void delete_link_index(uint32_t index);
// A newly-created TAP disappears on close/crash until its ownership record is
// durable and persist_tap is explicitly called. Never attach an existing TAP.
Fd open_transient_tap(const std::string& name);
void persist_tap(int fd);
}
