// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <set>
#include <string>

namespace droidvm::config {
// Java DiskConfig.getFullPath lexical semantics; not canonical/inode identity.
std::string disk_path(const Json::Value& row);
// New references may target only unique, well-formed paths with resolved,
// acyclic ancestry. Historical invalid rows remain readable for repair.
std::set<std::string> valid_disk_paths(const Json::Value& document);
// Throws invalid_argument if an edit introduces invalid paths/parent chains or
// changes a still-invalid historical row. No filesystem access or mutations.
void validate_disk_transition(const Json::Value& before, const Json::Value& after);
}
