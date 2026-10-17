// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <set>
#include <string>
#include <map>
#include <optional>
#include "disk_file_leases.h"

namespace droidvm::config {
struct DiskImageInfo {
    std::string format;
    std::optional<std::string> parent;
};
// Java DiskConfig.getFullPath lexical semantics; not canonical/inode identity.
std::string disk_path(const Json::Value& row);
// New references may target only unique, well-formed paths with resolved,
// acyclic ancestry. Historical invalid rows remain readable for repair.
std::set<std::string> valid_disk_paths(const Json::Value& document);
// Throws invalid_argument if an edit introduces invalid paths/parent chains or
// changes a still-invalid historical row. No filesystem access or mutations.
void validate_disk_transition(const Json::Value& before, const Json::Value& after);
// Paths in the old/new connected families of changed rows, for runtime leases.
std::set<std::string> affected_disk_paths(const Json::Value& before, const Json::Value& after);
// CursorPlan.reconcile for persisted slots in changed families: a writable slot
// on a childless row that gains an overlay follows it when follow_new; slots on
// removed rows climb the old parent chain to the nearest surviving row or are
// removed; a slot on a base or on a row held by two slots becomes read-only.
Json::Value reattach_disk_slots(const Json::Value& vms, const Json::Value& before, const Json::Value& after,
    bool follow_new = false);
struct DiskReferences { std::set<std::string> bases; std::map<std::string, size_t> holders; };
DiskReferences disk_references(const Json::Value& vms, const Json::Value& registry);
// Startup is stricter than historical-document preservation: every used path
// must resolve, and base/shared slots must be read-only in the effective session.
void validate_disk_start(const Json::Value& vm, const Json::Value& vms, const Json::Value& registry);
std::vector<DiskFileLeases::Request> disk_start_files(const Json::Value& vm, const Json::Value& registry);
std::map<std::string, std::optional<std::string>> disk_start_parents(const Json::Value& vm, const Json::Value& registry);
}
