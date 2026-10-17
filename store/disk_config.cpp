// SPDX-License-Identifier: GPL-3.0-or-later
#include "disk_config.h"
#include "network_config.h"
#include <map>
#include <stdexcept>
#include <vector>

namespace droidvm::config {
DiskReferences disk_references(const Json::Value& vms, const Json::Value& registry) {
    std::map<std::string, std::string> paths_by_id;
    DiskReferences result;
    for (const auto& row : registry["disks"]) paths_by_id.emplace(uuid(row), disk_path(row));
    for (const auto& row : registry["disks"]) {
        Json::Value parent; parent["id"] = member(row, "parent");
        try {
            const auto found = paths_by_id.find(uuid(parent));
            if (found != paths_by_id.end()) result.bases.insert(found->second);
        } catch (const std::invalid_argument&) {}
    }
    for (const auto& vm : vms["vms"]) {
        const auto& slots = member(vm, "disks");
        if (slots.isArray()) for (const auto& slot : slots) {
            const auto& path = member(slot, "path");
            if (path.isString() && !path.asString().empty()) ++result.holders[path.asString()];
        }
    }
    return result;
}
void validate_disk_start(const Json::Value& vm, const Json::Value& vms, const Json::Value& registry) {
    const auto paths = valid_disk_paths(registry);
    const auto references = disk_references(vms, registry);
    const auto& slots = member(vm, "disks");
    if (slots.isNull()) return;
    if (!slots.isArray()) throw std::invalid_argument("VM disk slots must be an array");
    for (const auto& slot : slots) {
        const auto& value = member(slot, "path");
        if (value.isNull() || (value.isString() && value.asString().empty())) continue;
        if (!value.isString() || !paths.contains(value.asString()))
            throw std::invalid_argument("VM disk path is not registered with a valid backing chain");
        const auto& path = value.asString();
        const auto holders = references.holders.find(path);
        if ((references.bases.contains(path) || (holders != references.holders.end() && holders->second > 1))
                && !boolean(slot, "readonly"))
            throw std::invalid_argument("Shared and backing disks must be read-only before starting");
    }
}
std::string disk_path(const Json::Value& row) {
    auto base = string(row, "folder");
    auto child = string(row, "name");
    if (!base.empty() && base.back() == '/') base.pop_back();
    if (!child.empty() && child.front() == '/') child.erase(0, 1);
    return base + "/" + child;
}
std::vector<DiskFileLeases::Request> disk_start_files(const Json::Value& vm, const Json::Value& registry) {
    std::map<std::string, const Json::Value*> rows, paths;
    for (const auto& row : registry["disks"]) { rows[uuid(row)] = &row; paths[disk_path(row)] = &row; }
    const auto valid = valid_disk_paths(registry);
    std::map<std::string, bool> requested;
    const auto& slots = member(vm, "disks");
    if (slots.isArray()) for (const auto& slot : slots) {
        auto path = string(slot, "path");
        if (path.empty()) continue;
        if (!valid.contains(path)) throw std::invalid_argument("Invalid disk chain for file lease");
        requested[path] = requested[path] || !boolean(slot, "readonly");
        const Json::Value* row = paths.at(path);
        std::set<std::string> visited;
        while (row && visited.insert(uuid(*row)).second) {
            Json::Value parent; parent["id"] = member(*row, "parent");
            std::string parent_id;
            try { parent_id = uuid(parent); } catch (const std::invalid_argument&) { break; }
            const auto found = rows.find(parent_id);
            if (found == rows.end()) break;
            row = found->second;
            requested.try_emplace(disk_path(*row), false);
        }
    }
    std::vector<DiskFileLeases::Request> result;
    for (const auto& [path, write] : requested) result.push_back({path, write});
    return result;
}
namespace {
struct Registry {
    std::map<std::string, Json::Value> rows;
    std::map<std::string, std::string> parents;
    std::map<std::string, std::set<std::string>> issues;
};
bool path_valid(const Json::Value& row) {
    const auto& folder = member(row, "folder");
    const auto& name = member(row, "name");
    if (!folder.isString() || !name.isString()) return false;
    const auto base = folder.asString(), child = name.asString();
    if (base.empty() || base.front() != '/' || base.find('\0') != std::string::npos
            || child.empty() || child == "." || child == ".."
            || child.find('/') != std::string::npos || child.find('\0') != std::string::npos) return false;
    for (size_t offset = 0; offset < base.size();) {
        auto end = base.find('/', offset);
        if (end == std::string::npos) end = base.size();
        const auto segment = base.substr(offset, end - offset);
        if (segment == "." || segment == "..") return false;
        offset = end + 1;
    }
    return true;
}
Registry inspect(const Json::Value& document) {
    if (!document.isObject() || !member(document, "disks").isArray())
        throw std::invalid_argument("A disk registry is required");
    Registry result;
    std::map<std::string, std::vector<std::string>> paths;
    for (const auto& row : document["disks"]) {
        const auto id = uuid(row);
        if (!result.rows.emplace(id, row).second) throw std::invalid_argument("Duplicate disk identity");
        if (!path_valid(row)) result.issues[id].insert("path");
        paths[disk_path(row)].push_back(id);
    }
    for (const auto& [path, ids] : paths) if (ids.size() > 1)
        for (const auto& id : ids) result.issues[id].insert("duplicate-path:" + path);
    for (const auto& [id, row] : result.rows) {
        const auto& parent = member(row, "parent");
        if (parent.isNull() || (parent.isString() && parent.asString().empty())) continue;
        Json::Value identity; identity["id"] = parent;
        try {
            const auto target = uuid(identity);
            if (!result.rows.contains(target)) result.issues[id].insert("missing-parent:" + target);
            else result.parents.emplace(id, target);
        } catch (const std::invalid_argument&) { result.issues[id].insert("parent-format"); }
    }
    // Iterative graph traversal: bounded stack and linear edge visits even for
    // adversarial long chains. Mark ancestors before validating their children.
    std::map<std::string, int> colors;
    for (const auto& [start, row] : result.rows) {
        if (colors[start] == 2) continue;
        std::vector<std::string> chain;
        auto current = start;
        while (colors[current] == 0) {
            colors[current] = 1; chain.push_back(current);
            const auto parent = result.parents.find(current);
            if (parent == result.parents.end()) break;
            current = parent->second;
        }
        if (!chain.empty() && result.parents.contains(chain.back()) && colors[current] == 1) {
            bool cycle = false;
            for (const auto& id : chain) {
                cycle = cycle || id == current;
                if (cycle) result.issues[id].insert("parent-cycle");
            }
        }
        for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
            const auto parent = result.parents.find(*it);
            if (parent != result.parents.end() && !result.issues[parent->second].empty())
                result.issues[*it].insert("parent-unresolved");
            colors[*it] = 2;
        }
    }
    return result;
}
}
std::set<std::string> valid_disk_paths(const Json::Value& document) {
    auto registry = inspect(document);
    std::set<std::string> paths;
    for (const auto& [id, row] : registry.rows)
        if (registry.issues[id].empty()) paths.insert(disk_path(row));
    return paths;
}
void validate_disk_transition(const Json::Value& before, const Json::Value& after) {
    auto old = inspect(before), next = inspect(after);
    for (const auto& [id, row] : next.rows) {
        const auto& issues = next.issues[id];
        if (issues.empty()) continue;
        const auto prior = old.rows.find(id);
        if (prior == old.rows.end() || prior->second != row)
            throw std::invalid_argument("Repair disk path and parent chain before changing this entry");
        for (const auto& issue : issues) if (!old.issues[id].contains(issue))
            throw std::invalid_argument("Disk update introduces a broken or ambiguous parent chain");
    }
}
std::set<std::string> affected_disk_paths(const Json::Value& before, const Json::Value& after) {
    const auto old = inspect(before), next = inspect(after);
    std::map<std::string, std::set<std::string>> adjacent;
    for (const auto* registry : {&old, &next}) for (const auto& [id, parent] : registry->parents) {
        adjacent[id].insert(parent); adjacent[parent].insert(id);
    }
    std::set<std::string> changed;
    for (const auto& [id, row] : old.rows) {
        const auto found = next.rows.find(id);
        if (found == next.rows.end() || found->second != row) changed.insert(id);
    }
    for (const auto& [id, row] : next.rows) if (!old.rows.contains(id)) changed.insert(id);
    std::vector<std::string> queue(changed.begin(), changed.end());
    std::set<std::string> paths;
    for (size_t i = 0; i < queue.size(); ++i) {
        const auto id = queue[i];
        for (const auto* registry : {&old, &next}) {
            const auto row = registry->rows.find(id);
            if (row != registry->rows.end()) paths.insert(disk_path(row->second));
        }
        for (const auto& related : adjacent[id]) if (changed.insert(related).second) queue.push_back(related);
    }
    return paths;
}
}
