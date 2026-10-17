// SPDX-License-Identifier: GPL-3.0-or-later
#include "qemu_command.h"
#include "common/wire.h"
#include <set>
#include <stdexcept>

namespace droidvm::vm {
QemuDiskGraph qemu_disk_graph(const std::map<std::string, QemuDiskImage>& images) {
    QemuDiskGraph result;
    std::set<int> descriptors;
    std::map<std::string, int> color;
    for (const auto& [path, image] : images) {
        if (path.empty() || image.fd < 3 || !descriptors.insert(image.fd).second)
            throw std::invalid_argument("Disk graph requires distinct retained descriptors");
        if (image.format != "raw" && image.format != "qcow2")
            throw std::invalid_argument("Disk graph format requires an explicit supported driver");
        if (image.parent) {
            const auto parent = images.find(*image.parent);
            if (image.format != "qcow2" || parent == images.end() || !parent->second.readonly)
                throw std::invalid_argument("Disk graph requires a retained read-only backing node");
        }
        result.nodes.emplace(path, "dvm-disk-" + std::to_string(result.nodes.size()));
    }
    // Avoid recursive JSON nesting and stack use for long chains. Node references
    // explicitly select the inspected parent format and retained file descriptor.
    for (const auto& [start, unused] : images) {
        if (color[start] == 2) continue;
        std::vector<std::string> pending;
        auto path = start;
        for (;;) {
            if (color[path] == 1) throw std::invalid_argument("Disk graph contains a backing cycle");
            if (color[path] == 2) break;
            color[path] = 1;
            pending.push_back(path);
            const auto& parent = images.at(path).parent;
            if (!parent) break;
            path = *parent;
        }
        for (auto it = pending.rbegin(); it != pending.rend(); ++it) {
            const auto& image = images.at(*it);
            const auto set = result.preserve_fds.size();
            result.preserve_fds.push_back(image.fd);
            result.argv.insert(result.argv.end(), {"-add-fd", "fd=" + std::to_string(image.fd) + ",set=" + std::to_string(set)});
            Json::Value node;
            node["driver"] = image.format;
            node["node-name"] = result.nodes.at(*it);
            node["read-only"] = image.readonly;
            node["file"]["driver"] = "file";
            node["file"]["filename"] = "/dev/fdset/" + std::to_string(set);
            node["file"]["read-only"] = image.readonly;
            if (image.format == "qcow2")
                node["backing"] = image.parent ? Json::Value(result.nodes.at(*image.parent)) : Json::Value();
            result.argv.insert(result.argv.end(), {"-blockdev", wire::stringify(node)});
            color[*it] = 2;
        }
    }
    return result;
}
}
