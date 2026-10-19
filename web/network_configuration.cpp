// SPDX-License-Identifier: GPL-3.0-or-later
#include "network_configuration.h"
#include "common/wire.h"

namespace droidvm::web {
namespace {
constexpr size_t read_limit = 8u << 20, write_limit = 17u << 20, chunk_bytes = 48u << 10;
using namespace configuration_input;
void require_network(const SnapshotPage& page) {
    if (page.items.empty()) invalid();
    const auto first = wire::parse(page.items.front());
    if (first["type"] != "metadata" || first["resource"] != "networks" || first["encoding"] != "base64-json") invalid();
}
Json::Value project(const SnapshotPage& page) {
    Json::Value result;
    result["snapshotId"] = page.id;
    result["total"] = Json::UInt64(page.total);
    result["next"] = page.next ? Json::Value(Json::UInt64(*page.next)) : Json::Value();
    result["cursor"]["epoch"] = page.cursor.epoch;
    result["cursor"]["sequence"] = std::to_string(page.cursor.sequence);
    auto& items = result["items"] = Json::Value(Json::arrayValue);
    for (const auto& encoded : page.items) {
        const auto item = wire::parse(encoded);
        Json::Value row; row["type"] = item["type"];
        if (item["type"] == "metadata" && item["resource"] == "networks" && item["encoding"] == "base64-json")
            row["bytes"] = item["bytes"];
        else if (item["type"] == "chunk") { row["offset"] = item["offset"]; row["data"] = item["data"]; }
        else invalid();
        items.append(std::move(row));
    }
    return result;
}
}
ConfigOperations network_configuration(TaskService& tasks, JsonConfigurationStaging staging) {
    if (!staging.commit) throw std::invalid_argument("Missing network configuration commit");
    const auto commit = std::move(staging.commit);
    staging.commit = [commit](const CallContext& caller, const std::string& upload) {
        const auto ids = commit(caller, upload);
        if (!ids.isArray() || ids.size() > 1024) throw ServiceError(ErrorCode::internal, "Invalid network commit result");
        Json::Value result; result["updatedCount"] = ids.size(); return result;
    };
    auto writes = staged_configuration(tasks, std::move(staging), "network_configuration", "networks", write_limit);
    return { [&tasks, writes = std::move(writes)](const CallContext& caller, const std::string& operation, const Json::Value& input) {
        access(caller);
        if (!input.isObject()) invalid();
        if (operation == "read") {
            if (input.size() != 2 || !input.isMember("snapshotId")) invalid();
            const auto offset = count(input["offset"], 1 + (read_limit + chunk_bytes - 1) / chunk_bytes);
            if (input["snapshotId"].isNull()) {
                if (offset) invalid();
                const auto page = tasks.network_config_document(caller, 128u << 10);
                try { require_network(page); return project(page); }
                catch (...) { tasks.release_snapshot(caller, page.id); throw; }
            }
            const auto snapshot = id(input["snapshotId"]);
            // Snapshot IDs share a store with VM/disk/task documents. Verify the
            // first metadata page even when a caller jumps straight to chunks.
            require_network(tasks.snapshot_page(caller, snapshot, 0, 128u << 10));
            return project(tasks.snapshot_page(caller, snapshot, offset, 128u << 10));
        }
        if (operation == "release") {
            if (input.size() != 1) invalid();
            tasks.release_snapshot(caller, id(input["snapshotId"]));
            return Json::Value(Json::objectValue);
        }
        if (operation == "begin") {
            if (input.size() != 1 || !input.isMember("bytes")) invalid();
            auto staged = input; staged["revision"] = "conditional";
            return writes.invoke(caller, operation, staged);
        }
        return writes.invoke(caller, operation, input);
    }, {} };
}
}
