// SPDX-License-Identifier: GPL-3.0-or-later
#include "vm_configuration.h"
#include "common/wire.h"

namespace droidvm::web {
namespace {
constexpr size_t document_limit = 16u << 20, chunk_bytes = 48u << 10;
using namespace configuration_input;
Json::Value version(const VmConfigSnapshot& snapshot) {
    Json::Value result;
    result["revision"] = snapshot.revision;
    result["persisted"] = snapshot.persisted; result["recovered"] = snapshot.recovered;
    result["durabilityUncertain"] = snapshot.durability_uncertain;
    return result;
}
Json::Value page_json(const SnapshotPage& page) {
    Json::Value result;
    result["snapshotId"] = page.id;
    result["cursor"]["epoch"] = page.cursor.epoch;
    result["cursor"]["sequence"] = std::to_string(page.cursor.sequence);
    result["total"] = Json::UInt64(page.total);
    result["next"] = page.next ? Json::Value(Json::UInt64(*page.next)) : Json::Value();
    auto& rows = result["items"] = Json::Value(Json::arrayValue);
    for (const auto& encoded : page.items) {
        const auto item = wire::parse(encoded);
        Json::Value row;
        row["type"] = item["type"];
        if (item["type"] == "metadata" && item["encoding"] == "base64-json") {
            row["revision"] = item["revision"]; row["bytes"] = item["bytes"];
            row["persisted"] = item["persisted"]; row["recovered"] = item["recovered"];
            row["durabilityUncertain"] = item["durability_uncertain"];
        } else if (item["type"] == "chunk") {
            row["offset"] = item["offset"]; row["data"] = item["data"];
        } else invalid(); // Never expose a task/other row passed as a guessed snapshot.
        rows.append(std::move(row));
    }
    return result;
}
}
ConfigOperations vm_configuration(TaskService& tasks, ConfigStaging staging,
        std::function<Json::Value(const CallContext&)> defaults) {
    if (!staging.begin || !staging.append || !staging.commit || !staging.abort)
        throw std::invalid_argument("Missing configuration staging binding");
    auto writes = staged_configuration(tasks, {
        std::move(staging.begin), std::move(staging.append),
        [commit = std::move(staging.commit)](const CallContext& caller, const std::string& upload) {
            return version(*commit(caller, upload));
        }, std::move(staging.abort)
    }, "vm_configuration", "vms", document_limit);
    return { [&tasks, writes = std::move(writes)](const CallContext& caller, const std::string& operation, const Json::Value& input) {
        access(caller);
        if (!input.isObject()) invalid();
        Json::Value result(Json::objectValue);
        if (operation == "read") {
            if (input.size() != 2 || !input.isMember("snapshotId")) invalid();
            const auto offset = count(input["offset"], 1 + (document_limit + chunk_bytes - 1) / chunk_bytes);
            if (input["snapshotId"].isNull()) {
                if (offset) invalid();
                const auto page = tasks.vm_config_snapshot(caller, 128u << 10);
                try { return page_json(page); }
                catch (...) { tasks.release_snapshot(caller, page.id); throw; }
            }
            return page_json(tasks.snapshot_page(caller, id(input["snapshotId"]), offset, 128u << 10));
        }
        if (operation == "release") {
            if (input.size() != 1) invalid();
            tasks.release_snapshot(caller, id(input["snapshotId"]));
        } else return writes.invoke(caller, operation, input);
        return result;
    }, std::move(defaults) };
}
}
