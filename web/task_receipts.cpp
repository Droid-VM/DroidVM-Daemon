// SPDX-License-Identifier: GPL-3.0-or-later
#include "task_receipts.h"
#include "task_adapter.h"
#include "common/identity.h"
#include "common/wire.h"
#include <algorithm>
#include <chrono>
#include <mutex>
#include <set>

namespace droidvm::web {
namespace {
constexpr size_t max_records = 256, max_record_bytes = 32u << 10, max_store_bytes = 2u << 20;
constexpr uint64_t retention_ms = 30ull * 24 * 60 * 60 * 1000;
uint64_t wall_ms() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}
bool token(const Json::Value& value) {
    if (!value.isString()) return false;
    const auto text = value.asString();
    return !text.empty() && text.size() <= 128 &&
        text.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") == std::string::npos;
}
bool recoverable(const std::string& kind) {
    static const std::set<std::string> kinds{
        "image_install", "image_import", "vm_configuration", "network_configuration", "network_deletion",
        "usb_rules", "configuration_backup", "configuration_recovery", "network_lifecycle",
        "disk_operation", "disk_recovery", "agent_operation", "agent_recovery"
    };
    return kinds.contains(kind);
}
Json::Value projected_version(const TaskView& task) {
    if (task.state != TaskState::succeeded || !task.result.isObject()) return {};
    if (task.kind != "vm_configuration" && task.kind != "network_configuration" &&
        task.kind != "network_deletion" && task.kind != "usb_rules") return {};
    Json::Value result(Json::objectValue);
    for (const auto* key : {"revision", "networkId", "vmRevision"})
        if (token(task.result[key])) result[key] = task.result[key];
    for (const auto* key : {"persisted", "recovered", "durabilityUncertain"})
        if (task.result[key].isBool()) result[key] = task.result[key];
    for (const auto* key : {"applied", "updatedCount"})
        if (task.result[key].isUInt()) result[key] = task.result[key];
    const auto& persistence = task.result["persistence"];
    if (persistence == "persisted" || persistence == "uncertain" || persistence == "volatile")
        result["persistence"] = persistence;
    return result;
}
Json::Value project(const TaskView& task) {
    Json::Value result;
    result["epoch"] = task.ref.epoch;
    result["status"] = task_terminal(task.state) ? "terminal" : "unknown";
    result["task"] = task_view(task);
    // Rescue custody is a live lease, not a completed operation. Never persist
    // its session handle or let a later browser reattach from a stale receipt.
    if (result["task"].isMember("agentResult") && result["task"]["agentResult"]["outcome"] == "rescue_ready") {
        result["task"].removeMember("agentResult");
        result["status"] = "unknown";
    }
    // Historical records are evidence, never cancellation handles.
    result["task"]["cancellable"] = false;
    const auto version = projected_version(task);
    if (!version.isNull()) result["version"] = version;
    return result;
}
class Receipts {
public:
    explicit Receipts(TaskReceiptPersistence persistence) : persistence_(std::move(persistence)) {
        if (!persistence_.load || !persistence_.save) throw std::invalid_argument("Missing receipt persistence");
        saved_ = persistence_.load();
        if (saved_.isNull()) {
            saved_["schema"] = 1;
            saved_["hostId"] = random_id(true);
            saved_["records"] = Json::Value(Json::arrayValue);
            persistence_.save(saved_);
        }
        if (!saved_.isObject() || saved_["schema"] != 1 || !token(saved_["hostId"]) ||
            !saved_["records"].isArray() || saved_["records"].size() > max_records)
            throw std::runtime_error("Invalid operation receipts");
        (void)wire::stringify_bounded(saved_, max_store_bytes);
        for (const auto& row : saved_["records"]) {
            const auto& task = row["receipt"]["task"];
            if (!row["savedMs"].isUInt64() || !token(row["receipt"]["epoch"]) || !token(task["requestId"]) ||
                !token(task["id"]) || !task["kind"].isString() || !recoverable(task["kind"].asString()) ||
                (row["receipt"]["status"] != "unknown" && row["receipt"]["status"] != "terminal"))
                throw std::runtime_error("Invalid operation receipt");
        }
    }
    std::string host_id() const { return saved_["hostId"].asString(); }
    void observe(const TaskView& task) {
        if (!recoverable(task.kind) || !token(Json::Value(task.request_id))) return;
        auto receipt = project(task);
        (void)wire::stringify_bounded(receipt, max_record_bytes);
        std::lock_guard lock(mutex_);
        auto next = saved_;
        auto& records = next["records"];
        Json::Value kept(Json::arrayValue);
        const auto now = wall_ms();
        for (const auto& row : records) {
            const auto time = row["savedMs"].asUInt64();
            if (row["receipt"]["epoch"] == task.ref.epoch && row["receipt"]["task"]["id"] == task.ref.id) continue;
            if (now >= time && now - time > retention_ms) continue;
            kept.append(row);
        }
        while (kept.size() >= max_records) kept.removeIndex(0, nullptr);
        Json::Value row;
        row["savedMs"] = Json::UInt64(now);
        row["receipt"] = std::move(receipt);
        kept.append(std::move(row));
        records = std::move(kept);
        while (records.size() > 1) {
            try { (void)wire::stringify_bounded(next, max_store_bytes); break; }
            catch (const std::length_error&) { records.removeIndex(0, nullptr); }
        }
        persistence_.save(next);
        saved_ = std::move(next);
    }
    Json::Value lookup(TaskService& tasks, const CallContext& caller, const std::string& request_id) {
        if (!token(Json::Value(request_id))) throw ServiceError(ErrorCode::invalid_argument, "Invalid request ID");
        const auto live = tasks.find_request_for_recovery(caller, request_id);
        Json::Value result;
        {
            std::lock_guard lock(mutex_);
            const auto now = wall_ms();
            for (const auto& row : saved_["records"]) {
                const auto time = row["savedMs"].asUInt64();
                if (now >= time && now - time > retention_ms) continue;
                const auto& receipt = row["receipt"];
                if (receipt["task"]["requestId"] != request_id) continue;
                if (!result.isNull() || (live && (receipt["epoch"] != live->ref.epoch || receipt["task"]["id"] != live->ref.id)))
                    throw ServiceError(ErrorCode::conflict, "Ambiguous recovery request");
                result = receipt;
            }
        }
        if (live && recoverable(live->kind)) {
            result = project(*live);
            // Current terminal state is valid evidence even if the final store
            // write failed. On restart its persisted unknown row stays unknown.
            if (!task_terminal(live->state)) result["status"] = "active";
        }
        return result;
    }
private:
    TaskReceiptPersistence persistence_;
    Json::Value saved_;
    std::mutex mutex_;
};
}
void bind_task_receipts(TaskService& tasks, TaskReceiptPersistence persistence) {
    const auto receipts = std::make_shared<Receipts>(std::move(persistence));
    tasks.observe_receipts([receipts](const TaskView& task) { receipts->observe(task); }, receipts->host_id(),
        [receipts, &tasks](const CallContext& caller, const std::string& id) { return receipts->lookup(tasks, caller, id); });
}
}
