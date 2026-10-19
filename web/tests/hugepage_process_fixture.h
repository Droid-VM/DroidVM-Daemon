// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "web/hugepage_processes.h"
#include "common/wire.h"
#include <mutex>

namespace droidvm::web {
// Synthetic process identities only: never reads /proc or sends a signal.
struct FixtureHugepageProcesses {
    std::mutex mutex;
    std::string mode = "ready";
    uint64_t revision = 1, reads = 0, stack_reads = 0, effects = 0;
    static TaskView receipt(TaskView task) {
        if (task.kind == "hugepage_process_signal" && task.state == TaskState::cancelled && task.result.isNull()) {
            task.result["signal"] = Json::Value(); task.result["expected"] = Json::Value();
            task.result["sent"] = false; task.result["uncertain"] = false; task.result["exited"] = false; task.result_available = true;
        }
        return task;
    }
    Json::Value identity(const std::string& source) const {
        Json::Value value;
        value["pid"] = 42420; value["startTicks"] = std::to_string(10000 + revision);
        value["source"] = source; value["membership"] = "fixture:" + source + ":" + std::to_string(revision);
        return value;
    }
    bool available() const { return mode != "unknown" && mode != "empty" && mode != "exited" && mode != "reused"; }
    Json::Value snapshot_locked(const std::string& requested) const {
        const auto selected = requested == "scan" || (requested == "auto" && mode == "fallback") ? "scan" : "ko";
        const bool missing = mode == "unknown" || (requested == "ko" && mode == "fallback");
        const bool partial = mode == "partial";
        Json::Value value;
        value["capability"] = "hugepage-processes-v1"; value["requestedSource"] = requested; value["source"] = selected;
        value["available"] = !missing; value["partial"] = partial || missing;
        value["coverage"] = std::string_view(selected) == "ko" ? "module-owners" : "running-vms";
        value["fallbackReason"] = requested == "auto" && mode == "fallback" ? Json::Value("ko-unavailable") : Json::Value();
        value["observedAtMs"] = "1700000000000"; value["pageBytes"] = "2097152";
        auto& rows = value["entries"] = Json::Value(Json::arrayValue);
        auto& issues = value["issues"] = Json::Value(Json::arrayValue);
        if (missing) issues.append("ko-unavailable");
        if (partial) issues.append("process-unreadable");
        const bool populated = !missing && mode != "empty";
        if (populated) {
            Json::Value row;
            row["pid"] = 42420; row["name"] = "fixture-qemu"; row["source"] = selected;
            row["pages"] = partial ? Json::Value() : Json::Value("512");
            row["bytes"] = partial ? Json::Value() : Json::Value("1073741824");
            row["state"] = mode == "d-state" || mode == "uncertain" ? "D" : "S";
            row["alive"] = mode != "exited";
            row["identityStatus"] = mode == "reused" ? "changed" : mode == "exited" ? "exited" : "verified";
            row["attributionVerified"] = mode != "legacy";
            row["startTicks"] = identity(selected)["startTicks"];
            row["vm"]["id"] = "fixture-hugepage-vm"; row["vm"]["name"] = "Hugepage fixture VM";
            row["vm"]["runtimeInstance"] = "fixture-instance-" + std::to_string(revision); row["vm"]["runtimeRevision"] = std::to_string(revision);
            row["expected"] = available() ? identity(mode == "legacy" ? "scan" : selected) : Json::Value();
            row["canSignal"] = available(); row["canStack"] = available() && row["state"] == "D";
            row["reason"] = mode == "legacy" ? Json::Value("ko-owner-unverified") : mode == "reused" ? Json::Value("process-changed") : mode == "exited" ? Json::Value("process-exited") : Json::Value();
            row["private"] = "/private/not-for-browser";
            rows.append(row);
            if (std::string_view(selected) == "ko") {
                row["pid"] = 42421; row["name"] = "legacy-owner"; row["pages"] = "128"; row["bytes"] = "268435456";
                row["identityStatus"] = "unverified"; row["attributionVerified"] = false; row["startTicks"] = Json::Value();
                row["vm"] = Json::Value(); row["expected"] = Json::Value(); row["alive"] = Json::Value(); row["state"] = Json::Value();
                row["canSignal"] = false; row["canStack"] = false; row["reason"] = "identity-unverified"; rows.append(row);
            }
        }
        const auto known_pages = !populated ? 0u : std::string_view(selected) == "ko" ? (partial ? 128u : 640u) : partial ? 0u : 512u;
        value["totals"]["knownPages"] = std::to_string(known_pages);
        value["totals"]["knownBytes"] = std::to_string(uint64_t(known_pages) * 2097152);
        value["totals"]["pages"] = missing || partial ? Json::Value() : value["totals"]["knownPages"];
        value["totals"]["bytes"] = missing || partial ? Json::Value() : value["totals"]["knownBytes"];
        return value;
    }
    void verify_locked(const Json::Value& expected) const {
        const auto source = expected["source"].asString();
        if (!available() || expected != identity(source) || (source == "ko" && (mode == "legacy" || mode == "fallback")))
            throw ServiceError(ErrorCode::conflict, "Fixture process identity changed");
    }
    HugepageProcessBindings bindings(TaskService& tasks) {
        return {
            [this](const CallContext&, const std::string& source) { std::lock_guard lock(mutex); ++reads; return snapshot_locked(source); },
            [this](const CallContext&, const Json::Value& expected) {
                std::lock_guard lock(mutex); ++stack_reads; verify_locked(expected);
                const bool is_d = mode == "d-state" || mode == "uncertain";
                Json::Value value; value["expected"] = expected; value["available"] = is_d; value["truncated"] = false;
                value["text"] = is_d ? Json::Value("fixture_wait\nfixture_io\n") : Json::Value();
                value["reason"] = is_d ? Json::Value() : Json::Value("not-d-state"); return value;
            },
            [this, &tasks](const CallContext& caller, const Json::Value& input) {
                TaskSpec spec{"hugepage_process_signal", "hugepage-processes", 4096, true, true};
                spec.request_id = input["requestId"].asString();
                auto signature = input; signature.removeMember("requestId"); spec.request_signature = wire::stringify_bounded(signature, 2048);
                const auto ref = tasks.submit(caller, spec, [this, input](TaskControl& control) {
                    Json::Value receipt; receipt["expected"] = input["expected"]; receipt["signal"] = input["signal"];
                    receipt["sent"] = false; receipt["uncertain"] = false; receipt["exited"] = false;
                    std::lock_guard lock(mutex);
                    try { verify_locked(input["expected"]); }
                    catch (const ServiceError& error) { return TaskCompletion::failure(error.code(), "Fixture process identity changed", receipt); }
                    if (!control.enter_commit()) return TaskCompletion::cancelled(receipt);
                    ++effects;
                    const bool uncertain = mode == "uncertain";
                    const bool exited = input["signal"] == "kill" && mode == "ready";
                    receipt["sent"] = true; receipt["uncertain"] = uncertain; receipt["exited"] = exited;
                    if (exited) mode = "exited";
                    receipt["private"] = "/private/not-for-browser";
                    return uncertain ? TaskCompletion::failure(ErrorCode::commit_uncertain, "Fixture outcome unknown", receipt) : TaskCompletion::success(receipt);
                });
                return receipt(tasks.get(caller, ref));
            },
            [&tasks](const CallContext& caller, const std::string& request_id) {
                const auto task = tasks.find_request(caller, request_id);
                if (!task) throw ServiceError(ErrorCode::task_not_found, "Task not found");
                return receipt(*task);
            }
        };
    }
};
}
