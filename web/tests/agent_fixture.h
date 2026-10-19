// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "web/agent_operations.h"
#include "agent/rescue_sessions.h"
#include <mutex>

// Fixed receipts and in-memory echo only. No guest or disk mutation runs.
struct FixtureAgent {
    struct Target final : droidvm::agent::RescueTarget {
        droidvm::vm::RuntimeVersion version;
        droidvm::vm::ConsoleHistory history;
        bool closed = false;
        Target() { history.append("DroidVM rescue shell\r\ndroidvm-rescue # "); }
        droidvm::vm::Observation observation() override {
            if (closed) throw droidvm::ServiceError(droidvm::ErrorCode::not_found, "Closed rescue");
            return version.observe();
        }
        droidvm::vm::LogSlice read(const droidvm::vm::Observation& expected,
                const std::optional<droidvm::vm::LogCursor>& cursor, bool tail) override {
            version.require(expected);
            return history.read(cursor, tail);
        }
        size_t write(const droidvm::vm::Observation& expected, std::string_view bytes) override {
            version.require(expected);
            history.append(bytes);
            return bytes.size();
        }
        droidvm::agent::CleanupReport close() override { closed = true; return {true, true, true}; }
    };
    droidvm::agent::RescueSessions rescues;
    std::mutex mutex;
    size_t unfinished = 0;
    bool grow_succeeds = false;
    void set_grow_success(bool value) { std::lock_guard lock(mutex); grow_succeeds = value; }
    droidvm::agent::NativeResult execute(const droidvm::CallContext& caller, droidvm::agent::Request request,
        const droidvm::agent::Confirmation& confirmation, droidvm::TaskControl& control, bool rescue) {
        using namespace droidvm;
        using namespace droidvm::agent;
        if (confirmation.disk_revision != "fixture-disk-revision" || confirmation.vm_revision != "fixture-reference-revision")
            throw ServiceError(ErrorCode::conflict, "Fixture observation changed");
        NativeResult result;
        auto& run = result.execution;
        if (!control.enter_commit()) {
            run.status = RunnerStatus::cancelled;
            run.reason = RunnerReason::cancelled;
            run.cleanup = {true, true, false};
            return result;
        }
        run.committed = true;
        run.protocol.outcome = run.protocol.guest_result = Outcome::guest_succeeded;
        run.protocol.guest_cleanup = GuestCleanup::succeeded;
        run.protocol.actions.push_back({request.action(), false, ActionState::succeeded, {}});
        if (rescue) {
            run.status = RunnerStatus::guest_reported;
            run.protocol.shell_ready = true;
            result.rescue_session_id = rescues.publish(caller, request.disk_id(), std::make_shared<Target>());
            run.handed_off = true;
        } else if (request.action() == ActionKind::password) {
            run.cleanup = {true, true, true};
            run.status = RunnerStatus::guest_reported;
            run.durability_confirmed = true;
        } else {
            std::lock_guard lock(mutex);
            if (grow_succeeds) {
                run.cleanup = {true, true, true};
                run.status = RunnerStatus::guest_reported;
                run.durability_confirmed = true;
            } else {
                unfinished = 1;
                run.status = RunnerStatus::cleanup_failed;
                run.reason = RunnerReason::host_exception;
            }
        }
        return result;
    }
    size_t pending() { std::lock_guard lock(mutex); return unfinished; }
    Json::Value recover() {
        std::lock_guard lock(mutex);
        unfinished = 0;
        Json::Value result; result["pending"] = Json::UInt64(unfinished); return result;
    }
};
