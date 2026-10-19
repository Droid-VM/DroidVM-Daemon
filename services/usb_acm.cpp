// SPDX-License-Identifier: GPL-3.0-or-later
#include "usb_acm.h"
#include "common/identity.h"
#include <algorithm>
#include <mutex>

namespace droidvm {
namespace {
void require(bool value, ErrorCode code, const char* message) { if (!value) throw ServiceError(code, message); }
void access(const CallContext& caller) {
    require(caller.authenticated && !caller.principal.empty(), ErrorCode::unauthenticated, "Authentication required");
    require(caller.administrator, ErrorCode::permission_denied, "Administrator permission required");
}
void keys(const Json::Value& value, std::initializer_list<const char*> allowed) {
    require(value.isObject(), ErrorCode::invalid_argument, "Expected USB ACM object");
    for (const auto& key : value.getMemberNames())
        require(std::any_of(allowed.begin(), allowed.end(), [&](const auto* name) { return key == name; }), ErrorCode::invalid_argument, "Unexpected USB ACM field");
}
bool token(const Json::Value& value) {
    if (!value.isString()) return false;
    const auto text = value.asString();
    return !text.empty() && text.size() <= 128 && text.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-") == std::string::npos;
}
vm::AcmDesired desired(const Json::Value& value) {
    require(value["enabled"].isBool() && value["ports"].isInt() && value["ports"].asInt() >= 1 && value["ports"].asInt() <= 6,
        ErrorCode::invalid_argument, "USB ACM requires enabled boolean and 1 to 6 ports");
    return {value["enabled"].asBool(), value["ports"].asInt()};
}
Json::Value json(const vm::AcmDesired& value) { Json::Value out; out["enabled"] = value.enabled; out["ports"] = value.ports; return out; }
Json::Value receipt(const Json::Value& expected, const Json::Value& value) {
    Json::Value out; out["expected"] = expected; out["desired"] = value;
    out["saved"] = false; out["applied"] = false; out["uncertain"] = false;
    out["revision"] = Json::Value(); out["live"] = Json::Value(); return out;
}
TaskView cancelled_receipt(TaskView view) {
    if (view.state == TaskState::cancelled && !view.result.isObject()) { view.result = receipt({}, {}); view.result_available = true; }
    return view;
}
}
struct UsbAcmService::Impl {
    TaskService& tasks;
    UsbAcmOptions io;
    mutable std::mutex mutex;
    vm::AcmDesired current;
    std::string revision = "0";
    bool initialized = false, persistence_uncertain = false, unknown_installation = false, apply_uncertain = false, apply_blocked = false;
    Impl(TaskService& service, UsbAcmOptions options) : tasks(service), io(std::move(options)) {
        require(io.pool && io.load && io.save, ErrorCode::unavailable, "USB ACM storage or pool unavailable");
        const auto loaded = io.load();
        if (loaded) {
            const auto& document = loaded->document;
            keys(document, {"version", "revision", "desired"}); keys(document["desired"], {"enabled", "ports"});
            require(document.size() == 3 && document["version"].isInt() && document["version"] == 1 && token(document["revision"]) && document["revision"] != "0",
                ErrorCode::invalid_argument, "Invalid persisted USB ACM configuration");
            current = desired(document["desired"]); revision = document["revision"].asString();
            initialized = true; persistence_uncertain = loaded->recovered;
        }
        io.pool->transaction([&](vm::AcmTransaction& pool) {
            pool.bind(initialized ? std::optional(current) : std::nullopt);
            // No first-run teardown. A recovered backup also requires an explicit
            // user operation before changing the gadget's current composition.
            if (initialized && !persistence_uncertain) {
                try { pool.admit(current); apply(pool); }
                catch (...) { apply_blocked = true; pool.bind(std::nullopt); }
            }
        });
    }
    Json::Value live(vm::AcmTransaction& pool) const {
        Json::Value out;
        try { out = pool.live(current); }
        catch (...) {
            out["available"] = false; out["applied"] = false; out["udcBound"] = Json::Value();
            out["ports"] = Json::Value(); out["owners"] = Json::Value(Json::arrayValue); out["reason"] = "observation-unavailable";
        }
        if (unknown_installation || apply_uncertain) {
            out["applied"] = false;
            out["reason"] = unknown_installation ? "persistence-outcome-unknown" : "application-outcome-unknown";
        } else if (apply_blocked) { out["applied"] = false; out["reason"] = "application-failed"; }
        else if (!initialized) { out["applied"] = false; out["reason"] = "not-initialized"; }
        return out;
    }
    Json::Value snapshot(vm::AcmTransaction& pool) const {
        Json::Value out; out["capability"] = UsbAcmService::capability; out["expected"]["revision"] = revision;
        out["desired"] = json(current); out["initialized"] = initialized;
        out["persistenceUncertain"] = persistence_uncertain; out["live"] = live(pool); return out;
    }
    UsbAcmSave save(vm::AcmTransaction& pool, const vm::AcmDesired& next) {
        Json::Value document; document["version"] = 1; document["revision"] = random_id(false); document["desired"] = json(next);
        UsbAcmSave outcome;
        try { outcome = io.save(document); }
        catch (...) {
            initialized = true; persistence_uncertain = true; unknown_installation = true; pool.bind(std::nullopt);
            throw ServiceError(ErrorCode::commit_uncertain, "USB ACM save outcome unknown");
        }
        if (outcome != UsbAcmSave::not_saved) {
            current = next; revision = document["revision"].asString(); initialized = true;
            persistence_uncertain = outcome == UsbAcmSave::installed_uncertain;
            pool.bind(current);
        }
        return outcome;
    }
    void apply(vm::AcmTransaction& pool) {
        pool.bind(current); apply_blocked = true;
        // Missing configfs at boot is a definite no-effect failure, not an
        // unknown UDC operation. It may be explicitly applied after USB is ready.
        try { require(pool.live(current)["available"].asBool(), ErrorCode::unavailable, "USB gadget is unavailable before application"); }
        catch (...) { pool.bind(std::nullopt); throw; }
        apply_uncertain = true;
        try {
            pool.apply();
            require(pool.live(current)["applied"].asBool(), ErrorCode::unavailable, "USB ACM readback does not match the saved configuration");
            apply_uncertain = false; apply_blocked = false;
        } catch (...) {
            // A mismatching but trustworthy readback is a known partial failure.
            // New acquisitions remain disabled, but an explicit apply may retry.
            try { apply_uncertain = !pool.live(current)["available"].asBool(); }
            catch (...) { apply_uncertain = true; }
            pool.bind(std::nullopt); throw;
        }
    }
    TaskCompletion operation(const Json::Value& request, TaskControl& control) {
        std::lock_guard lock(mutex);
        auto result = receipt(request["expected"], json(current));
        TaskCompletion completion = TaskCompletion::failure(ErrorCode::internal, "USB ACM operation did not run", result);
        io.pool->transaction([&](vm::AcmTransaction& pool) {
            try {
                result["live"] = live(pool);
                require(request["expected"]["revision"] == revision, ErrorCode::conflict, "USB ACM preferences changed; refresh before editing");
                require(!unknown_installation, ErrorCode::commit_uncertain, "USB ACM installation unknown; restart the daemon before writing");
                require(!apply_uncertain, ErrorCode::commit_uncertain, "USB ACM application outcome unknown; query the original request instead of replaying it");
                const bool configure = request["operation"]["kind"] == "configure";
                require(configure || initialized, ErrorCode::conflict, "USB ACM preferences have not been saved");
                const auto next = configure ? desired(request["operation"]) : current;
                pool.admit(next); // Before saving: an active slot forbids any required UDC rebind.
                if (!control.enter_commit()) { completion = TaskCompletion::cancelled(result); return; }
                if (configure) {
                    const auto outcome = save(pool, next);
                    require(outcome != UsbAcmSave::not_saved, ErrorCode::io_error, "USB ACM preferences were not saved");
                }
                result["desired"] = json(current); result["revision"] = revision;
                result["saved"] = !persistence_uncertain;
                apply(pool);
                result["live"] = live(pool); result["applied"] = true; result["uncertain"] = persistence_uncertain;
                completion = persistence_uncertain ? TaskCompletion::failure(ErrorCode::commit_uncertain, "USB ACM applied but configuration durability is unconfirmed", result)
                    : TaskCompletion::success(result);
            } catch (const ServiceError& error) {
                result["uncertain"] = unknown_installation || apply_uncertain || (result["revision"].isString() && persistence_uncertain);
                result["live"] = live(pool);
                completion = TaskCompletion::failure(error.code(), error.what(), result);
            } catch (...) {
                result["uncertain"] = unknown_installation || apply_uncertain || (result["revision"].isString() && persistence_uncertain);
                result["live"] = live(pool);
                completion = TaskCompletion::failure(result["uncertain"].asBool() ? ErrorCode::commit_uncertain : ErrorCode::unavailable,
                    "USB ACM could not be applied; inspect current state before another explicit operation", result);
            }
        });
        return completion;
    }
};
UsbAcmService::UsbAcmService(TaskService& tasks, UsbAcmOptions options) : impl_(std::make_unique<Impl>(tasks, std::move(options))) {}
UsbAcmService::~UsbAcmService() = default;
Json::Value UsbAcmService::snapshot(const CallContext& caller) const {
    access(caller); std::lock_guard lock(impl_->mutex); Json::Value out;
    impl_->io.pool->transaction([&](vm::AcmTransaction& pool) { out = impl_->snapshot(pool); }); return out;
}
Json::Value UsbAcmService::sync_legacy(const CallContext& caller, const Json::Value& config) {
    access(caller); require(config.isObject(), ErrorCode::invalid_argument, "App preferences must be an object");
    std::lock_guard lock(impl_->mutex); Json::Value out;
    impl_->io.pool->transaction([&](vm::AcmTransaction& pool) {
        if (!impl_->initialized && (config.isMember("usb_acm_enable") || config.isMember("usb_acm_ports"))) {
            auto next = impl_->current;
            if (config.isMember("usb_acm_enable")) {
                require(config["usb_acm_enable"].isBool(), ErrorCode::invalid_argument, "USB ACM enable must be boolean");
                next.enabled = config["usb_acm_enable"].asBool();
            }
            if (config.isMember("usb_acm_ports")) {
                require(config["usb_acm_ports"].isInt(), ErrorCode::invalid_argument, "USB ACM port count must be an integer");
                next.ports = std::clamp(config["usb_acm_ports"].asInt(), 1, 6);
            }
            pool.admit(next);
            require(impl_->save(pool, next) != UsbAcmSave::not_saved, ErrorCode::io_error, "USB ACM preferences were not imported");
            try { impl_->apply(pool); } catch (...) { /* Snapshot reports saved versus applied separately. */ }
        }
        out = impl_->snapshot(pool);
    }); return out;
}
TaskView UsbAcmService::start(const CallContext& caller, const Json::Value& request) {
    access(caller); keys(request, {"requestId", "expected", "operation"});
    require(request.size() == 3 && token(request["requestId"]), ErrorCode::invalid_argument, "Invalid USB ACM request ID");
    keys(request["expected"], {"revision"});
    require(request["expected"].size() == 1 && token(request["expected"]["revision"]), ErrorCode::invalid_argument, "Invalid USB ACM revision");
    const auto& operation = request["operation"];
    keys(operation, {"kind", "enabled", "ports"});
    if (operation["kind"] == "configure") { require(operation.size() == 3, ErrorCode::invalid_argument, "Incomplete USB ACM configuration"); (void)desired(operation); }
    else require(operation.size() == 1 && operation["kind"] == "apply", ErrorCode::invalid_argument, "Invalid USB ACM operation");
    Json::StreamWriterBuilder writer; writer["indentation"] = "";
    TaskSpec spec; spec.kind = "usb_acm"; spec.resource = "usb-acm"; spec.request_id = request["requestId"].asString();
    spec.request_signature = Json::writeString(writer, request); spec.result_bytes = 8192; spec.background = true;
    const auto ref = impl_->tasks.submit(caller, std::move(spec), [impl = impl_.get(), request](TaskControl& control) { return impl->operation(request, control); });
    return cancelled_receipt(impl_->tasks.get(caller, ref));
}
TaskView UsbAcmService::status(const CallContext& caller, const std::string& request_id) {
    access(caller); require(token(Json::Value(request_id)), ErrorCode::invalid_argument, "Invalid USB ACM request ID");
    const auto found = impl_->tasks.find_request(caller, request_id);
    require(found && found->kind == "usb_acm" && found->resource == "usb-acm", ErrorCode::task_not_found, "USB ACM operation is not retained");
    return cancelled_receipt(impl_->tasks.get(caller, found->ref));
}
}
