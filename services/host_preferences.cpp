// SPDX-License-Identifier: GPL-3.0-or-later
#include "host_preferences.h"
#include "common/identity.h"
#include <algorithm>
#include <array>
#include <mutex>
#include <charconv>
#include <set>
#include <string_view>

namespace droidvm {
namespace {
constexpr std::array names{"vm_hugepage_auto_reserve", "optimize_sdcard", "vm_clear_logs_before_start"};
struct PreferenceProfile { const char* capability; const char* kind; const char* resource; size_t result_bytes; };
const PreferenceProfile& profile(HostPreferenceDomain domain) {
    static const PreferenceProfile host{HostPreferencesService::capability, "host_preferences", "host-preferences", 4096};
    static const PreferenceProfile disks{HostPreferencesService::disk_defaults_capability, "disk_defaults", "disk-defaults", 32u << 10};
    return domain == HostPreferenceDomain::disk_operations ? disks : host;
}
void require(bool condition, ErrorCode code, const char* message) {
    if (!condition) throw ServiceError(code, message);
}
void access(const CallContext& caller) {
    require(caller.authenticated && !caller.principal.empty(), ErrorCode::unauthenticated, "Authentication required");
    require(caller.administrator, ErrorCode::permission_denied, "Administrator permission required");
}
void keys(const Json::Value& value, std::initializer_list<const char*> allowed) {
    require(value.isObject(), ErrorCode::invalid_argument, "Expected an object");
    for (const auto& key : value.getMemberNames())
        require(std::any_of(allowed.begin(), allowed.end(), [&](const auto* name) { return key == name; }),
            ErrorCode::invalid_argument, "Unexpected host preference field");
}
bool valid_token(const Json::Value& value) {
    if (!value.isString()) return false;
    const auto text = value.asString();
    return !text.empty() && text.size() <= 128 && text.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-") == std::string::npos;
}
void validate_values(HostPreferenceDomain domain, const Json::Value& values, bool complete) {
    if (domain == HostPreferenceDomain::disk_operations) {
        keys(values, {"optimizeCompression", "qemuImgCpus"});
        require(complete ? values.size() == 2 : !values.empty(), ErrorCode::invalid_argument, "Invalid disk defaults");
        if (values.isMember("optimizeCompression"))
            require(values["optimizeCompression"] == "ask" || values["optimizeCompression"] == "none", ErrorCode::invalid_argument, "Unsupported optimize compression default");
        if (values.isMember("qemuImgCpus")) {
            const auto& cpus = values["qemuImgCpus"];
            require(cpus.isArray() && cpus.size() <= 1024, ErrorCode::invalid_argument, "CPU defaults must be an array of at most 1024 cores");
            std::set<int> seen;
            for (const auto& cpu : cpus)
                require(cpu.isInt() && cpu.asInt() >= 0 && cpu.asInt() <= 1023 && seen.insert(cpu.asInt()).second,
                    ErrorCode::invalid_argument, "CPU defaults must contain unique core indices between 0 and 1023");
        }
        return;
    }
    keys(values, {names[0], names[1], names[2]});
    require(complete ? values.size() == 3 : !values.empty(), ErrorCode::invalid_argument, "Invalid host preference values");
    for (const auto& name : values.getMemberNames())
        require(values[name].isBool(), ErrorCode::invalid_argument, "Host preferences must be booleans");
}
Json::Value defaults(HostPreferenceDomain domain) {
    Json::Value out(Json::objectValue);
    if (domain == HostPreferenceDomain::disk_operations) {
        out["optimizeCompression"] = "ask"; out["qemuImgCpus"] = Json::Value(Json::arrayValue); return out;
    }
    out[names[0]] = true; out[names[1]] = true; out[names[2]] = false;
    return out;
}
Json::Value normalized(HostPreferenceDomain domain, Json::Value values) {
    if (domain == HostPreferenceDomain::disk_operations && values.isMember("qemuImgCpus")) {
        std::set<int> cpus;
        for (const auto& cpu : values["qemuImgCpus"]) cpus.insert(cpu.asInt());
        auto& list = values["qemuImgCpus"] = Json::Value(Json::arrayValue);
        for (const auto cpu : cpus) list.append(cpu);
    }
    return values;
}
std::string_view trim(std::string_view value) {
    constexpr std::string_view whitespace = " \t\r\n";
    const auto begin = value.find_first_not_of(whitespace);
    if (begin == std::string_view::npos) return {};
    return value.substr(begin, value.find_last_not_of(whitespace) - begin + 1);
}
int cpu_number(std::string_view text) {
    text = trim(text); int value = -1;
    require(!text.empty(), ErrorCode::invalid_argument, "Legacy CPU preference contains an empty core index");
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    require(error == std::errc() && end == text.data() + text.size() && value >= 0 && value <= 1023,
        ErrorCode::invalid_argument, "Legacy CPU preference contains an invalid core index");
    return value;
}
Json::Value legacy_cpus(const Json::Value& value) {
    require(value.isString() && value.asString().size() <= 16u << 10, ErrorCode::invalid_argument, "Legacy CPU preference must be a bounded CPU list");
    const auto storage = value.asString(); auto input = trim(storage);
    Json::Value out(Json::arrayValue); std::set<int> cpus;
    if (input.empty()) return out;
    for (;;) {
        const auto separator = input.find(','); const auto item = trim(input.substr(0, separator));
        const auto dash = item.find('-');
        const int first = cpu_number(item.substr(0, dash));
        const int last = dash == std::string_view::npos ? first : cpu_number(item.substr(dash + 1));
        require(first <= last, ErrorCode::invalid_argument, "Legacy CPU preference contains a reversed range");
        for (int cpu = first; cpu <= last; ++cpu) cpus.insert(cpu);
        if (separator == std::string_view::npos) break;
        input.remove_prefix(separator + 1);
        require(!trim(input).empty(), ErrorCode::invalid_argument, "Legacy CPU preference contains an empty element");
    }
    for (const auto cpu : cpus) out.append(cpu);
    return out;
}
Json::Value legacy_changes(HostPreferenceDomain domain, const Json::Value& config) {
    Json::Value out(Json::objectValue);
    if (domain == HostPreferenceDomain::disk_operations) {
        if (config.isMember("vm_optimize_compression"))
            out["optimizeCompression"] = config["vm_optimize_compression"] == "none" ? "none" : "ask";
        if (config.isMember("qemu_img_cpu_affinity")) out["qemuImgCpus"] = legacy_cpus(config["qemu_img_cpu_affinity"]);
    } else for (const auto* name : names) if (config.isMember(name)) {
        require(config[name].isBool(), ErrorCode::invalid_argument, "Shared App preference must be a boolean"); out[name] = config[name];
    }
    return out;
}
Json::Value receipt(const Json::Value& expected, const Json::Value& values) {
    Json::Value out;
    out["expected"] = expected; out["values"] = values; out["saved"] = false;
    out["uncertain"] = false; out["revision"] = Json::Value();
    return out;
}
TaskView cancelled_receipt(TaskView view) {
    if (view.state == TaskState::cancelled && !view.result.isObject()) {
        view.result = receipt({}, {}); view.result_available = true;
    }
    return view;
}
}
void validate_host_preference_values(const Json::Value& values, bool complete, HostPreferenceDomain domain) {
    validate_values(domain, values, complete);
}
struct HostPreferencesService::Impl {
    TaskService& tasks;
    HostPreferencesOptions io;
    mutable std::mutex mutex;
    Json::Value current;
    std::string revision = "0";
    bool initialized = false, uncertain = false, unknown_installation = false;
    Impl(TaskService& service, HostPreferencesOptions options) : tasks(service), io(std::move(options)) {
        current = defaults(io.domain);
        require(bool(io.load) && bool(io.save), ErrorCode::unavailable, "Host preference storage is unavailable");
        const auto loaded = io.load(); // Corruption/read errors must never become an empty first-run store.
        if (!loaded) return;
        const auto& document = loaded->document;
        keys(document, {"version", "revision", "values"});
        require(document.size() == 3 && document["version"].isInt() && document["version"].asInt() == 1 &&
            valid_token(document["revision"]) && document["revision"] != "0", ErrorCode::invalid_argument, "Invalid persisted host preferences");
        validate_values(io.domain, document["values"], true);
        current = normalized(io.domain, document["values"]); revision = document["revision"].asString();
        initialized = true; uncertain = loaded->recovered;
    }
    Json::Value snapshot_locked() const {
        Json::Value out;
        out["capability"] = profile(io.domain).capability; out["expected"]["revision"] = revision;
        out["values"] = current; out["initialized"] = initialized; out["uncertain"] = uncertain;
        return out;
    }
    // Called under the same lock for CAS and first-time legacy migration.
    HostPreferencesSave save_locked(const Json::Value& next) {
        require(!unknown_installation, ErrorCode::commit_uncertain, "Previous preference installation is unknown; reload the daemon before writing");
        Json::Value document;
        document["version"] = 1; document["revision"] = random_id(false); document["values"] = next;
        HostPreferencesSave outcome;
        try { outcome = io.save(document); }
        catch (...) {
            // An arbitrary injected/store exception makes no promise about whether
            // rename happened. Keep the last observed values, prohibit migration.
            unknown_installation = true; uncertain = true; initialized = true;
            throw ServiceError(ErrorCode::commit_uncertain, "Host preference save outcome is unknown");
        }
        if (outcome != HostPreferencesSave::not_saved) {
            current = next; revision = document["revision"].asString(); initialized = true;
            uncertain = outcome == HostPreferencesSave::installed_uncertain;
        }
        return outcome;
    }
    TaskCompletion patch(const Json::Value& request, TaskControl& control) {
        std::lock_guard lock(mutex);
        auto result = receipt(request["expected"], current);
        try {
            require(request["expected"]["revision"] == revision, ErrorCode::conflict, "Host preferences changed; refresh before editing");
            require(!unknown_installation, ErrorCode::commit_uncertain, "Host preference save outcome is unknown");
            auto next = current;
            for (const auto& key : request["changes"].getMemberNames()) next[key] = request["changes"][key];
            next = normalized(io.domain, std::move(next));
            if (!control.enter_commit()) return TaskCompletion::cancelled(result);
            const auto outcome = save_locked(next);
            result["values"] = current;
            if (outcome == HostPreferencesSave::not_saved)
                return TaskCompletion::failure(ErrorCode::io_error, "Host preferences were not saved", result);
            result["revision"] = revision;
            result["uncertain"] = uncertain;
            result["saved"] = outcome == HostPreferencesSave::saved;
            if (uncertain) return TaskCompletion::failure(ErrorCode::commit_uncertain, "Host preferences installed but durability is unconfirmed", result);
            return TaskCompletion::success(result);
        } catch (const ServiceError& error) {
            result["uncertain"] = error.code() == ErrorCode::commit_uncertain;
            return TaskCompletion::failure(error.code(), error.what(), result);
        } catch (...) {
            return TaskCompletion::failure(ErrorCode::internal, "Host preference operation failed", result);
        }
    }
};
HostPreferencesService::HostPreferencesService(TaskService& tasks, HostPreferencesOptions options)
    : impl_(std::make_unique<Impl>(tasks, std::move(options))) {}
HostPreferencesService::~HostPreferencesService() = default;
Json::Value HostPreferencesService::snapshot(const CallContext& caller) const {
    access(caller); std::lock_guard lock(impl_->mutex); return impl_->snapshot_locked();
}
Json::Value HostPreferencesService::values() const {
    std::lock_guard lock(impl_->mutex);
    require(!impl_->unknown_installation, ErrorCode::commit_uncertain, "Host preference installation is unknown; runtime start is unavailable");
    return impl_->current;
}
Json::Value HostPreferencesService::sync_legacy(const CallContext& caller, const Json::Value& config) {
    access(caller); require(config.isObject(), ErrorCode::invalid_argument, "App preferences must be an object");
    std::lock_guard lock(impl_->mutex);
    // Once initialized, do not even parse stale App values. An old client cannot
    // break synchronization by supplying an obsolete or malformed legacy key.
    const auto changes = impl_->initialized ? Json::Value(Json::objectValue) : legacy_changes(impl_->io.domain, config);
    if (!changes.empty()) {
        auto next = impl_->current;
        for (const auto& name : changes.getMemberNames()) next[name] = changes[name];
        const auto outcome = impl_->save_locked(next);
        require(outcome != HostPreferencesSave::not_saved, ErrorCode::io_error, "Shared App preferences were not imported");
    }
    return impl_->snapshot_locked();
}
TaskView HostPreferencesService::start(const CallContext& caller, const Json::Value& request) {
    access(caller); keys(request, {"requestId", "expected", "changes"});
    require(request.size() == 3 && valid_token(request["requestId"]), ErrorCode::invalid_argument, "Invalid preference request ID");
    keys(request["expected"], {"revision"});
    require(request["expected"].size() == 1 && valid_token(request["expected"]["revision"]), ErrorCode::invalid_argument, "Invalid preference revision");
    validate_values(impl_->io.domain, request["changes"], false);
    Json::StreamWriterBuilder writer; writer["indentation"] = "";
    const auto& domain = profile(impl_->io.domain);
    TaskSpec spec; spec.kind = domain.kind; spec.resource = domain.resource;
    spec.request_id = request["requestId"].asString(); spec.request_signature = Json::writeString(writer, request);
    spec.result_bytes = domain.result_bytes; spec.background = true;
    const auto ref = impl_->tasks.submit(caller, std::move(spec), [impl = impl_.get(), request](TaskControl& control) { return impl->patch(request, control); });
    return cancelled_receipt(impl_->tasks.get(caller, ref));
}
TaskView HostPreferencesService::status(const CallContext& caller, const std::string& request_id) {
    access(caller); require(valid_token(Json::Value(request_id)), ErrorCode::invalid_argument, "Invalid preference request ID");
    const auto found = impl_->tasks.find_request(caller, request_id);
    const auto& domain = profile(impl_->io.domain);
    require(found && found->kind == domain.kind && found->resource == domain.resource, ErrorCode::task_not_found, "Host preference operation is not retained");
    return cancelled_receipt(impl_->tasks.get(caller, found->ref));
}
}
