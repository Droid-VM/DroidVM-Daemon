// SPDX-License-Identifier: GPL-3.0-or-later
#include "http_api.h"
#include "vm_terminal_source.h"
#include "vm_display.h"
#include <algorithm>
#include <charconv>
#include <memory>

namespace droidvm::web {
namespace {
bool rescue_available(const AgentRescueOperations& rescue) {
    return rescue.list && rescue.close.submit && rescue.close.find && rescue.terminal_source
        && rescue.terminal_source->list && rescue.terminal_source->read && rescue.terminal_source->write;
}
bool transfers_available(const PackageTransferOperations& value) {
    return value.uploads.begin && value.uploads.status && value.uploads.append && value.uploads.finish && value.uploads.erase
        && value.downloads.begin && value.downloads.status && value.downloads.file && value.downloads.erase;
}
bool image_uploads_available(const ImageUploadOperations& value) {
    return value.uploads.begin && value.uploads.status && value.uploads.append && value.uploads.finish && value.uploads.erase
        && value.installs.submit && value.installs.find;
}
bool same_name(std::string_view left, std::string_view right) {
    if (left.size() != right.size()) return false;
    for (size_t i = 0; i < left.size(); ++i) {
        char c = left[i]; if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
        if (c != right[i]) return false;
    }
    return true;
}
std::string_view trim(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
    return value;
}
[[noreturn]] void invalid() { throw ServiceError(ErrorCode::invalid_argument, "Invalid HTTP request"); }
// Only use on freshly parsed, mutable JSON: its string values own their bytes.
// The transport still owns HttpRequest::body; this boundary cannot erase that
// const input, parser temporaries, or copies made by an adapter.
void erase_parsed_strings(Json::Value& value) noexcept {
    if (value.isString()) {
        const char* begin = nullptr;
        const char* end = nullptr;
        if (value.getString(&begin, &end)) {
            volatile char* bytes = const_cast<char*>(begin);
            for (size_t i = 0; i < static_cast<size_t>(end - begin); ++i) bytes[i] = 0;
        }
    } else if (value.isObject() || value.isArray()) {
        for (auto& entry : value) erase_parsed_strings(entry);
    }
}
struct ParsedSecretGuard {
    Json::Value* value;
    ~ParsedSecretGuard() { if (value) erase_parsed_strings(*value); }
};
// HTTP qvalue is at most three decimal digits, not a general floating point number.
int encoding_quality(std::string_view value) {
    if (value.empty() || (value.front() != '0' && value.front() != '1')) return 0;
    const bool one = value.front() == '1';
    value.remove_prefix(1);
    if (value.empty()) return one ? 1000 : 0;
    if (value.front() != '.' || value.size() > 4) return 0;
    value.remove_prefix(1);
    int result = 0, factor = 100;
    for (char c : value) {
        if (c < '0' || c > '9' || (one && c != '0')) return 0;
        result += (c - '0') * factor; factor /= 10;
    }
    return one ? 1000 : result;
}
}
HttpApi::HttpApi(SessionStore& sessions, std::vector<AccessOrigin> origins, ListVms list_vms, ServerInfo server,
    std::span<const StaticAsset> assets, TaskOperations tasks, VmOperations vms, VmLogs logs, bool events, ConfigOperations config, ResourceCatalogs resources, UsbOperations usb, ConfigOperations usb_rules)
    : sessions_(sessions), origins_(std::move(origins)), list_vms_(std::move(list_vms)), server_(std::move(server)), tasks_(std::move(tasks)), vms_(std::move(vms)), logs_(std::move(logs)), events_(events), config_(std::move(config)), resources_(std::move(resources)), usb_(std::move(usb)), usb_rules_(std::move(usb_rules)), assets_(assets) {
    if (origins_.empty() || origins_.size() > 64 || !list_vms_) throw std::invalid_argument("Missing HTTP API configuration");
    if (server_.daemon_epoch.empty() || server_.daemon_epoch.size() > 128 ||
        server_.build.version.empty() || server_.build.version.size() > 128 ||
        server_.build.version_code.empty() || server_.build.version_code.size() > 20 ||
        server_.build.version_code.find_first_not_of("0123456789") != std::string::npos)
        throw std::invalid_argument("Missing WebUI server metadata");
    validate_origins(origins_);
}
void HttpApi::validate_origins(const std::vector<AccessOrigin>& origins) {
    if (origins.empty() || origins.size() > 64) throw std::invalid_argument("Invalid HTTP origin count");
    for (const auto& entry : origins) {
        if (entry.authority.empty() || entry.authority.size() > 255 || entry.origin != "http://" + entry.authority ||
            std::any_of(entry.authority.begin(), entry.authority.end(), [](unsigned char c) {
                return c <= 32 || c >= 127 || c == '/' || c == '\\' || c == '@' || c == '?' || c == '#';
            })) throw std::invalid_argument("Invalid HTTP origin configuration");
    }
}
std::optional<std::string_view> HttpApi::header(const HttpRequest& request, std::string_view name) {
    std::optional<std::string_view> result;
    for (const auto& entry : request.headers) if (same_name(entry.first, name)) {
        if (result) invalid();
        result = trim(entry.second);
    }
    return result;
}
void HttpApi::check_origin(const HttpRequest& request, bool required) const {
    if (request.headers.size() > 64) invalid();
    size_t header_bytes = 0;
    for (const auto& [name, value] : request.headers) {
        if (name.size() > 8192 || value.size() > 8192 || header_bytes > 8192 - name.size()) invalid();
        header_bytes += name.size();
        if (header_bytes > 8192 - value.size()) invalid();
        header_bytes += value.size();
        if (name.empty() || std::any_of(name.begin(), name.end(), [](unsigned char c) { return c <= 32 || c >= 127 || c == ':'; }) ||
            std::any_of(value.begin(), value.end(), [](unsigned char c) { return (c < 32 && c != '\t') || c == 127; })) invalid();
    }
    const auto host = header(request, "host"), origin = header(request, "origin");
    if (!host || (required && !origin)) throw ServiceError(ErrorCode::permission_denied, "Origin rejected");
    const bool allowed = std::any_of(origins_.begin(), origins_.end(), [&](const AccessOrigin& entry) {
        return *host == entry.authority && (!origin || *origin == entry.origin);
    });
    if (!allowed) throw ServiceError(ErrorCode::permission_denied, "Origin rejected");
}
std::string HttpApi::cookie(const HttpRequest& request, std::string_view name) {
    const auto field = header(request, "cookie");
    if (!field) return {};
    std::string result;
    bool found = false;
    auto remaining = *field;
    while (!remaining.empty()) {
        const auto semicolon = remaining.find(';');
        const auto part = trim(remaining.substr(0, semicolon));
        const auto equal = part.find('=');
        if (equal != std::string_view::npos && trim(part.substr(0, equal)) == name) {
            if (found) invalid();
            found = true;
            result = std::string(trim(part.substr(equal + 1)));
        }
        if (semicolon == std::string_view::npos) break;
        remaining.remove_prefix(semicolon + 1);
    }
    return result;
}
Json::Value HttpApi::parse_pairing(const HttpRequest& request) {
    auto result = parse_object(request);
    if (!result["pairingToken"].isString() ||
        result.size() != (result.isMember("remember") ? 2u : 1u) ||
        (result.isMember("remember") && !result["remember"].isBool())) invalid();
    return result;
}
Json::Value HttpApi::parse_object(const HttpRequest& request) {
    const auto content_type = header(request, "content-type");
    if (!content_type || (*content_type != "application/json" && *content_type != "application/json; charset=utf-8")) invalid();
    Json::CharReaderBuilder builder;
    builder["collectComments"] = false;
    builder["allowComments"] = false;
    builder["allowTrailingCommas"] = false;
    builder["strictRoot"] = true;
    builder["failIfExtra"] = true;
    builder["rejectDupKeys"] = true;
    builder["stackLimit"] = 8;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    Json::Value result;
    ParsedSecretGuard secret{request.path == "/api/v1/agent-operations" ? &result : nullptr};
    bool parsed = false;
    try { parsed = reader->parse(request.body.data(), request.body.data() + request.body.size(), &result, nullptr); }
    catch (const Json::Exception&) { invalid(); }
    if (!parsed || !result.isObject()) invalid();
    secret.value = nullptr; // Successful callers guard the returned parsed owner.
    return result;
}
Json::Value HttpApi::server_json() const {
    Json::Value value(Json::objectValue);
    value["apiMajor"] = 1; value["apiMinor"] = 0;
    value["daemonEpoch"] = server_.daemon_epoch;
    if (!tasks_.host_id.empty()) value["hostId"] = tasks_.host_id;
    value["version"] = server_.build.version;
    value["versionCode"] = server_.build.version_code;
    value["capabilities"] = Json::Value(Json::arrayValue);
    // Advertise only implemented browser adapters, never the local IPC command list.
    value["capabilities"].append("session.v1");
    if (sessions_.can_remember()) value["capabilities"].append("session.remember.v1");
    value["capabilities"].append("session.lan-auto.v1");
    value["capabilities"].append("vm.list.v1");
    if (tasks_.list) value["capabilities"].append("tasks.list.v1");
    if (tasks_.cancel) value["capabilities"].append("tasks.cancel.v1");
    if (tasks_.receipt) value["capabilities"].append("tasks.receipts.v1");
    if (vms_.submit && vms_.find) value["capabilities"].append("vm.lifecycle.v1");
    if (logs_.list && logs_.read) value["capabilities"].append("vm.logs.v1");
    if (events_) value["capabilities"].append("events.invalidate.v1");
    if (config_.invoke) value["capabilities"].append("vm.configuration.v1");
    if (config_.invoke && config_.defaults) value["capabilities"].append("vm.defaults.v1");
    if (resources_.disks) value["capabilities"].append("disks.list.v1");
    if (resources_.disk_detail) value["capabilities"].append("disks.inspect.v1");
    if (resources_.disk_compression) value["capabilities"].append("disks.compression.v1");
    if (resources_.disk_actions.submit && resources_.disk_actions.find) value["capabilities"].append("disks.operations.v1");
    if (resources_.disk_clone_directory && resources_.disk_actions.submit && resources_.disk_actions.find)
        value["capabilities"].append("disks.clone-directory.v1");
    if (resources_.disk_recovery.status && resources_.disk_recovery.tasks.submit && resources_.disk_recovery.tasks.find)
        value["capabilities"].append("disks.recovery.v1");
    if (resources_.networks) value["capabilities"].append("networks.list.v1");
    if (resources_.network_configuration.invoke) value["capabilities"].append("networks.configuration.v1");
    if (resources_.network_deletion.invoke) value["capabilities"].append("networks.deletion.v1");
    if (resources_.terminal_catalog && resources_.terminal_source) value["capabilities"].append("vm.terminal.v1");
    if (resources_.display_source && resources_.display_source->list && resources_.display_source->open)
        value["capabilities"].append("vm.display.v1");
    if (resources_.agent_actions.submit && resources_.agent_actions.find)
        value["capabilities"].append("agent.operations.v1");
    if (resources_.agent_recovery.status && resources_.agent_recovery.tasks.submit && resources_.agent_recovery.tasks.find)
        value["capabilities"].append("agent.recovery.v1");
    if (rescue_available(resources_.agent_rescue))
        value["capabilities"].append("agent.rescue.v1");
    if (resources_.package_exports.plan && resources_.package_exports.tasks.submit && resources_.package_exports.tasks.find)
        value["capabilities"].append("packages.export.v1");
    if (resources_.package_imports.plans.submit && resources_.package_imports.plans.find
        && resources_.package_imports.tasks.submit && resources_.package_imports.tasks.find)
        value["capabilities"].append("packages.import.v1");
    if (resources_.image_imports.plans.submit && resources_.image_imports.plans.find
        && resources_.image_imports.tasks.submit && resources_.image_imports.tasks.find)
        value["capabilities"].append("images.import.v1");
    if (transfers_available(resources_.package_transfers)) value["capabilities"].append("packages.transfer.v1");
    if (image_uploads_available(resources_.image_uploads)) value["capabilities"].append("images.upload.v1");
    if (resources_.configuration_recovery.submit && resources_.configuration_recovery.find)
        value["capabilities"].append("configuration.recovery.v1");
    if (resources_.configuration_backup.configuration.invoke && resources_.configuration_backup.file)
        value["capabilities"].append("configuration.backup.v1");
    if (resources_.web_service.read && resources_.web_service.tasks.submit && resources_.web_service.tasks.find)
        value["capabilities"].append("web.service.v1");
    if (resources_.network_detail) value["capabilities"].append("networks.inspect.v1");
    if (resources_.host_network) value["capabilities"].append("host.network.v1");
    if (resources_.network_actions.submit && resources_.network_actions.find)
        value["capabilities"].append("networks.lifecycle.v1");
    if (resources_.audio) value["capabilities"].append("host.audio.v1");
    if (resources_.cpus) value["capabilities"].append("host.cpu.v1");
    if (resources_.host_devices) value["capabilities"].append("host.devices.v1");
    if (resources_.host_overview) value["capabilities"].append("host.overview.v1");
    if (resources_.hugepages.read && resources_.hugepages.tasks.submit && resources_.hugepages.tasks.find) {
        value["capabilities"].append("host.hugepages.v1");
        value["capabilities"].append("host.hugepages.manage.v1");
    }
    if (resources_.hugepage_processes.list && resources_.hugepage_processes.stack &&
        resources_.hugepage_processes.tasks.submit && resources_.hugepage_processes.tasks.find)
        value["capabilities"].append("host.hugepages.processes.v1");
    if (resources_.host_preferences.read && resources_.host_preferences.tasks.submit && resources_.host_preferences.tasks.find)
        value["capabilities"].append("host.preferences.v1");
    if (resources_.usb_acm.read && resources_.usb_acm.tasks.submit && resources_.usb_acm.tasks.find)
        value["capabilities"].append("host.usb-acm.v1");
    if (resources_.disk_defaults.read && resources_.disk_defaults.tasks.submit && resources_.disk_defaults.tasks.find)
        value["capabilities"].append("host.disk-defaults.v1");
    if (resources_.usb) value["capabilities"].append("usb.list.v1");
    if (resources_.usb && usb_.submit && usb_.find) value["capabilities"].append("usb.target.v1");
    if (usb_rules_.invoke) value["capabilities"].append("usb.rules.v1");
    if (usb_rules_.invoke && usb_rules_.preview) value["capabilities"].append("usb.rules.preview.v1");
    return value;
}
Json::Value HttpApi::context_json(const SessionView& view) const {
    Json::Value value(Json::objectValue);
    value["daemonEpoch"] = server_.daemon_epoch; value["sessionId"] = view.id;
    return value;
}
Json::Value HttpApi::view_json(const SessionView& view) const {
    Json::Value value(Json::objectValue);
    value["id"] = view.id;
    value["csrfToken"] = view.csrf;
    value["remembered"] = view.remembered;
    value["lanOnly"] = view.lan_only;
    value["permissions"]["administrator"] = view.caller.administrator;
    value["permissions"]["manageTasks"] = view.caller.manage_tasks;
    value["server"] = server_json();
    return value;
}
HttpResponse HttpApi::json(int status, const Json::Value& value) {
    Json::StreamWriterBuilder writer;
    writer["indentation"] = "";
    return {status, {{"Content-Type", "application/json; charset=utf-8"}, {"Cache-Control", "no-store"},
        {"X-Content-Type-Options", "nosniff"}}, Json::writeString(writer, value)};
}
HttpResponse HttpApi::problem(int status, const char* code) {
    Json::Value value(Json::objectValue); value["error"]["code"] = code;
    auto response = json(status, value);
    if (status == 429) response.headers.emplace_back("Retry-After", "60");
    return response;
}
size_t HttpApi::request_limit(std::string_view path) {
    if (path == "/api/v1/display") return 64u << 10;
    if (path == "/api/v1/image-installs") return 32u << 10;
    if (path.starts_with("/api/v1/image-uploads/") && path.ends_with("/chunks")) return 384u << 10;
    if (path == "/api/v1/image-import-plans") return 32u << 10;
    if (path == "/api/v1/web-service/operations") return 16u << 10;
    if (path == "/api/v1/configuration-backup/append") return 68u << 10;
    if (path.starts_with("/api/v1/package-uploads/") && path.ends_with("/chunks")) return 384u << 10;
    if (path == "/api/v1/package-uploads" || path == "/api/v1/package-downloads") return 384u << 10;
    if (path == "/api/v1/disk-operations" || path == "/api/v1/package-exports"
        || path == "/api/v1/package-import-plans" || path == "/api/v1/package-imports") return 32u << 10;
    if (path == "/api/v1/disk-default-operations" || path == "/api/v1/disk-operations") return 8192;
    return (path == "/api/v1/vm-configuration/append" || path == "/api/v1/usb-rules/append" || path == "/api/v1/network-configuration/append" || path == "/api/v1/network-deletion/append") ? (68u << 10) : 4096;
}
HttpResponse HttpApi::guard_download(const HttpRequest& request, const SessionView& session, HttpResponse response) {
    if (!response.stream || !response.stream->read) throw ServiceError(ErrorCode::internal, "Missing download source");
    auto stream = std::make_shared<HttpStreamBody>(*response.stream);
    // Generation owns this session store for the lifetime of every stream;
    // standalone users must likewise retain their API/store.
    stream->read = [store = &sessions_, token = cookie(request), session_id = session.id,
        principal = session.caller.principal, trusted_lan = request.trusted_lan, read = stream->read](uint64_t offset, size_t maximum) {
        const auto check = [&] {
            const auto current = store->authenticate(token, std::nullopt, false, trusted_lan);
            if (current.id != session_id || current.caller.principal != principal || !current.caller.administrator || !current.caller.manage_tasks)
                throw ServiceError(ErrorCode::permission_denied, "Download session changed");
        };
        check(); auto bytes = read(offset, maximum); check(); return bytes;
    };
    response.stream = std::move(stream); return response;
}
HttpResponse HttpApi::handle(const HttpRequest& request) {
    try {
        check_origin(request, request.method != "GET" && request.method != "HEAD");
        if (request.body.size() > request_limit(request.path)) return problem(413, "payload_too_large");
        const auto path = request.path == "/" ? std::string_view("/index.html") : std::string_view(request.path);
        for (const auto& asset : assets_) if (asset.path == path) return static_resource(request, asset);
        if (request.path == "/api/v1/session/options") {
            if (request.method != "GET") return problem(405, "method_not_allowed");
            if (!request.body.empty()) invalid();
            Json::Value value; value["rememberSupported"] = sessions_.can_remember();
            value["lanAvailable"] = request.trusted_lan;
            return json(200, value);
        }
        if (request.path == "/api/v1/session/local") {
            if (request.method != "POST") return problem(405, "method_not_allowed");
            if (!request.trusted_lan) throw ServiceError(ErrorCode::permission_denied, "Local access unavailable");
            if (!parse_object(request).empty()) invalid();
            const auto grant = sessions_.grant_local();
            auto response = json(201, view_json(grant.session));
            response.headers.emplace_back("Set-Cookie", "droidvm-session=" + grant.token + "; Path=/; HttpOnly; SameSite=Strict");
            response.headers.emplace_back("Set-Cookie", "droidvm-local-logout=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
            return response;
        }
        if (request.path == "/api/v1/session") {
            if (request.method == "POST") {
                const auto input = parse_pairing(request);
                const bool remember = input.get("remember", false).asBool();
                const auto grant = sessions_.exchange(input["pairingToken"].asString(), remember);
                auto response = json(201, view_json(grant.session));
                response.headers.emplace_back("Set-Cookie", "droidvm-session=" + grant.token + "; Path=/; HttpOnly; SameSite=Strict" +
                    (remember ? "; Max-Age=2592000" : ""));
                response.headers.emplace_back("Set-Cookie", "droidvm-local-logout=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
                return response;
            }
            if (!request.body.empty()) invalid();
            if (request.method == "GET") {
                try { return json(200, view_json(sessions_.authenticate(cookie(request), std::nullopt, true, request.trusted_lan))); }
                catch (const ServiceError& error) {
                    if (error.code() != ErrorCode::unauthenticated || !request.trusted_lan ||
                        !cookie(request, "droidvm-local-logout").empty()) throw;
                }
                // The custom header requires a CORS preflight across origins, which this
                // API rejects. Fetch Metadata is absent on some plain HTTP LAN browsers.
                const auto site = header(request, "sec-fetch-site");
                if (header(request, "x-droidvm-session") != std::optional<std::string_view>("1") ||
                    (site && *site != "same-origin"))
                    throw ServiceError(ErrorCode::permission_denied, "Local session origin rejected");
                const auto grant = sessions_.grant_local();
                auto response = json(200, view_json(grant.session));
                response.headers.emplace_back("Set-Cookie", "droidvm-session=" + grant.token + "; Path=/; HttpOnly; SameSite=Strict");
                return response;
            }
            if (request.method == "DELETE") {
                const auto csrf = header(request, "x-droidvm-csrf");
                HttpResponse response{204, {{"Cache-Control", "no-store"}}, {}};
                try {
                    (void)sessions_.authenticate(cookie(request), csrf.value_or(""), true, request.trusted_lan);
                    sessions_.logout(cookie(request), csrf.value_or(""));
                } catch (const ServiceError& error) {
                    if (error.code() != ErrorCode::unauthenticated) throw;
                    // An already expired/revoked credential is also a completed logout.
                    // Keep the existing 401 contract and suppress automatic LAN re-entry.
                    response = problem(401, "unauthenticated");
                }
                response.headers.emplace_back("Set-Cookie", "droidvm-session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
                response.headers.emplace_back("Set-Cookie", "droidvm-local-logout=1; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000");
                return response;
            }
            auto response = problem(405, "method_not_allowed");
            response.headers.emplace_back("Allow", "GET, POST, DELETE");
            return response;
        }
        if (request.path == "/api/v1/image-uploads" || request.path.starts_with("/api/v1/image-uploads/")
            || request.path == "/api/v1/package-uploads" || request.path.starts_with("/api/v1/package-uploads/")
            || request.path == "/api/v1/package-downloads" || request.path.starts_with("/api/v1/package-downloads/")) {
            const bool image = request.path.starts_with("/api/v1/image-uploads");
            const bool upload = image || request.path.starts_with("/api/v1/package-uploads");
            const std::string base = image ? "/api/v1/image-uploads" : upload ? "/api/v1/package-uploads" : "/api/v1/package-downloads";
            const bool begin = request.path == base;
            const auto tail = begin ? std::string() : request.path.substr(base.size() + 1);
            const auto slash = tail.find('/');
            const auto id = tail.substr(0, slash);
            const auto operation = slash == std::string::npos ? std::string() : tail.substr(slash + 1);
            if (!begin && (id.empty() || id.size() > 128 || id.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::string::npos)) invalid();
            const bool file = !upload && operation.starts_with("files/");
            const bool append = upload && operation == "chunks", finish = upload && operation == "finish";
            if (!operation.empty() && !file && !append && !finish) return problem(404, "not_found");
            const bool mutation = begin || append || finish || request.method == "DELETE";
            const bool allowed = begin || append || finish ? request.method == "POST" : file ? request.method == "GET"
                : request.method == "GET" || request.method == "DELETE";
            if (!allowed) {
                auto response = problem(405, "method_not_allowed");
                response.headers.emplace_back("Allow", begin || append || finish ? "POST" : file ? "GET" : "GET, DELETE"); return response;
            }
            const auto csrf = mutation ? std::optional(header(request, "x-droidvm-csrf").value_or("")) : std::nullopt;
            const auto session = sessions_.authenticate(cookie(request), csrf, true, request.trusted_lan);
            if (!session.caller.administrator || !session.caller.manage_tasks)
                throw ServiceError(ErrorCode::permission_denied, "Package transfer permission required");
            if (image ? !image_uploads_available(resources_.image_uploads) : !transfers_available(resources_.package_transfers)) return problem(501, "unsupported");
            const auto& transfers = resources_.package_transfers;
            const auto& uploads = image ? resources_.image_uploads.uploads : transfers.uploads;
            if (file) {
                if (!request.body.empty()) invalid();
                const auto index_text = operation.substr(6);
                uint32_t index = 0;
                const auto parsed = std::from_chars(index_text.data(), index_text.data() + index_text.size(), index);
                if (parsed.ec != std::errc() || parsed.ptr != index_text.data() + index_text.size() || std::to_string(index) != index_text) invalid();
                if (header(request, "range")) {
                    auto response = problem(416, "range_not_supported"); response.headers.emplace_back("Accept-Ranges", "none"); return response;
                }
                return guard_download(request, session, transfers.downloads.file(session.caller, id, index));
            }
            if (request.method == "DELETE") {
                if (!request.body.empty()) invalid();
                (upload ? uploads.erase : transfers.downloads.erase)(session.caller, id);
                return {204, {{"Cache-Control", "no-store"}}, {}};
            }
            Json::Value result;
            if (request.method == "GET") {
                if (!request.body.empty()) invalid();
                result["transfer"] = (upload ? uploads.status : transfers.downloads.status)(session.caller, id);
            } else {
                auto input = parse_object(request);
                const auto expected = begin ? 3u : append ? 4u : 1u;
                if (input.size() != expected || !input["context"].isObject() || input["context"].size() != 2
                    || !input["context"]["daemonEpoch"].isString() || !input["context"]["sessionId"].isString()) invalid();
                if (input["context"] != context_json(session)) return problem(409, "context_changed");
                input.removeMember("context");
                if (begin) result["transfer"] = (upload ? uploads.begin : transfers.downloads.begin)(session.caller, input);
                else if (append) result["transfer"] = uploads.append(session.caller, id, input);
                else result["transfer"] = uploads.finish(session.caller, id);
            }
            result["context"] = context_json(session); return json(200, result);
        }
        if (request.path == "/api/v1/web-service") {
            if (request.method != "GET") {
                auto response = problem(405, "method_not_allowed"); response.headers.emplace_back("Allow", "GET"); return response;
            }
            if (!request.body.empty()) invalid();
            const auto session = sessions_.authenticate(cookie(request), std::nullopt, true, request.trusted_lan);
            if (!session.caller.administrator || !session.caller.manage_tasks)
                throw ServiceError(ErrorCode::permission_denied, "Web service permission required");
            if (!resources_.web_service.read) return problem(501, "unsupported");
            auto result = resources_.web_service.read(session.caller); result["context"] = context_json(session);
            return json(200, result);
        }
        if (request.path == "/api/v1/host/preferences" || request.path == "/api/v1/host/usb-acm" || request.path == "/api/v1/host/disk-defaults") {
            if (request.method != "GET") {
                auto response = problem(405, "method_not_allowed"); response.headers.emplace_back("Allow", "GET"); return response;
            }
            if (!request.body.empty()) invalid();
            const auto session = sessions_.authenticate(cookie(request), std::nullopt, true, request.trusted_lan);
            if (!session.caller.administrator) throw ServiceError(ErrorCode::permission_denied, "Host preference permission required");
            const auto& operations = request.path == "/api/v1/host/disk-defaults" ? resources_.disk_defaults : request.path == "/api/v1/host/usb-acm" ? resources_.usb_acm : resources_.host_preferences;
            if (!operations.read) return problem(501, "unsupported");
            auto result = operations.read(session.caller);
            result["context"] = context_json(session); return json(200, result);
        }
        if (request.path == "/api/v1/host/hugepage-processes" || request.path.starts_with("/api/v1/host/hugepage-processes/")) {
            if (request.method != "GET") {
                auto response = problem(405, "method_not_allowed"); response.headers.emplace_back("Allow", "GET"); return response;
            }
            if (!request.body.empty()) invalid();
            const auto session = sessions_.authenticate(cookie(request), std::nullopt, true, request.trusted_lan);
            if (!session.caller.administrator) throw ServiceError(ErrorCode::permission_denied, "Hugepage process permission required");
            std::string source = "auto";
            constexpr std::string_view base = "/api/v1/host/hugepage-processes";
            if (request.path != base) {
                source = request.path.substr(base.size() + 1);
                if (source != "auto" && source != "ko" && source != "scan") invalid();
            }
            if (!resources_.hugepage_processes.list) return problem(501, "unsupported");
            auto result = resources_.hugepage_processes.list(session.caller, source);
            result["context"] = context_json(session); return json(200, result);
        }
        if (request.path == "/api/v1/hugepage-process-stack") {
            if (request.method != "POST") {
                auto response = problem(405, "method_not_allowed"); response.headers.emplace_back("Allow", "POST"); return response;
            }
            const auto session = sessions_.authenticate(cookie(request), header(request, "x-droidvm-csrf").value_or(""), true, request.trusted_lan);
            if (!session.caller.administrator) throw ServiceError(ErrorCode::permission_denied, "Hugepage process permission required");
            if (!resources_.hugepage_processes.stack) return problem(501, "unsupported");
            const auto input = parse_object(request);
            if (input.size() != 2 || !input["expected"].isObject() || !input["context"].isObject() || input["context"].size() != 2 ||
                !input["context"]["daemonEpoch"].isString() || !input["context"]["sessionId"].isString()) invalid();
            if (input["context"] != context_json(session)) return problem(409, "context_changed");
            auto result = resources_.hugepage_processes.stack(session.caller, input["expected"]);
            result["context"] = context_json(session); return json(200, result);
        }
        if (request.path == "/api/v1/vms" || request.path == "/api/v1/capabilities") {
            if (request.method != "GET") {
                auto response = problem(405, "method_not_allowed"); response.headers.emplace_back("Allow", "GET"); return response;
            }
            if (!request.body.empty()) invalid();
            const auto session = sessions_.authenticate(cookie(request), std::nullopt, true, request.trusted_lan);
            if (request.path == "/api/v1/capabilities") {
                Json::Value result; result["server"] = server_json(); result["context"] = context_json(session);
                return json(200, result);
            }
            auto result = list_vms_(session.caller);
            result["context"] = context_json(session);
            return json(200, result);
        }
        if (request.path.starts_with("/api/v1/disks/") || request.path.starts_with("/api/v1/networks/")) {
            if (request.method != "GET") {
                auto response = problem(405, "method_not_allowed"); response.headers.emplace_back("Allow", "GET"); return response;
            }
            if (!request.body.empty()) invalid();
            const auto session = sessions_.authenticate(cookie(request), std::nullopt, true, request.trusted_lan);
            if (!session.caller.administrator) throw ServiceError(ErrorCode::permission_denied, "Resource permission required");
            const bool network = request.path.starts_with("/api/v1/networks/");
            auto id = request.path.substr(network ? std::string_view("/api/v1/networks/").size() : std::string_view("/api/v1/disks/").size());
            const bool compression = !network && id.ends_with("/compression");
            if (compression) id.resize(id.size() - std::string_view("/compression").size());
            if (id.empty() || id.size() > 128 || id.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::string::npos) invalid();
            const auto& detail = network ? resources_.network_detail : compression ? resources_.disk_compression : resources_.disk_detail;
            if (!detail) return problem(501, "unsupported");
            auto result = detail(session.caller, id);
            result["context"] = context_json(session);
            return json(200, result);
        }
        if (request.path == "/api/v1/disks" || request.path == "/api/v1/networks" || request.path == "/api/v1/host/audio" || request.path == "/api/v1/usb" || request.path == "/api/v1/host/cpus" || request.path == "/api/v1/host/devices" || request.path == "/api/v1/host/network" || request.path == "/api/v1/host/overview" || request.path == "/api/v1/host/hugepages") {
            if (request.method != "GET") {
                auto response = problem(405, "method_not_allowed"); response.headers.emplace_back("Allow", "GET"); return response;
            }
            if (!request.body.empty()) invalid();
            const auto session = sessions_.authenticate(cookie(request), std::nullopt, true, request.trusted_lan);
            if (!session.caller.administrator) throw ServiceError(ErrorCode::permission_denied, "Resource permission required");
            const auto& list = request.path == "/api/v1/disks" ? resources_.disks :
                request.path == "/api/v1/networks" ? resources_.networks :
                request.path == "/api/v1/host/cpus" ? resources_.cpus :
                request.path == "/api/v1/host/devices" ? resources_.host_devices :
                request.path == "/api/v1/host/overview" ? resources_.host_overview :
                request.path == "/api/v1/host/hugepages" ? resources_.hugepages.read :
                request.path == "/api/v1/host/network" ? resources_.host_network :
                request.path == "/api/v1/usb" ? resources_.usb : resources_.audio;
            if (!list) return problem(501, "unsupported");
            auto result = list(session.caller);
            result["context"] = context_json(session);
            return json(200, result);
        }
        if (request.path.starts_with("/api/v1/package-export-plans/")) {
            if (request.method != "GET") {
                auto response = problem(405, "method_not_allowed"); response.headers.emplace_back("Allow", "GET"); return response;
            }
            const auto session = sessions_.authenticate(cookie(request), std::nullopt, true, request.trusted_lan);
            if (!session.caller.administrator || !session.caller.manage_tasks)
                throw ServiceError(ErrorCode::permission_denied, "Package export permission required");
            if (!request.body.empty()) invalid();
            if (!resources_.package_exports.plan) return problem(501, "unsupported");
            auto result = resources_.package_exports.plan(session.caller,
                request.path.substr(std::string_view("/api/v1/package-export-plans/").size()));
            result["context"] = context_json(session);
            return json(200, result);
        }
        if (request.path == "/api/v1/agent-rescue-sessions") {
            if (request.method != "GET") {
                auto response = problem(405, "method_not_allowed"); response.headers.emplace_back("Allow", "GET"); return response;
            }
            const auto session = sessions_.authenticate(cookie(request), std::nullopt, true, request.trusted_lan);
            if (!session.caller.administrator || !session.caller.manage_tasks)
                throw ServiceError(ErrorCode::permission_denied, "Rescue permission required");
            if (!request.body.empty()) invalid();
            if (!resources_.agent_rescue.list) return problem(501, "unsupported");
            auto result = resources_.agent_rescue.list(session.caller);
            result["context"] = context_json(session);
            return json(200, result);
        }
        if (request.path.starts_with("/api/v1/vm-displays/")) {
            if (request.method != "GET") {
                auto response = problem(405, "method_not_allowed"); response.headers.emplace_back("Allow", "GET"); return response;
            }
            if (!request.body.empty()) invalid();
            const auto session = sessions_.authenticate(cookie(request), std::nullopt, true, request.trusted_lan);
            if (!resources_.display_source || !resources_.display_source->list || !resources_.display_source->open) return problem(501, "unsupported");
            auto result = vm_display_list(*resources_.display_source, session.caller, request.path.substr(std::string_view("/api/v1/vm-displays/").size()));
            result["context"] = context_json(session); return json(200, result);
        }
        if (request.path.starts_with("/api/v1/vm-terminals/") || request.path.starts_with("/api/v1/agent-rescue-terminals/")) {
            const bool rescue = request.path.starts_with("/api/v1/agent-rescue-terminals/");
            if (request.method != "GET") {
                auto response = problem(405, "method_not_allowed"); response.headers.emplace_back("Allow", "GET"); return response;
            }
            const auto session = sessions_.authenticate(cookie(request), std::nullopt, true, request.trusted_lan);
            if (!session.caller.administrator || (rescue && !session.caller.manage_tasks))
                throw ServiceError(ErrorCode::permission_denied, "Terminal permission required");
            if (!request.body.empty()) invalid();
            Json::Value result;
            if (rescue) {
                const auto source = resources_.agent_rescue.terminal_source;
                if (!source || !source->list || !source->read || !source->write) return problem(501, "unsupported");
                const auto id = request.path.substr(std::string_view("/api/v1/agent-rescue-terminals/").size());
                if (id.size() != 64 || id.find_first_not_of("0123456789abcdef") != std::string::npos) invalid();
                const auto target = source->list(session.caller, id);
                if (target.vm_id != id || target.streams != std::vector<std::string>{"uart"}
                    || target.observed.instance.size() != 32
                    || target.observed.instance.find_first_not_of("0123456789abcdef") != std::string::npos)
                    throw ServiceError(ErrorCode::unavailable, "Rescue terminal unavailable");
                result["vmId"] = id; result["expected"]["instanceId"] = target.observed.instance;
                result["expected"]["revision"] = std::to_string(target.observed.revision);
                result["resizeSupported"] = false;
                result["streams"] = Json::Value(Json::arrayValue); result["streams"].append("uart");
            } else {
                if (!resources_.terminal_catalog || !resources_.terminal_source) return problem(501, "unsupported");
                result = resources_.terminal_catalog(session.caller, request.path.substr(std::string_view("/api/v1/vm-terminals/").size()));
            }
            result["context"] = context_json(session);
            return json(200, result);
        }
        if (request.path == "/api/v1/configuration-backup/file") {
            if (request.method != "GET") {
                auto response = problem(405, "method_not_allowed"); response.headers.emplace_back("Allow", "GET"); return response;
            }
            if (!request.body.empty()) invalid();
            const auto session = sessions_.authenticate(cookie(request), std::nullopt, true, request.trusted_lan);
            if (!session.caller.administrator || !session.caller.manage_tasks)
                throw ServiceError(ErrorCode::permission_denied, "Configuration permission required");
            if (!resources_.configuration_backup.file) return problem(501, "unsupported");
            if (header(request, "range")) {
                auto response = problem(416, "range_not_supported"); response.headers.emplace_back("Accept-Ranges", "none"); return response;
            }
            return guard_download(request, session, resources_.configuration_backup.file(session.caller));
        }
        if (request.path.starts_with("/api/v1/vm-configuration/") || request.path.starts_with("/api/v1/usb-rules/") || request.path.starts_with("/api/v1/network-configuration/") || request.path.starts_with("/api/v1/network-deletion/") || request.path.starts_with("/api/v1/configuration-backup/")) {
            const bool usb_rules = request.path.starts_with("/api/v1/usb-rules/");
            const bool networks = request.path.starts_with("/api/v1/network-configuration/");
            const bool deletion = request.path.starts_with("/api/v1/network-deletion/");
            const bool backup = request.path.starts_with("/api/v1/configuration-backup/");
            const auto& configuration = backup ? resources_.configuration_backup.configuration : deletion ? resources_.network_deletion : networks ? resources_.network_configuration : usb_rules ? usb_rules_ : config_;
            if (request.method != "POST") {
                auto response = problem(405, "method_not_allowed"); response.headers.emplace_back("Allow", "POST"); return response;
            }
            const auto session = sessions_.authenticate(cookie(request), header(request, "x-droidvm-csrf").value_or(""), true, request.trusted_lan);
            if (!session.caller.administrator || !session.caller.manage_tasks)
                throw ServiceError(ErrorCode::permission_denied, "Configuration permission required");
            if (!configuration.invoke) return problem(501, "unsupported");
            auto input = parse_object(request);
            if (!input["context"].isObject() || input["context"].size() != 2) invalid();
            if (input["context"] != context_json(session)) return problem(409, "context_changed");
            input.removeMember("context");
            const auto operation = request.path.substr(backup ? std::string_view("/api/v1/configuration-backup/").size() : deletion ? std::string_view("/api/v1/network-deletion/").size() : networks ? std::string_view("/api/v1/network-configuration/").size() : usb_rules ? std::string_view("/api/v1/usb-rules/").size() : std::string_view("/api/v1/vm-configuration/").size());
            Json::Value result;
            if (operation == "preview" && usb_rules) {
                if (!usb_rules_.preview) return problem(501, "unsupported");
                result = usb_rules_.preview(session.caller, input);
            } else if (operation == "defaults" && !usb_rules && !networks && !deletion && !backup) {
                if (!config_.defaults) return problem(501, "unsupported");
                if (!input.empty()) invalid();
                Json::StreamWriterBuilder writer; writer["indentation"] = "";
                auto text = Json::writeString(writer, config_.defaults(session.caller));
                if (text.size() > (64u << 10))
                    throw ServiceError(ErrorCode::resource_exhausted, "VM defaults exceed response limit");
                result["json"] = std::move(text);
            } else result = configuration.invoke(session.caller, operation, input);
            result["context"] = context_json(session);
            return json(operation == "commit" ? 202 : 200, result);
        }
        if (request.path == "/api/v1/vm-logs/read" || request.path.starts_with("/api/v1/vm-logs/")) {
            const bool read = request.path == "/api/v1/vm-logs/read";
            if (request.method != (read ? "POST" : "GET")) {
                auto response = problem(405, "method_not_allowed"); response.headers.emplace_back("Allow", read ? "POST" : "GET"); return response;
            }
            const auto csrf = read ? std::optional(header(request, "x-droidvm-csrf").value_or("")) : std::nullopt;
            const auto session = sessions_.authenticate(cookie(request), csrf, true, request.trusted_lan);
            if (!session.caller.administrator) throw ServiceError(ErrorCode::permission_denied, "Log permission required");
            if (!logs_.list || !logs_.read) return problem(501, "unsupported");
            Json::Value result;
            if (read) {
                auto input = parse_object(request);
                if (input.size() != 6 || !input["context"].isObject() || input["context"].size() != 2 ||
                    !input["context"]["daemonEpoch"].isString() || !input["context"]["sessionId"].isString()) invalid();
                if (input["context"] != context_json(session)) return problem(409, "context_changed");
                input.removeMember("context");
                result = logs_.read(session.caller, input);
            } else {
                if (!request.body.empty()) invalid();
                result = logs_.list(session.caller, request.path.substr(std::string_view("/api/v1/vm-logs/").size()));
            }
            result["context"] = context_json(session);
            return json(200, result);
        }
        if ((request.path == "/api/v1/agent-recovery" || request.path == "/api/v1/disk-recovery") && request.method == "GET") {
            const auto& recovery = request.path == "/api/v1/agent-recovery" ? resources_.agent_recovery : resources_.disk_recovery;
            const auto session = sessions_.authenticate(cookie(request), std::nullopt, true, request.trusted_lan);
            if (!session.caller.administrator || !session.caller.manage_tasks) throw ServiceError(ErrorCode::permission_denied, "Disk recovery permission required");
            if (!request.body.empty()) invalid();
            if (!recovery.status) return problem(501, "unsupported");
            auto result = recovery.status(session.caller);
            result["context"] = context_json(session);
            return json(200, result);
        }
        if (request.path == "/api/v1/vm-operations" || request.path.starts_with("/api/v1/vm-operations/") ||
            request.path == "/api/v1/package-exports" || request.path.starts_with("/api/v1/package-exports/") ||
            request.path == "/api/v1/package-import-plans" || request.path.starts_with("/api/v1/package-import-plans/") ||
            request.path == "/api/v1/package-imports" || request.path.starts_with("/api/v1/package-imports/") ||
            request.path == "/api/v1/image-import-plans" || request.path.starts_with("/api/v1/image-import-plans/") ||
            request.path == "/api/v1/image-imports" || request.path.starts_with("/api/v1/image-imports/") ||
            request.path == "/api/v1/image-installs" || request.path.starts_with("/api/v1/image-installs/") ||
            request.path == "/api/v1/usb-acm-operations" || request.path.starts_with("/api/v1/usb-acm-operations/") ||
            request.path == "/api/v1/host-preference-operations" || request.path.starts_with("/api/v1/host-preference-operations/") ||
            request.path == "/api/v1/disk-default-operations" || request.path.starts_with("/api/v1/disk-default-operations/") ||
            request.path == "/api/v1/hugepage-process-operations" || request.path.starts_with("/api/v1/hugepage-process-operations/") ||
            request.path == "/api/v1/hugepage-operations" || request.path.starts_with("/api/v1/hugepage-operations/") ||
            request.path == "/api/v1/agent-operations" || request.path.starts_with("/api/v1/agent-operations/") ||
            request.path == "/api/v1/agent-recovery" || request.path.starts_with("/api/v1/agent-recovery/") ||
            request.path == "/api/v1/agent-rescue-operations" || request.path.starts_with("/api/v1/agent-rescue-operations/") ||
            request.path == "/api/v1/configuration-recovery" || request.path.starts_with("/api/v1/configuration-recovery/") ||
            request.path == "/api/v1/web-service/operations" || request.path.starts_with("/api/v1/web-service/operations/") ||
            request.path == "/api/v1/network-operations" || request.path.starts_with("/api/v1/network-operations/") ||
            request.path == "/api/v1/disk-recovery" || request.path.starts_with("/api/v1/disk-recovery/") ||
            request.path == "/api/v1/usb-operations" || request.path.starts_with("/api/v1/usb-operations/") ||
            request.path == "/api/v1/disk-operations" || request.path.starts_with("/api/v1/disk-operations/")) {
            const bool usb = request.path.starts_with("/api/v1/usb-operations");
            const bool recovery = request.path.starts_with("/api/v1/disk-recovery");
            const bool config_recovery = request.path.starts_with("/api/v1/configuration-recovery");
            const bool web_service = request.path.starts_with("/api/v1/web-service/operations");
            const bool disk = request.path.starts_with("/api/v1/disk-operations");
            const bool network = request.path.starts_with("/api/v1/network-operations");
            const bool agent = request.path.starts_with("/api/v1/agent-operations");
            const bool agent_recovery = request.path.starts_with("/api/v1/agent-recovery");
            const bool rescue = request.path.starts_with("/api/v1/agent-rescue-operations");
            const bool package = request.path.starts_with("/api/v1/package-exports");
            const bool import_plan = request.path.starts_with("/api/v1/package-import-plans");
            const bool package_import = request.path.starts_with("/api/v1/package-imports");
            const bool image_plan = request.path.starts_with("/api/v1/image-import-plans");
            const bool image_import = request.path.starts_with("/api/v1/image-imports");
            const bool image_install = request.path.starts_with("/api/v1/image-installs");
            const bool hugepage = request.path.starts_with("/api/v1/hugepage-operations");
            const bool hugepage_process = request.path.starts_with("/api/v1/hugepage-process-operations");
            const bool usb_acm = request.path.starts_with("/api/v1/usb-acm-operations");
            const bool host_preference = request.path.starts_with("/api/v1/host-preference-operations");
            const bool disk_default = request.path.starts_with("/api/v1/disk-default-operations");
            const std::string base = disk_default ? "/api/v1/disk-default-operations" : usb_acm ? "/api/v1/usb-acm-operations" : host_preference ? "/api/v1/host-preference-operations" : hugepage_process ? "/api/v1/hugepage-process-operations" : hugepage ? "/api/v1/hugepage-operations" : image_install ? "/api/v1/image-installs" : image_plan ? "/api/v1/image-import-plans" : image_import ? "/api/v1/image-imports" : web_service ? "/api/v1/web-service/operations" : import_plan ? "/api/v1/package-import-plans" : package_import ? "/api/v1/package-imports" : package ? "/api/v1/package-exports" : rescue ? "/api/v1/agent-rescue-operations" : agent ? "/api/v1/agent-operations" : agent_recovery ? "/api/v1/agent-recovery" : config_recovery ? "/api/v1/configuration-recovery" : network ? "/api/v1/network-operations" : recovery ? "/api/v1/disk-recovery" : disk ? "/api/v1/disk-operations" : usb ? "/api/v1/usb-operations" : "/api/v1/vm-operations";
            const auto& operations = disk_default ? resources_.disk_defaults.tasks : usb_acm ? resources_.usb_acm.tasks : host_preference ? resources_.host_preferences.tasks : hugepage_process ? resources_.hugepage_processes.tasks : hugepage ? resources_.hugepages.tasks : image_install ? resources_.image_uploads.installs : image_plan ? resources_.image_imports.plans : image_import ? resources_.image_imports.tasks : web_service ? resources_.web_service.tasks : import_plan ? resources_.package_imports.plans : package_import ? resources_.package_imports.tasks : package ? resources_.package_exports.tasks : rescue ? resources_.agent_rescue.close : agent ? resources_.agent_actions : agent_recovery ? resources_.agent_recovery.tasks : config_recovery ? resources_.configuration_recovery : network ? resources_.network_actions : recovery ? resources_.disk_recovery.tasks : disk ? resources_.disk_actions : usb ? usb_ : vms_;
            const bool submit = request.path == base;
            if (request.method != (submit ? "POST" : "GET")) {
                auto response = problem(405, "method_not_allowed"); response.headers.emplace_back("Allow", (recovery || agent_recovery) && submit ? "GET, POST" : submit ? "POST" : "GET"); return response;
            }
            const auto csrf = submit ? std::optional(header(request, "x-droidvm-csrf").value_or("")) : std::nullopt;
            const auto session = sessions_.authenticate(cookie(request), csrf, true, request.trusted_lan);
            if (!session.caller.administrator || !session.caller.manage_tasks) throw ServiceError(ErrorCode::permission_denied, "VM operation permission required");
            if (!operations.submit || !operations.find) return problem(501, "unsupported");
            Json::Value result;
            if (submit) {
                auto input = parse_object(request);
                ParsedSecretGuard secret{agent ? &input : nullptr};
                const auto expected_size = (hugepage || hugepage_process || host_preference || usb_acm || disk_default) ? 4u : image_install ? 5u : (import_plan || image_plan || image_import) ? 3u : package_import ? 4u : package ? 7u : rescue ? 3u : (recovery || config_recovery || agent_recovery) ? 2u : 5u;
                if (input.size() != expected_size + (agent && input.isMember("rescue") ? 1u : 0u)
                    || (agent && input.isMember("rescue") && !input["rescue"].isBool())
                    || !input["context"].isObject() || input["context"].size() != 2 ||
                    !input["context"]["daemonEpoch"].isString() || !input["context"]["sessionId"].isString()) invalid();
                if (input["context"] != context_json(session)) return problem(409, "context_changed");
                if (agent && input.get("rescue", false).asBool() && !rescue_available(resources_.agent_rescue))
                    return problem(501, "unsupported");
                if (disk && input["operation"].isObject() && input["operation"]["action"] == "clone" &&
                    input["operation"].isMember("createFolder") && !resources_.disk_clone_directory)
                    return problem(501, "unsupported");
                input.removeMember("context");
                result["task"] = operations.submit(session.caller, input);
            } else {
                if (!request.body.empty()) invalid();
                result["task"] = operations.find(session.caller, request.path.substr(base.size() + 1));
            }
            result["context"] = context_json(session);
            return json(submit ? 202 : 200, result);
        }
        if (request.path.starts_with("/api/v1/tasks/receipts/")) {
            if (request.method != "GET") return problem(405, "method_not_allowed");
            if (!request.body.empty()) invalid();
            const auto session = sessions_.authenticate(cookie(request), std::nullopt, true, request.trusted_lan);
            if (!session.caller.administrator || !session.caller.manage_tasks)
                throw ServiceError(ErrorCode::permission_denied, "Recovery permission required");
            if (!tasks_.receipt) return problem(404, "not_found");
            const auto id = request.path.substr(std::string_view("/api/v1/tasks/receipts/").size());
            if (id.empty() || id.size() > 128 ||
                id.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::string::npos) invalid();
            Json::Value result;
            result["context"] = context_json(session);
            result["hostId"] = tasks_.host_id;
            result["receipt"] = tasks_.receipt(session.caller, id);
            return json(200, result);
        }
        if (request.path == "/api/v1/tasks" || request.path == "/api/v1/tasks/cancel") {
            const bool cancel = request.path == "/api/v1/tasks/cancel";
            if (request.method != (cancel ? "POST" : "GET")) {
                auto response = problem(405, "method_not_allowed"); response.headers.emplace_back("Allow", cancel ? "POST" : "GET"); return response;
            }
            const auto csrf = cancel ? std::optional(header(request, "x-droidvm-csrf").value_or("")) : std::nullopt;
            const auto session = sessions_.authenticate(cookie(request), csrf, true, request.trusted_lan);
            if (!session.caller.manage_tasks) throw ServiceError(ErrorCode::permission_denied, "Task permission required");
            Json::Value result;
            if (cancel) {
                const auto input = parse_object(request);
                if (input.size() != 2 || !input["context"].isObject() || input["context"].size() != 2 ||
                    !input["context"]["daemonEpoch"].isString() || !input["context"]["sessionId"].isString() ||
                    !input["taskId"].isString()) invalid();
                const auto id = input["taskId"].asString();
                if (id.empty() || id.size() > 128 || id.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::string::npos) invalid();
                if (input["context"] != context_json(session)) return problem(409, "context_changed");
                if (!tasks_.cancel) return problem(501, "unsupported");
                result["task"] = tasks_.cancel(session.caller, id);
            } else {
                if (!request.body.empty()) invalid();
                if (!tasks_.list) return problem(501, "unsupported");
                result = tasks_.list(session.caller);
            }
            result["context"] = context_json(session);
            return json(200, result);
        }
        return problem(404, "not_found");
    } catch (const ServiceError& error) {
        switch (error.code()) {
        case ErrorCode::invalid_argument: return problem(400, "invalid_argument");
        case ErrorCode::unauthenticated: return problem(401, "unauthenticated");
        case ErrorCode::permission_denied: return problem(403, "permission_denied");
        case ErrorCode::resource_exhausted: return problem(429, "resource_exhausted");
        case ErrorCode::unavailable: return problem(503, "unavailable");
        case ErrorCode::not_found: return problem(404, "not_found");
        case ErrorCode::task_not_found: return problem(404, "task_not_found");
        case ErrorCode::not_cancellable: return problem(409, "not_cancellable");
        case ErrorCode::conflict: return problem(409, "conflict");
        case ErrorCode::task_epoch_mismatch: return problem(409, "context_changed");
        case ErrorCode::snapshot_expired: return problem(409, "snapshot_expired");
        default: return problem(500, "internal");
        }
    } catch (...) { return problem(500, "internal"); }
}
HttpResponse HttpApi::static_resource(const HttpRequest& request, const StaticAsset& asset) {
    if (request.method != "GET" && request.method != "HEAD") {
        auto response = problem(405, "method_not_allowed");
        response.headers.emplace_back("Allow", "GET, HEAD");
        return response;
    }
    if (!request.body.empty()) invalid();
    // Prefer gzip at equal quality. Invalid/ambiguous values never enable compression.
    int gzip = -1, identity = -1, wildcard = -1;
    if (auto encoding = header(request, "accept-encoding")) {
        auto remaining = *encoding;
        while (!remaining.empty()) {
            const auto comma = remaining.find(',');
            auto item = trim(remaining.substr(0, comma));
            const auto semicolon = item.find(';');
            const auto name = trim(item.substr(0, semicolon));
            int quality = 1000;
            if (semicolon != std::string_view::npos) {
                auto parameter = trim(item.substr(semicolon + 1));
                if (!parameter.starts_with("q=")) quality = 0;
                else {
                    parameter.remove_prefix(2);
                    quality = encoding_quality(parameter);
                }
            }
            if (same_name(name, "gzip")) gzip = quality;
            else if (same_name(name, "identity")) identity = quality;
            else if (name == "*") wildcard = quality;
            if (comma == std::string_view::npos) break;
            remaining.remove_prefix(comma + 1);
        }
    }
    if (gzip < 0) gzip = std::max(0, wildcard);
    if (identity < 0) identity = wildcard == 0 ? 0 : 1000;
    const bool compressed = !asset.gzip.empty() && gzip > 0 && gzip >= identity;
    if (!compressed && identity == 0) return problem(406, "not_acceptable");
    std::string etag(asset.etag);
    if (compressed) etag.insert(etag.size() - 1, "-gzip");
    HttpResponse response{200, {
        {"Content-Type", std::string(asset.type)},
        {"Cache-Control", asset.path == "/index.html" ? "no-cache" : "public, max-age=31536000, immutable"},
        {"ETag", etag}, {"Vary", "Accept-Encoding"},
        {"X-Content-Type-Options", "nosniff"}, {"Referrer-Policy", "no-referrer"},
        {"Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"},
        {"X-Frame-Options", "DENY"}
    }, {}};
    if (compressed) response.headers.emplace_back("Content-Encoding", "gzip");
    if (auto match = header(request, "if-none-match")) {
        auto remaining = *match;
        while (!remaining.empty()) {
            const auto comma = remaining.find(',');
            auto item = trim(remaining.substr(0, comma));
            if (item.starts_with("W/")) item.remove_prefix(2);
            if (item == "*" || item == etag) { response.status = 304; return response; }
            if (comma == std::string_view::npos) break;
            remaining.remove_prefix(comma + 1);
        }
    }
    response.body = compressed ? asset.gzip : asset.body;
    return response; // The transport suppresses HEAD payload, retaining its Content-Length.
}
SessionView HttpApi::authorize_stream(const HttpRequest& request, bool touch) {
    if (request.method != "GET" || !request.body.empty()) invalid();
    check_origin(request, true);
    // The stream router still checks path, target and capability before upgrade.
    return sessions_.authenticate(cookie(request), std::nullopt, touch, request.trusted_lan);
}
Json::Value HttpApi::parse_stream_frame(const std::string& frame) {
    if (frame.empty() || frame.size() > 4096) invalid();
    return parse_object({"", "", {{"content-type", "application/json"}}, frame});
}
SessionView HttpApi::authorize_events(const HttpRequest& request, const Json::Value& subscription) {
    if (!events_ || request.path != "/api/v1/events") throw ServiceError(ErrorCode::not_found, "Stream unavailable");
    const auto view = authorize_stream(request);
    if (subscription.isNull()) return view; // Upgrade / periodic revocation check.
    if (!subscription.isObject() || subscription.size() != 4 || subscription["type"] != "subscribe" ||
        !subscription["csrfToken"].isString() || !subscription.isMember("cursor")) invalid();
    const auto checked = sessions_.authenticate(cookie(request), subscription["csrfToken"].asString(), false, request.trusted_lan);
    if (subscription["context"] != context_json(checked)) throw ServiceError(ErrorCode::conflict, "Session context changed");
    return checked;
}
SessionView HttpApi::authorize_terminal(const HttpRequest& request, const Json::Value& frame) {
    const auto source = terminal_source(request.path);
    if (!source || !source->list || !source->read || !source->write
        || (request.path == "/api/v1/terminal" && !resources_.terminal_catalog))
        throw ServiceError(ErrorCode::not_found, "Terminal unavailable");
    const auto view = authorize_stream(request);
    if (!view.caller.administrator || (request.path == "/api/v1/agent-rescue-terminal" && !view.caller.manage_tasks))
        throw ServiceError(ErrorCode::permission_denied, "Terminal permission required");
    if (frame.isNull()) return view;
    if (!frame.isObject() || frame.size() != 7 || frame["type"] != "open" || !frame["csrfToken"].isString()) invalid();
    const auto checked = sessions_.authenticate(cookie(request), frame["csrfToken"].asString(), false, request.trusted_lan);
    if (frame["context"] != context_json(checked)) throw ServiceError(ErrorCode::conflict, "Session context changed");
    return checked;
}
SessionView HttpApi::authorize_display(const HttpRequest& request, const Json::Value& frame) {
    if (request.path != "/api/v1/display" || !resources_.display_source || !resources_.display_source->list || !resources_.display_source->open)
        throw ServiceError(ErrorCode::not_found, "Display unavailable");
    const auto view = authorize_stream(request);
    if (!view.caller.administrator) throw ServiceError(ErrorCode::permission_denied, "Display permission required");
    if (frame.isNull()) return view;
    if (!frame.isObject() || frame.size() != 6 || frame["type"] != "open" || !frame["csrfToken"].isString()) invalid();
    const auto checked = sessions_.authenticate(cookie(request), frame["csrfToken"].asString(), false, request.trusted_lan);
    if (frame["context"] != context_json(checked)) throw ServiceError(ErrorCode::conflict, "Display context changed");
    return checked;
}
std::shared_ptr<void> HttpApi::reserve_display(const HttpRequest& request) {
    (void)authorize_display(request, Json::Value()); return sessions_.reserve_display(cookie(request));
}
}
