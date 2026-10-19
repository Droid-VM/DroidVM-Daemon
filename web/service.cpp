// SPDX-License-Identifier: GPL-3.0-or-later
#include "service.h"
#include "task_adapter.h"
#include "event_channel.h"
#include "vm_terminal.h"
#include "vm_display.h"
#include "service_control.h"
#include "services/tasks.h"
#include <algorithm>
#include <atomic>
#include <mutex>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

namespace droidvm::web {
namespace {
void access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (caller.principal != "local-admin" || !caller.administrator)
        throw ServiceError(ErrorCode::permission_denied, "Local administration required");
}
void browser_access(const CallContext& caller) {
    if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
    if (!caller.administrator || caller.principal.empty())
        throw ServiceError(ErrorCode::permission_denied, "Administrator permission required");
}
std::vector<AccessOrigin> origins(const ListenPlan& plan, const WebSettings& settings) {
    std::vector<AccessOrigin> result;
    for (const auto& address : plan.access_addresses) {
        auto authority = (address.find(':') == std::string::npos ? address : "[" + address + "]") + ":" + std::to_string(settings.port);
        result.push_back({authority, "http://" + authority});
    }
    for (const auto& origin : settings.public_origins) result.push_back({origin.substr(7), origin});
    HttpApi::validate_origins(result);
    return result;
}
HttpResponse unavailable() { return {503, {{"Content-Type", "application/json"}, {"Cache-Control", "no-store"}}, "{\"error\":{\"code\":\"unavailable\"}}"}; }
}
Json::Value WebSettings::json() const {
    if (scope != ListenScope::lan && scope != ListenScope::all) throw std::invalid_argument("Invalid WebUI scope");
    Json::Value value; value["enabled"] = enabled; value["port"] = port;
    value["scope"] = scope == ListenScope::lan ? "lan" : "all";
    value["lanAutoLogin"] = lan_auto_login;
    value["publicOrigins"] = Json::Value(Json::arrayValue);
    for (const auto& origin : public_origins) value["publicOrigins"].append(origin);
    return value;
}
WebSettings WebSettings::parse(const Json::Value& value) {
    if (!value.isObject() || value.size() != (value.isMember("lanAutoLogin") ? 5u : 4u) ||
        (value.isMember("lanAutoLogin") && !value["lanAutoLogin"].isBool()) || !value["enabled"].isBool() || !value["port"].isUInt() ||
        value["port"].asUInt() < 1024 || value["port"].asUInt() > 65535 || !value["scope"].isString() ||
        !value["publicOrigins"].isArray() || value["publicOrigins"].size() > 8)
        throw ServiceError(ErrorCode::invalid_argument, "Invalid WebUI settings");
    WebSettings result; result.enabled = value["enabled"].asBool(); result.port = static_cast<uint16_t>(value["port"].asUInt());
    result.lan_auto_login = value.get("lanAutoLogin", false).asBool();
    try { result.scope = listen_scope(value["scope"].asString()); }
    catch (...) { throw ServiceError(ErrorCode::invalid_argument, "Invalid WebUI scope"); }
    for (const auto& origin : value["publicOrigins"]) {
        if (!origin.isString() || !origin.asString().starts_with("http://"))
            throw ServiceError(ErrorCode::invalid_argument, "Invalid public origin");
        result.public_origins.push_back(origin.asString());
    }
    try { origins(make_listen_plan({}, ListenScope::lan, false), result); }
    catch (...) { throw ServiceError(ErrorCode::invalid_argument, "Invalid public origin"); }
    return result;
}
bool ipv6_available() {
    sockaddr_in6 address{}; address.sin6_family = AF_INET6; address.sin6_addr = in6addr_loopback;
#ifdef _WIN32
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data)) return false;
    const auto socket_fd = socket(AF_INET6, SOCK_STREAM, 0);
    const bool result = socket_fd != INVALID_SOCKET && bind(socket_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0;
    if (socket_fd != INVALID_SOCKET) closesocket(socket_fd);
    WSACleanup(); return result;
#else
    const int socket_fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (socket_fd < 0) return false;
    const bool result = bind(socket_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0;
    close(socket_fd); return result;
#endif
}
struct WebService::Impl : std::enable_shared_from_this<WebService::Impl> {
    struct Generation : std::enable_shared_from_this<Generation> {
        std::shared_ptr<SessionStore> sessions;
        HttpApi api;
        std::atomic<bool> active{true};
        Generation(std::shared_ptr<SessionStore> store, std::vector<AccessOrigin> allowed, HttpApi::ListVms list, ServerInfo server, TaskService& tasks, VmOperations vms, VmLogs logs, ConfigOperations config, ResourceCatalogs resources, UsbOperations usb, ConfigOperations usb_rules)
            : sessions(std::move(store)), api(*sessions, std::move(allowed), std::move(list), std::move(server), embedded_assets(), task_operations(tasks), std::move(vms), std::move(logs), true, std::move(config), std::move(resources), std::move(usb), std::move(usb_rules)) {}
        HttpResponse handle(const HttpRequest& request) {
            if (!active) return unavailable();
            auto result = api.handle(request);
            if (result.stream) {
                auto stream = std::make_shared<HttpStreamBody>(*result.stream);
                stream->read = [self = shared_from_this(), read = stream->read](uint64_t offset, size_t maximum) {
                    if (!self->active) throw ServiceError(ErrorCode::unavailable, "Web generation is no longer active");
                    auto bytes = read(offset, maximum);
                    if (!self->active) throw ServiceError(ErrorCode::unavailable, "Web generation is no longer active");
                    return bytes;
                };
                result.stream = std::move(stream);
            }
            return active ? std::move(result) : unavailable();
        }
    };
    TaskService& workers;
    WebSettings settings;
    Discover discover;
    HttpApi::ListVms list_vms;
    VmOperations vm_actions;
    VmLogs vm_logs;
    ConfigOperations vm_config;
    ResourceCatalogs resources;
    UsbOperations usb_actions;
    ConfigOperations usb_rules_actions;
    const WebBuild build;
    Save save;
    Load load;
    SessionPersistence persistence;
    bool configuration_uncertain = false;
    bool apply_pending = false, force_restart = false;
    std::chrono::steady_clock::time_point apply_at{};
    std::function<bool()> ipv6;
    std::mutex mutex;
    std::atomic<bool> stopped{false}, pending{false};
    std::chrono::steady_clock::time_point next{};
    std::shared_ptr<SessionStore> sessions;
    std::shared_ptr<Generation> generation;
    std::vector<std::unique_ptr<HttpListener>> listeners;
    std::optional<ListenPlan> current;
    std::optional<ListenPlan> current_lan;
    WebSettings applied;
    std::string error;
    Impl(TaskService& pool, WebSettings config, Discover scan, HttpApi::ListVms list, Save persist, Load read, WebBuild metadata, std::function<bool()> v6, VmOperations actions, VmLogs logs, ConfigOperations configuration, ResourceCatalogs catalogs, UsbOperations usb, ConfigOperations usb_rules, SessionPersistence credentials)
        : workers(pool), settings(WebSettings::parse(config.json())), discover(std::move(scan)), list_vms(std::move(list)),
          vm_actions(std::move(actions)), vm_logs(std::move(logs)), vm_config(std::move(configuration)), resources(std::move(catalogs)), usb_actions(std::move(usb)), usb_rules_actions(std::move(usb_rules)), build(std::move(metadata)), save(std::move(persist)), load(std::move(read)), persistence(std::move(credentials)), ipv6(std::move(v6)) {
        if (!discover || !list_vms || !save || !load || !ipv6) throw std::invalid_argument("Missing WebUI dependencies");
    }
    void close(bool clear_sessions) {
        if (generation) generation->active = false;
        listeners.clear(); generation.reset(); current.reset(); current_lan.reset();
        if (sessions) sessions->revoke_local();
        if (clear_sessions && sessions) { sessions->shutdown(); sessions.reset(); }
    }
    void ensure_sessions() {
        if (!sessions) sessions = std::make_shared<SessionStore>(SessionLimits{}, SessionStore::Clock::now, SessionStore::Random{}, persistence);
    }
    void activate(ListenPlan plan, ListenPlan lan_plan) {
        auto allowed = origins(plan, settings);
        auto catalogs = resources;
        const auto owner = weak_from_this();
        catalogs.web_service = web_service_operations(workers, {
            [owner](const CallContext& caller) {
                auto service = owner.lock();
                if (!service) throw ServiceError(ErrorCode::unavailable, "WebUI service is no longer available");
                return service->browser_status(caller);
            },
            [owner](const CallContext& caller, const Json::Value& request) {
                auto service = owner.lock();
                if (!service) throw ServiceError(ErrorCode::unavailable, "WebUI service is no longer available");
                return service->browser_change(caller, request);
            }
        });
        generation = std::make_shared<Generation>(sessions, std::move(allowed), list_vms, ServerInfo{workers.epoch(), build}, workers, vm_actions, vm_logs, vm_config, std::move(catalogs), usb_actions, usb_rules_actions);
        for (const auto& endpoint : plan.endpoints) {
            HttpListenConfig config; config.address = endpoint.address; config.port = settings.port;
            config.allow_peer = [endpoint](std::string_view peer) { return endpoint.allows(peer); };
            if (settings.lan_auto_login) config.trusted_lan = [lan_plan](std::string_view peer, std::string_view local) {
                return direct_lan_peer(lan_plan, peer, local);
            };
            auto listener = std::make_unique<HttpListener>(std::move(config), workers,
                [state = generation](const auto& request) { return state->handle(request); },
                [state = generation, &tasks = workers](const HttpRequest& request) -> AsyncHttp::Handle {
                    if (request.path == "/api/v1/display") {
                        auto quota = state->api.reserve_display(request);
                        auto channel = std::make_shared<VmDisplayChannel>(*state->api.display_source(), tasks.epoch(),
                            [state, request](const Json::Value& frame) {
                                if (!state->active) throw ServiceError(ErrorCode::unavailable, "Listener replaced");
                                return state->api.authorize_display(request, frame);
                            }, std::move(quota));
                        return [channel](const HttpRequest& frame) { return channel->next(frame); };
                    }
                    if (request.path == "/api/v1/terminal" || request.path == "/api/v1/agent-rescue-terminal") {
                        state->api.authorize_terminal(request, Json::Value());
                        auto channel = std::make_shared<VmTerminalChannel>(*state->api.terminal_source(request.path), tasks.epoch(),
                            [state, request](const Json::Value& frame) {
                                if (!state->active) throw ServiceError(ErrorCode::unavailable, "Listener replaced");
                                return state->api.authorize_terminal(request, frame);
                            });
                        return [channel](const HttpRequest& frame) { return channel->next(frame); };
                    }
                    auto channel = std::make_shared<EventChannel>(tasks, [state, request](const Json::Value& frame) {
                        if (!state->active) throw ServiceError(ErrorCode::unavailable, "Listener replaced");
                        return state->api.authorize_events(request, frame);
                    });
                    return [channel](const HttpRequest& frame) { return channel->next(frame); };
                });
            listener->start(); listeners.push_back(std::move(listener));
        }
        current = std::move(plan); current_lan = std::move(lan_plan); applied = settings;
    }
    void reconcile() { // mutex held, worker only
        if (apply_pending) {
            if (std::chrono::steady_clock::now() < apply_at) return;
            apply_pending = false;
        }
        next = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        if (configuration_uncertain) { force_restart = false; close(true); return; }
        if (stopped || !settings.enabled) { force_restart = false; close(true); error.clear(); return; }
        ListenPlan plan, lan_plan;
        bool v6 = false;
        error.clear();
        try {
            v6 = ipv6(); const auto snapshot = discover();
            plan = make_listen_plan(snapshot, settings.scope, v6);
            if (settings.lan_auto_login) lan_plan = make_listen_plan(snapshot, ListenScope::lan, v6);
        }
        catch (...) {
            // Discovery failure revokes old address/prefix admission immediately
            // at reconciliation, including when configured for all networks.
            plan = make_listen_plan({}, ListenScope::lan, v6); error = "discovery_failed";
        }
        if (stopped) { close(true); return; }
        if (!force_restart && current && *current == plan && current_lan == lan_plan && applied == settings) return;
        force_restart = false;
        close(false); // closes old connections before narrowing admission
        ensure_sessions();
        try { activate(std::move(plan), std::move(lan_plan)); }
        catch (...) {
            close(false); error = "listen_failed";
            try { activate(make_listen_plan({}, ListenScope::lan, v6), {}); }
            catch (...) { close(false); }
        }
    }
    void cancel_application() { apply_pending = false; force_restart = false; }
    void queue_application(bool restart) {
        apply_pending = true; force_restart = force_restart || restart;
        apply_at = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    }
    Json::Value browser_status(const CallContext& caller) {
        browser_access(caller);
        std::lock_guard lock(mutex);
        if (stopped) throw ServiceError(ErrorCode::unavailable, "WebUI service is stopping");
        return status();
    }
    Json::Value browser_change(const CallContext& caller, const Json::Value& request) {
        browser_access(caller);
        if (!request.isObject() || request.size() != 3 || !request["action"].isString())
            throw ServiceError(ErrorCode::invalid_argument, "Invalid WebUI service change");
        const auto action = request["action"].asString();
        if (action != "configure" && action != "restart")
            throw ServiceError(ErrorCode::invalid_argument, "Invalid WebUI service action");
        const auto expected = WebSettings::parse(request["expected"]);
        auto wanted = WebSettings::parse(request["settings"]);
        if (action == "restart" && expected != wanted)
            throw ServiceError(ErrorCode::invalid_argument, "Restart cannot change WebUI settings");
        std::lock_guard lock(mutex);
        if (stopped) throw ServiceError(ErrorCode::unavailable, "WebUI service is stopping");
        if (configuration_uncertain)
            throw ServiceError(ErrorCode::commit_uncertain, "Reload WebUI settings from the App before applying changes");
        if (apply_pending)
            throw ServiceError(ErrorCode::conflict, "A WebUI settings change is already waiting to apply");
        if (settings != expected) throw ServiceError(ErrorCode::conflict, "WebUI settings changed; reload before applying changes");
        // Allocate the receipt before persistence; after save succeeds only
        // nonthrowing moves and deadline updates remain before returning it.
        Json::Value result; result["action"] = action; result["settings"] = wanted.json(); result["applyPending"] = true;
        if (action == "configure" && settings != wanted) {
            try { save(wanted.json()); }
            catch (...) {
                configuration_uncertain = true; error = "configuration_write_failed";
                // Preserve the current response path until maintenance; do not
                // claim persistence or close its listener on this worker.
                queue_application(false);
                throw ServiceError(ErrorCode::commit_uncertain, "WebUI settings write could not be confirmed; reload from the App");
            }
            settings = std::move(wanted);
        }
        queue_application(action == "restart");
        return result;
    }
    Json::Value status() { // mutex held; browser-safe projection
        Json::Value result; result["settings"] = settings.json(); result["running"] = !listeners.empty();
        const bool only_local = current && std::all_of(current->endpoints.begin(), current->endpoints.end(),
            [](const auto& endpoint) { return !endpoint.unrestricted && endpoint.interface_name.empty(); });
        result["state"] = configuration_uncertain ? "error" : stopped ? "disabled" : !listeners.empty() ?
            (only_local ? "local_only" : "running") : !settings.enabled ? "disabled" : "error";
        result["error"] = error.empty() ? Json::Value() : Json::Value(error);
        result["addresses"] = Json::Value(Json::arrayValue); result["applyPending"] = apply_pending;
        if (current) for (const auto& origin : origins(*current, applied)) result["addresses"].append(origin.origin);
        return result;
    }
};
WebService::WebService(TaskService& workers, WebSettings settings, Discover discover, HttpApi::ListVms list, Save save, Load load, WebBuild build, std::function<bool()> ipv6, VmOperations vms, VmLogs logs, ConfigOperations config, ResourceCatalogs resources, UsbOperations usb, ConfigOperations usb_rules, SessionPersistence persistence)
    : impl_(std::make_shared<Impl>(workers, std::move(settings), std::move(discover), std::move(list), std::move(save), std::move(load), std::move(build), std::move(ipv6), std::move(vms), std::move(logs), std::move(config), std::move(resources), std::move(usb), std::move(usb_rules), std::move(persistence))) {}
WebService::~WebService() { stop(); }
void WebService::stop() {
    impl_->stopped = true;
    std::lock_guard lock(impl_->mutex); impl_->cancel_application(); impl_->close(true);
}
void WebService::schedule() {
    auto state = impl_;
    if (state->stopped || state->pending.exchange(true)) return;
    {
        std::unique_lock lock(state->mutex, std::try_to_lock);
        if (!lock || (state->apply_pending ? std::chrono::steady_clock::now() < state->apply_at :
                !state->settings.enabled || std::chrono::steady_clock::now() < state->next)) {
            state->pending = false; return;
        }
    }
    try {
        state->workers.post({"web-maintenance", true, true, false}, [state](bool discarded) {
            try {
                std::lock_guard lock(state->mutex);
                if (!discarded && !state->stopped && (state->apply_pending ? std::chrono::steady_clock::now() >= state->apply_at :
                    state->settings.enabled && std::chrono::steady_clock::now() >= state->next)) state->reconcile();
            } catch (...) {}
            state->pending = false;
        });
    } catch (...) { state->pending = false; }
}
Json::Value WebService::execute(const CallContext& caller, const std::string& command, const Json::Value& request) {
    access(caller);
    if (!request.isObject()) throw ServiceError(ErrorCode::invalid_argument, "WebUI request must be an object");
    std::lock_guard lock(impl_->mutex);
    if (impl_->stopped) throw ServiceError(ErrorCode::unavailable, "WebUI service is stopping");
    // Keep remembered browsers visible/revocable from the App even when HTTP is disabled.
    impl_->ensure_sessions();
    if (command == "web_configure") {
        if (impl_->configuration_uncertain) throw ServiceError(ErrorCode::commit_uncertain, "Reload WebUI settings before saving");
        const auto expected = WebSettings::parse(request["expected"]), settings = WebSettings::parse(request["settings"]);
        if (impl_->settings != expected) throw ServiceError(ErrorCode::conflict, "WebUI settings changed; reload before saving");
        impl_->cancel_application();
        if (impl_->settings != settings) {
            try { impl_->save(settings.json()); }
            catch (...) {
                impl_->close(true); impl_->configuration_uncertain = true; impl_->error = "configuration_write_failed";
                throw ServiceError(ErrorCode::commit_uncertain, "WebUI settings write could not be confirmed; reload before saving");
            }
            impl_->settings = settings;
        }
        impl_->reconcile();
    } else if (command == "web_reload") {
        auto loaded = WebSettings::parse(impl_->load().json());
        impl_->cancel_application();
        // Explicit local recovery also replaces a retired authorization store.
        impl_->close(true);
        impl_->settings = std::move(loaded); impl_->configuration_uncertain = false;
        impl_->reconcile();
    } else if (command == "web_pair") {
        if (!impl_->sessions || impl_->listeners.empty()) throw ServiceError(ErrorCode::unavailable, "WebUI is not listening");
        Json::Value result; result["pairingToken"] = impl_->sessions->issue_pairing(caller).token; return result;
    } else if (command == "web_revoke") {
        if (!request["session_id"].isString()) throw ServiceError(ErrorCode::invalid_argument, "Missing session ID");
        if (impl_->sessions) impl_->sessions->revoke(caller, request["session_id"].asString());
    } else if (command != "web_status") throw ServiceError(ErrorCode::invalid_argument, "Unknown WebUI command");
    impl_->ensure_sessions();
    auto result = impl_->status(); result["sessions"] = Json::Value(Json::arrayValue);
    if (impl_->sessions) for (const auto& id : impl_->sessions->session_ids(caller)) result["sessions"].append(id);
    return result;
}
}
