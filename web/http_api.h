// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "session.h"
#include "static_assets.h"
#include <json/json.h>
#include <utility>

namespace droidvm::web {
struct VmTerminalSource;
struct VmDisplaySource;
using Headers = std::vector<std::pair<std::string, std::string>>;
struct HttpRequest {
    std::string method;
    std::string path; // Raw path including query: no credentials accepted in URLs.
    Headers headers; // Preserve duplicate fields so ambiguity can be rejected.
    std::string body;
    bool binary = false; // WebSocket frame only; HTTP handlers never set this.
    bool trusted_lan = false; // Transport-only: enabled policy and directly connected LAN peer.
};
struct HttpStreamBody {
    uint64_t length = 0;
    // Worker-only, exact bounded read; the transport retains one block at a time.
    std::function<std::string(uint64_t offset, size_t maximum)> read;
    size_t chunk_bytes = 256u << 10;
};
struct HttpResponse { int status; Headers headers; std::string body; std::shared_ptr<HttpStreamBody> stream{}; bool binary = false; };
struct AccessOrigin { std::string authority; std::string origin; };
struct WebBuild { std::string version, version_code; };
struct ServerInfo { std::string daemon_epoch; WebBuild build; };
struct TaskOperations {
    std::function<Json::Value(const CallContext&)> list;
    std::function<Json::Value(const CallContext&, const std::string&)> cancel;
    std::function<Json::Value(const CallContext&, const std::string&)> receipt{};
    std::string host_id{};
};
struct BackgroundOperations {
    std::function<Json::Value(const CallContext&, const Json::Value&)> submit;
    std::function<Json::Value(const CallContext&, const std::string&)> find;
};
using VmOperations = BackgroundOperations;
using UsbOperations = BackgroundOperations;
struct DiskRecoveryOperations {
    std::function<Json::Value(const CallContext&)> status;
    BackgroundOperations tasks;
};
struct AgentRescueOperations {
    std::function<Json::Value(const CallContext&)> list;
    BackgroundOperations close;
    std::shared_ptr<VmTerminalSource> terminal_source;
};
struct PackageExportOperations {
    std::function<Json::Value(const CallContext&, const std::string&)> plan;
    BackgroundOperations tasks;
};
struct PackageImportOperations {
    BackgroundOperations plans;
    BackgroundOperations tasks;
};
using ImageImportOperations = PackageImportOperations;
struct PackageUploadOperations {
    std::function<Json::Value(const CallContext&, const Json::Value&)> begin;
    std::function<Json::Value(const CallContext&, const std::string&)> status, finish;
    std::function<Json::Value(const CallContext&, const std::string&, const Json::Value&)> append;
    std::function<void(const CallContext&, const std::string&)> erase;
};
struct PackageDownloadOperations {
    std::function<Json::Value(const CallContext&, const Json::Value&)> begin;
    std::function<Json::Value(const CallContext&, const std::string&)> status;
    std::function<HttpResponse(const CallContext&, const std::string&, uint32_t)> file;
    std::function<void(const CallContext&, const std::string&)> erase;
};
struct PackageTransferOperations { PackageUploadOperations uploads; PackageDownloadOperations downloads; };
struct ImageUploadOperations { PackageUploadOperations uploads; BackgroundOperations installs; };
struct VmLogs {
    std::function<Json::Value(const CallContext&, const std::string&)> list;
    std::function<Json::Value(const CallContext&, const Json::Value&)> read;
};
struct ConfigOperations {
    std::function<Json::Value(const CallContext&, const std::string&, const Json::Value&)> invoke;
    std::function<Json::Value(const CallContext&)> defaults;
    std::function<Json::Value(const CallContext&, const Json::Value&)> preview{};
};
struct ConfigurationBackupOperations {
    ConfigOperations configuration;
    std::function<HttpResponse(const CallContext&)> file;
};
struct WebServiceOperations {
    std::function<Json::Value(const CallContext&)> read;
    BackgroundOperations tasks;
};
using HugepageOperations = WebServiceOperations;
struct HugepageProcessOperations {
    std::function<Json::Value(const CallContext&, const std::string&)> list;
    std::function<Json::Value(const CallContext&, const Json::Value&)> stack;
    BackgroundOperations tasks;
};
struct ResourceCatalogs {
    std::function<Json::Value(const CallContext&)> disks, networks, audio, usb;
    std::function<Json::Value(const CallContext&)> cpus{};
    std::function<Json::Value(const CallContext&)> host_devices{};
    std::function<Json::Value(const CallContext&, const std::string&)> disk_detail{};
    BackgroundOperations disk_actions{};
    DiskRecoveryOperations disk_recovery{};
    ConfigOperations network_configuration{};
    std::function<Json::Value(const CallContext&, const std::string&)> network_detail{};
    std::function<Json::Value(const CallContext&)> host_network{};
    BackgroundOperations network_actions{};
    ConfigOperations network_deletion{};
    BackgroundOperations configuration_recovery{};
    std::function<Json::Value(const CallContext&, const std::string&)> terminal_catalog{};
    std::shared_ptr<VmTerminalSource> terminal_source{};
    BackgroundOperations agent_actions{};
    DiskRecoveryOperations agent_recovery{};
    AgentRescueOperations agent_rescue{};
    PackageExportOperations package_exports{};
    PackageImportOperations package_imports{};
    PackageTransferOperations package_transfers{};
    ConfigurationBackupOperations configuration_backup{};
    WebServiceOperations web_service{};
    ImageImportOperations image_imports{};
    ImageUploadOperations image_uploads{};
    std::shared_ptr<VmDisplaySource> display_source{};
    std::function<Json::Value(const CallContext&)> host_overview{};
    HugepageOperations hugepages{};
    HugepageProcessOperations hugepage_processes{};
    WebServiceOperations host_preferences{};
    WebServiceOperations usb_acm{};
    WebServiceOperations disk_defaults{};
    std::function<Json::Value(const CallContext&, const std::string&)> disk_compression{};
    bool disk_clone_directory = false;
};

// Reusable HTTP boundary: no socket ownership, threads, VM state or persistence.
// The transport enforces peer/listener policy before calling this adapter.
class HttpApi {
public:
    using ListVms = std::function<Json::Value(const CallContext&)>;
    HttpApi(SessionStore& sessions, std::vector<AccessOrigin> origins, ListVms list_vms, ServerInfo server,
        std::span<const StaticAsset> assets = embedded_assets(), TaskOperations tasks = {}, VmOperations vms = {}, VmLogs logs = {}, bool events = false, ConfigOperations config = {}, ResourceCatalogs resources = {}, UsbOperations usb = {}, ConfigOperations usb_rules = {});
    HttpResponse handle(const HttpRequest& request);
    static void validate_origins(const std::vector<AccessOrigin>& origins);
    // Also used before WS upgrade; periodic liveness checks do not refresh idle.
    SessionView authorize_stream(const HttpRequest& request, bool touch = false);
    SessionView authorize_events(const HttpRequest& request, const Json::Value& subscription);
    SessionView authorize_terminal(const HttpRequest& request, const Json::Value& frame);
    SessionView authorize_display(const HttpRequest& request, const Json::Value& frame);
    std::shared_ptr<void> reserve_display(const HttpRequest& request);
    std::shared_ptr<VmDisplaySource> display_source() const { return resources_.display_source; }
    std::shared_ptr<VmTerminalSource> terminal_source(std::string_view path = "/api/v1/terminal") const {
        return path == "/api/v1/agent-rescue-terminal" ? resources_.agent_rescue.terminal_source
            : path == "/api/v1/terminal" ? resources_.terminal_source : nullptr;
    }
    static Json::Value parse_stream_frame(const std::string& frame);
    static size_t request_limit(std::string_view path);
private:
    SessionStore& sessions_;
    std::vector<AccessOrigin> origins_;
    ListVms list_vms_;
    const ServerInfo server_;
    const TaskOperations tasks_;
    const VmOperations vms_;
    const VmLogs logs_;
    const bool events_;
    const ConfigOperations config_;
    const ResourceCatalogs resources_;
    const UsbOperations usb_;
    const ConfigOperations usb_rules_;
    std::span<const StaticAsset> assets_; // Build-time storage must outlive this adapter.
    HttpResponse static_resource(const HttpRequest& request, const StaticAsset& asset);
    void check_origin(const HttpRequest& request, bool required) const;
    static std::optional<std::string_view> header(const HttpRequest& request, std::string_view name);
    static std::string cookie(const HttpRequest& request, std::string_view name = "droidvm-session");
    static Json::Value parse_pairing(const HttpRequest& request);
    static Json::Value parse_object(const HttpRequest& request);
    Json::Value view_json(const SessionView& view) const;
    Json::Value server_json() const;
    Json::Value context_json(const SessionView& view) const;
    static HttpResponse json(int status, const Json::Value& value);
    static HttpResponse problem(int status, const char* code);
    HttpResponse guard_download(const HttpRequest& request, const SessionView& session, HttpResponse response);
};
}
