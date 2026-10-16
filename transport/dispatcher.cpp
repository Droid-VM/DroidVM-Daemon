// SPDX-License-Identifier: GPL-3.0-or-later
#include "dispatcher.h"
#include "common/wire.h"
#include "store/network_config.h"
#include "store/vm_config.h"
#include "vm/console.h"
#include "vm/crosvm_command.h"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <array>
#include <limits>
#include <unistd.h>

namespace droidvm {
namespace {
constexpr std::array commands{"task_get", "task_cancel", "task_snapshot", "task_snapshot_page",
                              "task_snapshot_release", "task_subscribe", "task_unsubscribe",
                              "network_config_snapshot", "network_config_document", "resource_snapshot_page", "resource_snapshot_release",
                              "resource_subscribe", "resource_unsubscribe"};
constexpr std::array network_commands{"network_create", "network_modify", "network_list", "network_info", "network_exists",
    "network_config_get", "network_config_update"};
constexpr std::array vm_upload_commands{"vm_config_upload_begin", "vm_config_upload_append", "vm_config_upload_commit", "vm_config_upload_abort"};
constexpr std::array network_upload_commands{"network_config_import_begin", "network_config_import_append", "network_config_import_commit", "network_config_import_abort"};
constexpr std::array delete_upload_commands{"network_config_delete_begin", "network_config_delete_append", "network_config_delete_commit", "network_config_delete_abort"};
bool delete_upload_command(const std::string& command) { return std::find(delete_upload_commands.begin(), delete_upload_commands.end(), command) != delete_upload_commands.end(); }
bool configuration_command(const std::string& command) { return command == "configuration_recover" || delete_upload_command(command); }
bool network_upload_command(const std::string& command) { return std::find(network_upload_commands.begin(), network_upload_commands.end(), command) != network_upload_commands.end(); }
bool vm_upload_command(const std::string& command) { return std::find(vm_upload_commands.begin(), vm_upload_commands.end(), command) != vm_upload_commands.end(); }
bool vm_config_command(const std::string& command) { return command == "vm_config_status" || command == "vm_config_apply" || command == "vm_config_snapshot" || command == "vm_start_configured" || vm_upload_command(command); }
constexpr std::array host_commands{"network_list_interfaces", "network_list_uplinks", "network_list_host_addresses"};
bool host_command(const std::string& command) {
    return std::find(host_commands.begin(), host_commands.end(), command) != host_commands.end();
}
constexpr std::array vm_commands{"vm_create", "vm_modify", "vm_delete", "vm_list", "vm_get", "vm_exists", "vm_status",
    "vm_start", "vm_stop", "vm_stop_all", "vm_reboot", "vm_suspend", "vm_resume", "vm_control", "vm_console_list",
    "vm_console_info", "vm_console_history", "vm_console_write", "vm_console_clear", "vm_vnc_info", "vm_input",
    "vm_bootscan", "set_app_config"};
// android.util.Base64.decode(NO_WRAP) of a client's evdev bytes.
std::string base64_decode(const std::string& text) {
    std::string out;
    uint32_t buffer = 0;
    int bits = 0;
    for (const char c : text) {
        int value;
        if (c >= 'A' && c <= 'Z') value = c - 'A';
        else if (c >= 'a' && c <= 'z') value = c - 'a' + 26;
        else if (c >= '0' && c <= '9') value = c - '0' + 52;
        else if (c == '+') value = 62;
        else if (c == '/') value = 63;
        else if (c == '=') break;
        else if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        else throw std::invalid_argument("bad base-64");
        buffer = buffer << 6 | static_cast<uint32_t>(value);
        bits += 6;
        if (bits >= 8) { bits -= 8; out += static_cast<char>((buffer >> bits) & 0xff); }
    }
    return out;
}
// JSONObject.optInt: numbers truncate, numeric strings parse as double.
int legacy_int(const Json::Value& request, const char* key, int fallback) {
    if (!request.isMember(key)) return fallback;
    const auto& value = request[key];
    double number;
    if (value.isNumeric() && !value.isBool()) number = value.asDouble();
    else if (value.isString()) {
        try { size_t used = 0; const auto text = value.asString(); number = std::stod(text, &used); if (used != text.size()) return fallback; }
        catch (const std::exception&) { return fallback; }
    } else return fallback;
    if (std::isnan(number)) return 0;
    if (number >= 2147483647.0) return 2147483647;
    if (number <= -2147483648.0) return -2147483647 - 1;
    return static_cast<int>(number);
}
// JSONObject.optBoolean: a boolean, or the strings "true"/"false" in any case.
bool legacy_flag(const Json::Value& request, const char* key, bool fallback = false) {
    if (!request.isMember(key)) return fallback;
    return input::java_boolean(request[key], fallback);
}
constexpr std::array keyboard_commands{"kbd_config", "kbd_grab", "kbd_status"};
bool keyboard_command(const std::string& command) {
    return std::find(keyboard_commands.begin(), keyboard_commands.end(), command) != keyboard_commands.end();
}
constexpr std::array usb_commands{"usb_attach", "usb_detach", "usb_host_list", "usb_rules_get", "usb_rules_set",
    "usb_rules_test", "usb_set_target", "usb_vm_list"};
bool usb_command(const std::string& command) {
    return std::find(usb_commands.begin(), usb_commands.end(), command) != usb_commands.end();
}
bool package_command(const std::string& command) { return command == "vm_export" || command == "vm_import"; }
bool vm_command(const std::string& command) {
    return std::find(vm_commands.begin(), vm_commands.end(), command) != vm_commands.end();
}
constexpr std::array runtime_commands{"network_start", "network_stop", "network_status", "network_tool_log",
    "network_delete", "network_pd_renew", "network_pd_release", "network_add_address", "network_remove_address",
    "network_add_interface", "network_remove_interface"};
bool runtime_command(const std::string& command) {
    return std::find(runtime_commands.begin(), runtime_commands.end(), command) != runtime_commands.end();
}
void runtime_fields(Json::Value& row, const NetworkView& view, bool lowercase) {
    // Legacy UI knows four states. Unresolved cleanup must never look STOPPED;
    // publish the exact native state separately for capable clients.
    auto projected = view.state;
    if (projected == NetworkState::recovering) projected = NetworkState::starting;
    if (projected == NetworkState::failed) projected = view.desired_running ? NetworkState::starting : NetworkState::stopping;
    std::string state = network_state_name(projected);
    if (lowercase) for (auto& c : state) c += 'a' - 'A';
    row["state"] = state;
    row["runtime_state"] = network_state_name(view.state);
    row["runtime_error"] = view.error;
    row["runtime_generation"] = std::to_string(view.generation);
    row["desired_running"] = view.desired_running;
    row["tools"] = view.tools;
}
CallContext context(const ClientSession& session) {
    // The existing IPC token grants local administrator rights. Never accept
    // principal/permissions from fields in the request, or use client_id as owner.
    return {"local-admin", session.caller.authorized, true, true};
}
std::string string_field(const Json::Value& request, const char* key) {
    if (!request[key].isString() || request[key].asString().size() > 128)
        throw ServiceError(ErrorCode::invalid_argument, std::string("Invalid ") + key);
    return request[key].asString();
}
size_t size_field(const Json::Value& request, const char* key, size_t fallback) {
    if (!request.isMember(key)) return fallback;
    if (!request[key].isUInt64() || request[key].asUInt64() > std::numeric_limits<size_t>::max())
        throw ServiceError(ErrorCode::invalid_argument, std::string("Invalid ") + key);
    return static_cast<size_t>(request[key].asUInt64());
}
Json::Value failure(const ServiceError& error) {
    Json::Value result;
    result["success"] = false;
    result["message"] = error.what();
    result["error"]["code"] = error_code_name(error.code());
    result["error"]["message"] = error.what();
    return result;
}
Json::Value config_status(const VmConfigService::Snapshot& snapshot) {
    Json::Value result;
    result["success"] = true;
    result["revision"] = snapshot->revision;
    result["persisted"] = snapshot->persisted;
    result["recovered"] = snapshot->recovered;
    result["durability_uncertain"] = snapshot->durability_uncertain;
    result["count"] = snapshot->document["vms"].size();
    return result;
}
Json::Value snapshot_json(const SnapshotPage& page) {
    Json::Value value;
    value["success"] = true;
    value["snapshot_id"] = page.id;
    value["epoch"] = page.cursor.epoch;
    value["cursor"] = std::to_string(page.cursor.sequence);
    value["total"] = Json::UInt64(page.total);
    value["next_offset"] = page.next ? Json::Value(Json::UInt64(*page.next)) : Json::Value();
    auto& items = value["items"] = Json::Value(Json::arrayValue);
    for (const auto& row : page.items) items.append(wire::parse(row));
    return value;
}
std::string legacy_id(const Json::Value& request, const char* key = "network_id") {
    // JSONObject.optString distinguishes an absent key from JSONObject.NULL
    // and stringifies other JSON values. DataItem's strict accessor is different.
    if (!request.isMember(key)) return {};
    const auto& value = request[key];
    if (value.isString()) return value.asString();
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    builder["emitUTF8"] = true;
    return Json::writeString(builder, value);
}
}
bool RequestDispatcher::background(const std::string& command) const {
    if (configuration_ && configuration_command(command)) return true;
    if (networks_ && network_upload_command(command)) return true;
    return (vm_config_ && (command == "vm_config_apply" || command == "vm_start_configured" || vm_upload_command(command))) || (display_attach_ && command == "display_attach") || (usb_ && usb_command(command)) || (packages_ && package_command(command)) ||
        (host_network_ && host_command(command)) || (vms_ && vm_command(command)) || (keyboard_ && keyboard_command(command)) ||
        (runtime_ && runtime_command(command)) ||
        (networks_ && std::find(network_commands.begin(), network_commands.end(), command) != network_commands.end());
}
Json::Value RequestDispatcher::execute_background(const CallContext& caller, const std::string& command, const Json::Value& request) {
    if (configuration_ && configuration_command(command)) {
        try {
            if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
            if (!caller.administrator || caller.principal.empty()) throw ServiceError(ErrorCode::permission_denied, "Administrator permission required");
            if (!request.isObject()) throw ServiceError(ErrorCode::invalid_argument, "Configuration request must be an object");
            const bool begin = command == "network_config_delete_begin", append = command == "network_config_delete_append";
            for (const auto& key : request.getMemberNames()) {
                if (key == "type" || key == "command" || key == "request_id") continue;
                if (command != "configuration_recover" && ((begin && (key == "revision" || key == "bytes"))
                    || (!begin && key == "upload_id") || (append && (key == "offset" || key == "data")))) continue;
                throw ServiceError(ErrorCode::invalid_argument, "Unexpected configuration transaction field");
            }
            Json::Value result; result["success"] = true;
            if (command == "configuration_recover") { configuration_->recover(caller); return result; }
            if (begin) {
                result["upload_id"] = vm_uploads_->begin_delete(caller, string_field(request, "revision"), size_field(request, "bytes", 0));
                result["chunk_bytes"] = Json::UInt64(ConfigUploads::chunk_bytes);
                result["expires_in_seconds"] = 120;
            } else {
                const auto id = string_field(request, "upload_id");
                if (command == "network_config_delete_commit") {
                    const auto deleted = vm_uploads_->commit_delete(caller, id);
                    result = config_status(deleted.vms); result["network_id"] = deleted.id;
                } else if (command == "network_config_delete_abort") vm_uploads_->abort_delete(caller, id);
                else {
                    if (!request["data"].isString() || !request.isMember("offset"))
                        throw ServiceError(ErrorCode::invalid_argument, "Missing deletion chunk data or offset");
                    std::string bytes;
                    try { bytes = wire::decode_base64(request["data"].asString(), ConfigUploads::chunk_bytes); }
                    catch (const std::exception&) { throw ServiceError(ErrorCode::invalid_argument, "Invalid deletion chunk encoding"); }
                    result["received"] = Json::UInt64(vm_uploads_->append_delete(caller, id, size_field(request, "offset", 0), bytes));
                }
            }
            return result;
        } catch (const ServiceError& error) { return failure(error); }
        catch (...) { return failure(ServiceError(ErrorCode::internal, "Configuration outcome unknown; recover and reload before further operations")); }
    }
    if (vm_config_ && command == "vm_start_configured") {
        try {
            auto snapshot = vm_config_->snapshot(caller);
            if (!vms_) throw ServiceError(ErrorCode::unavailable, "VM runtime unavailable");
            for (const auto& key : request.getMemberNames())
                if (key != "type" && key != "command" && key != "request_id" && key != "revision" && key != "vm_id" && key != "overrides" && key != "boot_entry" && key != "clear_logs_before_start")
                    throw ServiceError(ErrorCode::invalid_argument, "Unexpected configured start field");
            const auto revision = string_field(request, "revision");
            const auto id = string_field(request, "vm_id");
            if (revision.empty() || id.empty()) throw ServiceError(ErrorCode::invalid_argument, "Missing revision or VM ID");
            if (snapshot->revision != revision) throw ServiceError(ErrorCode::conflict, "VM configuration changed; reload before starting");
            if (snapshot->durability_uncertain) throw ServiceError(ErrorCode::commit_uncertain, "VM configuration durability is uncertain");
            // A boot key is an image-provided ID/title, not a UUID/revision.
            if (request.isMember("boot_entry") && (!request["boot_entry"].isString() || request["boot_entry"].asString().size() > (64u << 10)))
                throw ServiceError(ErrorCode::invalid_argument, "Invalid boot entry");
            const auto boot = request.isMember("boot_entry") ? request["boot_entry"].asString() : std::string();
            if (request.isMember("clear_logs_before_start") && !request["clear_logs_before_start"].isBool())
                throw ServiceError(ErrorCode::invalid_argument, "Invalid clear logs option");
            const bool clear_logs = request.get("clear_logs_before_start", false).asBool();
            for (const auto& row : snapshot->document["vms"]) if (row["id"] == id) {
                if (request["overrides"].isObject() && request["overrides"].isMember("pseudo_unprotected")) {
                    vm::HostFacts facts;
                    facts.has_kvm = access("/dev/kvm", F_OK) == 0;
                    facts.has_gunyah = access("/dev/gunyah", F_OK) == 0;
                    if (config::java_enum(row, "backend", "CROSVM", {"CROSVM", "QEMU"}) != "CROSVM" || !vm::resolves_to_gunyah(row, facts))
                        throw ServiceError(ErrorCode::invalid_argument, "Protection override requires crosvm with Gunyah");
                }
                if (!vms_->start_configured(caller, id, row, request["overrides"], boot.empty() ? std::nullopt : std::optional(boot), clear_logs))
                    throw ServiceError(ErrorCode::conflict, "VM start was not admitted; reload state before retrying");
                Json::Value result;
                result["success"] = true; result["vm_id"] = id; result["revision"] = revision;
                return result;
            }
            throw ServiceError(ErrorCode::not_found, "VM not found");
        } catch (const ServiceError& error) { return failure(error); }
        catch (...) { return failure(ServiceError(ErrorCode::internal, "VM start outcome is unknown; reload state before retrying")); }
    }
    const bool network_upload = networks_ && network_upload_command(command);
    if (vm_uploads_ && (network_upload || (vm_config_ && vm_upload_command(command)))) {
        try {
            if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
            if (!caller.administrator || caller.principal.empty()) throw ServiceError(ErrorCode::permission_denied, "Administrator permission required");
            if (!request.isObject()) throw ServiceError(ErrorCode::invalid_argument, "Upload request must be an object");
            Json::Value result; result["success"] = true;
            if (command == "vm_config_upload_begin" || command == "network_config_import_begin") {
                result["upload_id"] = network_upload ? vm_uploads_->begin_network(caller, size_field(request, "bytes", 0))
                    : vm_uploads_->begin(caller, string_field(request, "revision"), size_field(request, "bytes", 0));
                result["chunk_bytes"] = Json::UInt64(VmConfigUploads::chunk_bytes);
                result["expires_in_seconds"] = 120;
            } else {
                const auto id = string_field(request, "upload_id");
                if (command == "vm_config_upload_commit") return config_status(vm_uploads_->commit(caller, id));
                if (command == "network_config_import_commit") {
                    result["network_ids"] = vm_uploads_->commit_network(caller, id);
                    return result;
                }
                if (command == "vm_config_upload_abort") vm_uploads_->abort(caller, id);
                else if (command == "network_config_import_abort") vm_uploads_->abort_network(caller, id);
                else {
                    if (!request["data"].isString() || !request.isMember("offset"))
                        throw ServiceError(ErrorCode::invalid_argument, "Missing upload chunk data or offset");
                    std::string bytes;
                    try { bytes = wire::decode_base64(request["data"].asString(), VmConfigUploads::chunk_bytes); }
                    catch (const std::exception&) { throw ServiceError(ErrorCode::invalid_argument, "Invalid base64 upload chunk"); }
                    result["received"] = Json::UInt64(network_upload
                        ? vm_uploads_->append_network(caller, id, size_field(request, "offset", 0), bytes)
                        : vm_uploads_->append(caller, id, size_field(request, "offset", 0), bytes));
                }
            }
            return result;
        } catch (const ServiceError& error) { return failure(error); }
        catch (...) { return failure(ServiceError(ErrorCode::internal, "Configuration upload outcome unknown; reload before retrying")); }
    }
    if (vm_config_ && command == "vm_config_apply") {
        try {
            if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
            if (!caller.administrator || caller.principal.empty()) throw ServiceError(ErrorCode::permission_denied, "Administrator permission required");
            return config_status(vm_config_->apply(caller, string_field(request, "revision"), request["operations"]));
        }
        catch (const ServiceError& error) { return failure(error); }
    }
    Json::Value result;
    result["success"] = false;
    if (!caller.authenticated) {
        if (command == "network_config_get" || command == "network_config_update")
            return failure(ServiceError(ErrorCode::unauthenticated, "Authentication required"));
        result["message"] = "client is not authorized to perform this action"; return result;
    }
    if (vms_ && vm_command(command)) return execute_vm(caller, command, request);
    if (packages_ && package_command(command)) {
        // ExportHandler/ImportHandler: RequestException texts, else "internal error".
        try {
            const auto response = command == "vm_export" ? packages_->vm_export(caller, request) : packages_->vm_import(caller, request);
            for (const auto& key : response.getMemberNames()) result[key] = response[key];
            result["success"] = true;
        } catch (const pkg::RequestError& error) { result["message"] = error.what(); }
        catch (...) { result["message"] = "internal error"; }
        return result;
    }
    if (keyboard_ && keyboard_command(command)) return execute_keyboard(caller, command, request);
    if (usb_ && usb_command(command)) {
        // RequestException texts reach the client; anything else is "internal error".
        try {
            Json::Value response = command == "usb_attach" ? usb_->usb_attach(request) : command == "usb_detach" ? usb_->usb_detach(request) :
                command == "usb_host_list" ? usb_->usb_host_list(request) : command == "usb_rules_get" ? usb_->usb_rules_get(request) :
                command == "usb_rules_set" ? usb_->usb_rules_set(request) : command == "usb_rules_test" ? usb_->usb_rules_test(request) :
                command == "usb_set_target" ? usb_->usb_set_target(request) : usb_->usb_vm_list(request);
            for (const auto& key : response.getMemberNames()) result[key] = response[key];
            result["success"] = true;
        } catch (const usb::RequestError& error) { result["message"] = error.what(); }
        catch (...) { result["message"] = "internal error"; }
        return result;
    }
    if (display_attach_ && command == "display_attach") {
        const auto nonce = legacy_id(request, "nonce");
        if (nonce.empty()) { result["message"] = "missing nonce"; return result; }
        // Broadcast failures are logged only, as NativeDisplayBinder.attach.
        try { display_attach_(nonce); } catch (...) { result["message"] = "internal error"; return result; }
        result["success"] = true; return result;
    }
    try {
        if (host_command(command) && host_network_) {
            result["data"] = command == "network_list_uplinks" ? host_network_->uplinks(caller) :
                command == "network_list_host_addresses" ? host_network_->addresses(caller) : host_network_->available_interfaces(caller);
            result["success"] = true;
            return result;
        }
        if (!networks_) { result["message"] = "internal error"; return result; }
        if ((command == "network_config_get" || command == "network_config_update") && !request.isObject())
            throw ServiceError(ErrorCode::invalid_argument, "Network configuration request must be an object");
        if (runtime_ && runtime_command(command)) {
            const auto id = legacy_id(request);
            if (id.empty()) { result["message"] = "missing network_id"; return result; }
            if (command == "network_delete") {
                if (configuration_) throw ServiceError(ErrorCode::conflict, "Network deletion requires a coordinated confirmation");
                // DeleteHandler: running users first, then NICs leave every VM, then the lookup.
                if (vms_) {
                    const auto busy = vms_->busy_vms_using(id);
                    if (!busy.empty()) {
                        std::string names;
                        for (const auto& name : busy) names += (names.empty() ? "" : ", ") + name;
                        result["message"] = "network is in use by running VM: " + names; return result;
                    }
                    vms_->drop_network(id);
                }
                if (!networks_->exists(caller, id)) { result["message"] = "network " + id + " not found"; return result; }
                if (runtime_->get(caller, id).state != NetworkState::stopped) {
                    try { if (runtime_->stop(caller, id).state != NetworkState::stopped) throw ServiceError(ErrorCode::unavailable, "stop incomplete"); }
                    catch (const ServiceError&) { result["message"] = "Failed to stop network: " + id; return result; }
                }
                networks_->remove(caller, id);
                result["success"] = true; return result;
            }
            if (command.ends_with("_address") || command.ends_with("_interface")) {
                const bool address = command.ends_with("_address"), add = command.starts_with("network_add_");
                auto value = legacy_id(request, address ? "address" : "interface");
                if (value.empty()) { result["message"] = address ? "missing address" : "missing interface"; return result; }
                if (address) {
                    // IPNetwork.parse: IPv4 first, then IPv6; the stored form is address/prefix.
                    std::optional<config::NetworkPrefix> prefix;
                    for (const bool v6 : {false, true}) if (!prefix) try { prefix = config::NetworkPrefix::parse(value, v6); } catch (const std::exception&) {}
                    if (!prefix) { result["message"] = "invalid address: Invalid IP network: " + value; return result; }
                    value = prefix->address() + "/" + std::to_string(prefix->prefix());
                }
                if (!networks_->exists(caller, id)) { result["message"] = "network " + id + " not found"; return result; }
                if (!runtime_->manual(caller, id, address, value, add)) {
                    result["message"] = std::string("failed to ") + (add ? "add " : "remove ") + (address ? "address" : "interface"); return result;
                }
                result["success"] = true; return result;
            }
            if (command == "network_pd_renew" || command == "network_pd_release") {
                const auto vlan = legacy_int(request, "vlan_id", -1);
                if (vlan < 0) { result["message"] = "missing vlan_id"; return result; }
                if (!networks_->exists(caller, id)) { result["message"] = "network " + id + " not found"; return result; }
                const bool release = command == "network_pd_release";
                if (!runtime_->pd_action(caller, id, vlan, release)) {
                    result["message"] = release ? "failed to release PD delegation" : "failed to renew PD delegation"; return result;
                }
                result["success"] = true; return result;
            }
            if (!networks_->exists(caller, id)) { result["message"] = "network " + id + " not found"; return result; }
            if (command == "network_tool_log") {
                if (!request["tool"].isString() || request["tool"].asString().empty()) { result["message"] = "missing tool"; return result; }
                result["lines"] = runtime_->tool_log(caller, id, string_field(request, "tool"));
            } else {
                const auto view = command == "network_start" ? runtime_->start(caller, id) :
                    command == "network_stop" ? runtime_->stop(caller, id) : runtime_->get(caller, id);
                result["network_id"] = id;
                runtime_fields(result, view, true);
            }
            result["success"] = true; return result;
        }
        if (command == "network_config_get") {
            if (!request["network_id"].isString()) throw ServiceError(ErrorCode::invalid_argument, "network_id is required");
            result["config"] = networks_->get(caller, request["network_id"].asString());
        } else if (command == "network_config_update") {
            result["network_id"] = networks_->update_if_matches(caller, request["expected"], request["config"]);
        } else if (command == "network_create" || command == "network_modify") {
            if (!request.isMember("config")) { result["message"] = "missing config"; return result; }
            result["network_id"] = command == "network_create" ? networks_->create(caller, request["config"]) : networks_->update(caller, request["config"]);
        } else if (command == "network_list") {
            auto rows = networks_->list(caller);
            for (auto& row : rows) {
                if (runtime_) runtime_fields(row, runtime_->get(caller, row["id"].asString()), true);
                else row["state"] = "stopped";
            }
            result["data"] = std::move(rows);
        } else {
            auto id = legacy_id(request);
            if (id.empty()) { result["message"] = "missing network_id"; return result; }
            if (command == "network_exists") {
                result["network_id"] = id;
                result["exists"] = networks_->exists(caller, id);
            } else {
                auto row = networks_->get(caller, id);
                row["state"] = "STOPPED";
                row["tools"] = Json::Value(Json::arrayValue);
                if (runtime_) {
                    runtime_fields(row, runtime_->get(caller, id), false);
                    // BridgeBackend.appendForwardFailures: only when there are any.
                    auto failures = runtime_->forward_failures(caller, id);
                    if (!failures.empty()) row["forward_failures"] = std::move(failures);
                    auto live = runtime_->live(caller, id);
                    for (const auto& key : live.getMemberNames()) row[key] = live[key];
                    if (vms_ && row["live_interfaces"].isArray())
                        for (auto& item : row["live_interfaces"]) {
                            const auto owner = vms_->vm_by_tap(config::string(item, "name"));
                            if (owner.isObject()) { item["vm_id"] = owner["vm_id"]; item["vm_name"] = owner["vm_name"]; }
                        }
                }
                result["data"] = std::move(row);
            }
        }
        result["success"] = true;
        return result;
    } catch (const ServiceError& error) {
        if (runtime_command(command)) return failure(error);
        if (command == "network_config_get" || command == "network_config_update") return failure(error);
        if (runtime_ && command == "network_modify" && error.code() == ErrorCode::conflict) return failure(error);
        if (host_command(command)) return failure(error);
        if (error.code() == ErrorCode::commit_uncertain || error.code() == ErrorCode::io_error || error.code() == ErrorCode::resource_exhausted)
            return failure(error);
        if (command == "network_create" && error.code() == ErrorCode::conflict) result["message"] = "failed to create network";
        else if (command == "network_modify" && error.code() == ErrorCode::not_found) result["message"] = "failed to modify network";
        else if (command == "network_info" && error.code() == ErrorCode::not_found) result["message"] = "network not found";
        else result["message"] = "internal error";
        return result;
    } catch (...) {
        if (command == "network_config_get" || command == "network_config_update")
            return failure(ServiceError(ErrorCode::internal, "Network configuration result unknown; reload before retrying"));
        result["message"] = "internal error"; return result;
    }
}
Json::Value RequestDispatcher::execute_vm(const CallContext& caller, const std::string& command, const Json::Value& request) {
    Json::Value result;
    result["success"] = false;
    try {
        if (command == "vm_create" || command == "vm_modify") {
            if (!request.isMember("config")) { result["message"] = "missing config"; return result; }
            result["vm_id"] = command == "vm_create" ? vms_->create(caller, request["config"]) : vms_->modify(caller, request["config"]);
        } else if (command == "set_app_config") {
            // A missing or non-object config is a plain exception: "internal error".
            vms_->set_app_config(caller, request.isMember("config") ? request["config"] : Json::Value());
        } else if (command == "vm_bootscan") {
            const auto image = legacy_id(request, "image");
            if (image.empty()) { result["message"] = "missing image"; return result; }
            result["entries"] = vms_->boot_scan(caller, image);
        } else if (command == "vm_list") {
            result["data"] = vms_->list(caller);
        } else if (command == "vm_stop_all") {
            vms_->stop_all();
        } else if (command.starts_with("vm_console_") || command == "vm_vnc_info") {
            const auto id = legacy_id(request, "vm_id");
            const auto stream = legacy_id(request, "stream");
            if (id.empty()) { result["message"] = "missing vm_id"; return result; }
            if (stream.empty() && (command == "vm_console_info" || command == "vm_console_write" || command == "vm_console_clear")) {
                result["message"] = "missing stream"; return result;
            }
            std::shared_ptr<vm::VmRuntime> target;
            try { target = vms_->runtime(caller, id); }
            catch (const ServiceError& error) {
                if (error.code() != ErrorCode::not_found) throw;
                result["message"] = "VM not found"; return result;
            }
            if (command == "vm_console_list") {
                result["data"] = Json::Value(Json::arrayValue);
                for (const auto& name : target->streams()) result["data"].append(name);
            } else if (command == "vm_vnc_info") {
                const auto config = target->config();
                const auto screen = legacy_id(request, "screen");
                std::string found;
                for (const char* candidate : {"gpu-0", "simplefb"}) {
                    const auto& row = config::member(config::member(config, "screens"), candidate);
                    if (!row.isObject() || !config::boolean(row, "enabled") ||
                        config::java_enum(row, "exporter", "NONE", {"NATIVE", "VNC", "NONE"}) != "VNC") continue;
                    if (screen.empty() || screen == candidate) { found = candidate; break; }
                }
                if (found.empty()) { result["message"] = "VNC is not enabled for this VM"; return result; }
                const auto& vnc = config::member(config["screens"][found], "vnc");
                const auto host = config::string(vnc, "host");
                result["screen"] = found;
                result["host"] = host.empty() ? "127.0.0.1" : host;
                result["port"] = Json::Int64(config::integer(vnc, "port", -1));
                result["password"] = config::string(vnc, "password");
                result["transport_cap"] = vm::screen_transport_cap(config, found);
                // The wildcard bind is reached at the phone's own filtered address.
                if (host == "0.0.0.0" && host_ipv4_) {
                    const auto addresses = host_ipv4_->current();
                    if (!addresses.empty()) result["remote_host"] = addresses.front();
                }
            } else if (command == "vm_console_history") {
                result["vm_id"] = id;
                if (!stream.empty()) {
                    auto* log = target->log(stream);
                    if (!log) { result["message"] = "stream not found"; return result; }
                    result[stream] = vm::url_encode_bytes(log->contents());
                } else {
                    for (const auto& name : target->streams()) if (auto* log = target->log(name)) result[name] = vm::url_encode_bytes(log->contents());
                }
            } else {
                auto* log = target->log(stream);
                if (!log) { result["message"] = "stream not found"; return result; }
                if (command == "vm_console_clear") log->clear();
                else if (command == "vm_console_write") {
                    if (!target->write(stream, legacy_id(request, "data"))) { result["message"] = "failed to write to stream"; return result; }
                } else {
                    const auto info = target->stream_info(stream);
                    auto& data = result["data"];
                    data["type"] = info->type; data["name"] = stream; data["path"] = log->path();
                    data["length"] = Json::UInt64(log->size()); data["readable"] = info->readable; data["writable"] = info->writable;
                    if (info->fd_pipe) { data["read_fd"] = info->read_fd; data["write_fd"] = info->write_fd; data["ready"] = info->read_fd >= 0 || info->write_fd >= 0; }
                    if (info->type == "LocalSocketConsoleStream") data["ready"] = info->ready;
                }
            }
        } else if (command == "vm_input") {
            const auto id = legacy_id(request, "vm_id");
            if (id.empty()) { result["message"] = "missing vm_id"; return result; }
            const auto screen = legacy_id(request, "screen");
            const auto channel = legacy_int(request, "channel", -1);
            const auto data = base64_decode(legacy_id(request, "data"));
            result["delivered"] = vms_->runtime(caller, id)->write_input(screen, channel, data);
        } else if (command == "vm_start" || command == "vm_stop" || command == "vm_reboot" || command == "vm_suspend" ||
                   command == "vm_resume" || command == "vm_control") {
            const auto id = legacy_id(request, "vm_id");
            if (id.empty()) { result["message"] = "missing vm_id"; return result; }
            auto target = vms_->runtime(caller, id);
            bool done = false;
            if (command == "vm_start") {
                if (legacy_flag(request, "clear_logs_before_start") && target->state() == VmState::stopped) target->clear_logs();
                const auto entry = legacy_id(request, "boot_entry");
                done = target->start(entry.empty() ? std::nullopt : std::optional(entry));
                if (!done) { result["message"] = "failed to start VM"; return result; }
            } else if (command == "vm_control") {
                const auto cmd = legacy_id(request, "cmd");
                if (cmd.empty()) { result["message"] = "missing cmd"; return result; }
                if (!target->control(cmd)) { result["message"] = "failed to send command"; return result; }
            } else {
                done = command == "vm_stop" ? target->stop() : command == "vm_reboot" ? target->reboot() :
                    command == "vm_suspend" ? target->suspend() : target->resume();
                if (!done) { result["message"] = "failed to " + command.substr(3) + " VM"; return result; }
            }
        } else {
            const auto id = legacy_id(request, "vm_id");
            if (id.empty()) { result["message"] = "missing vm_id"; return result; }
            if (command == "vm_get") result["data"] = vms_->get(caller, id);
            else if (command == "vm_exists") { result["vm_id"] = id; result["exists"] = vms_->exists(caller, id); }
            else if (command == "vm_delete") result["existed"] = vms_->remove(caller, id);
            else {
                std::string state = vm_state_name(vms_->state(caller, id));
                for (auto& c : state) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                result["vm_id"] = id; result["state"] = state;
            }
        }
        result["success"] = true;
        return result;
    } catch (const ServiceError& error) {
        // Only RequestException texts reach a legacy client.
        if (error.code() == ErrorCode::not_found && (command == "vm_get" || command == "vm_status" || command == "vm_start" || command == "vm_stop" ||
            command == "vm_reboot" || command == "vm_suspend" || command == "vm_resume" || command == "vm_control" || command == "vm_input")) result["message"] = error.what();
        else if (error.code() == ErrorCode::conflict && command == "vm_create") result["message"] = "failed to create VM";
        else if ((error.code() == ErrorCode::not_found || error.code() == ErrorCode::conflict) && command == "vm_modify") result["message"] = "failed to modify VM";
        else if (error.code() == ErrorCode::unavailable && command == "vm_delete") result["message"] = error.what();
        else result["message"] = "internal error";
        return result;
    } catch (...) { result["message"] = "internal error"; return result; }
}
Json::Value RequestDispatcher::execute_keyboard(const CallContext& caller, const std::string& command, const Json::Value& request) {
    Json::Value result;
    result["success"] = false;
    try {
        if (command == "kbd_config") {
            // Through from_json, so one place decides what a usable chord is.
            const auto current = keyboard_->config();
            Json::Value config;
            config["enabled"] = legacy_flag(request, "enabled", current.enabled);
            config["escape_chord"] = request.isMember("escape_chord") && request["escape_chord"].isArray() ? request["escape_chord"] : current.json()["escape_chord"];
            keyboard_->set_config(input::KeyboardGrabConfig::from_json(config));
        } else if (command == "kbd_grab") {
            const auto vm = legacy_id(request, "vm_id");
            const auto screen = legacy_id(request, "screen");
            if (!legacy_flag(request, "grab", true)) {
                if (vm.empty()) keyboard_->release("asked over IPC");
                else keyboard_->release_for(vm, screen);
            } else {
                if (vm.empty()) { result["message"] = "missing vm_id"; return result; }
                if (!vms_ || !vms_->exists(caller, vm)) { result["message"] = "VM not found: " + vm; return result; }
                keyboard_->request(vm, screen);
            }
        }
        auto status = keyboard_->status();
        for (const auto& key : status.getMemberNames()) result[key] = status[key];
        result["success"] = true;
        return result;
    } catch (...) { result["message"] = "internal error"; return result; }
}
Json::Value RequestDispatcher::execute(ClientSession& session, const std::string& command, const Json::Value& request) {
    if (std::find(commands.begin(), commands.end(), command) == commands.end() && !(vm_config_ && vm_config_command(command))
        && !(configuration_ && configuration_command(command))) {
        auto result = system_.execute(session.caller, command, request);
        if (command == "capabilities" && result["success"].asBool()) {
            result["service_api_minor"] = 1;
            for (const auto* name : commands) {
                if (std::string_view(name) == "network_config_document" && (!networks_ || !networks_->has_events())) continue;
                result["commands"].append(name);
            }
            result["task_events"] = "explicit-subscription-v1";
            if (networks_) {
                for (const auto* name : network_commands) result["commands"].append(name);
                result["network_config_persistence"] = true;
                result["network_runtime"] = false;
                result["service_api_minor"] = 2;
            }
            if (host_network_) {
                for (const auto* name : host_commands) result["commands"].append(name);
                result["network_host_interfaces"] = true;
                result["network_uplinks"] = true;
                result["network_host_addresses"] = true;
                result["service_api_minor"] = 3;
            }
            if (runtime_) {
                for (const auto* name : runtime_commands) result["commands"].append(name);
                result["network_lifecycle_backends"] = Json::Value(Json::arrayValue);
                result["network_lifecycle_backends"].append("gvisor");
                result["network_lifecycle_backends"].append("linux-l3"); // no L2 uplink, PD or VM ports yet
                result["network_watchdog"] = true;
                result["network_auto_up"] = true;
                result["network_live_details"] = true;
                result["network_delete"] = true;
                result["service_api_minor"] = 4;
            }
            if (host_network_) result["service_api_minor"] = 5;
            if (vms_) {
                for (const auto* name : vm_commands) result["commands"].append(name);
                result["vm_inventory"] = true;
                result["vm_runtime"] = true;
                result["vm_runtime_backends"] = Json::Value(Json::arrayValue);
                result["vm_runtime_backends"].append("crosvm");
                result["vm_runtime_backends"].append("qemu");
                result["vm_auto_up"] = true;
                result["service_api_minor"] = 8;
            }
            if (keyboard_) {
                for (const auto* name : keyboard_commands) result["commands"].append(name);
                result["keyboard_grab"] = true;
                result["service_api_minor"] = 9;
            }
            if (usb_) {
                for (const auto* name : usb_commands) result["commands"].append(name);
                result["usb_passthrough"] = true;
            }
            if (packages_) {
                result["commands"].append("vm_export");
                result["commands"].append("vm_import");
                result["vm_packages"] = true;
            }
            if (display_attach_) {
                result["commands"].append("display_attach");
                result["native_display_binder"] = true;
                result["service_api_minor"] = 10;
            }
            if (packages_) {
                result["package_tasks"] = true;
                result["service_api_minor"] = 11;
            }
            if (networks_ && networks_->has_events()) {
                result["network_config_events"] = "invalidation-v1";
                result["service_api_minor"] = 12;
            }
            if (vm_config_) {
                result["commands"].append("vm_config_status");
                result["commands"].append("vm_config_apply");
                result["vm_config_updates"] = "revisioned-batch-v1";
                result["service_api_minor"] = 13;
                if (vm_config_->has_events()) {
                    result["commands"].append("vm_config_snapshot");
                    result["vm_config_events"] = "invalidation-v1";
                    result["vm_config_snapshot"] = "base64-json-chunks-v1";
                    result["service_api_minor"] = 14;
                }
                for (const auto* name : vm_upload_commands) result["commands"].append(name);
                result["vm_config_upload"] = "revisioned-chunks-v1";
                result["service_api_minor"] = 15;
                if (vms_) {
                    result["commands"].append("vm_start_configured");
                    result["vm_config_start"] = "revisioned-session-v1";
                    result["service_api_minor"] = 16;
                }
            }
            if (networks_) {
                result["network_config_update"] = "compare-config-v1";
                result["network_config_import"] = "conditional-chunks-v1";
                for (const auto* name : network_upload_commands) result["commands"].append(name);
                result["service_api_minor"] = 18;
                if (networks_->has_events()) {
                    result["network_config_document"] = "base64-json-chunks-v1";
                    result["service_api_minor"] = 19;
                }
            }
            if (configuration_) {
                result["network_config_delete"] = runtime_ ? "revisioned-stop-chunks-v1" : "revisioned-stopped-chunks-v1";
                result["configuration_recover"] = "redo-v1";
                for (const auto* name : delete_upload_commands) result["commands"].append(name);
                result["commands"].append("configuration_recover");
                result["service_api_minor"] = runtime_ ? 21 : 20;
            }
        }
        return result;
    }
    try {
        const auto caller = context(session);
        if (!caller.authenticated) throw ServiceError(ErrorCode::unauthenticated, "Authentication required");
        Json::Value result;
        result["success"] = true;
        if (configuration_ && configuration_command(command)) {
            return execute_background(caller, command, request);
        } else if (command == "vm_config_status") {
            return config_status(vm_config_->snapshot(caller));
        } else if (command == "vm_config_snapshot") {
            if (!vm_config_->has_events()) throw ServiceError(ErrorCode::unavailable, "VM configuration view unavailable");
            return snapshot_json(tasks_.vm_config_snapshot(caller, size_field(request, "max_bytes", 256u << 10)));
        } else if (command == "vm_config_apply" || command == "vm_start_configured" || vm_upload_command(command)) {
            // Server dispatches this to the bounded worker pool. Also support
            // direct adapter callers without a second implementation.
            return execute_background(caller, command, request);
        } else if (command == "task_get" || command == "task_cancel") {
            TaskRef ref{string_field(request, "epoch"), string_field(request, "task_id")};
            const auto task = command == "task_get" ? tasks_.get(caller, ref) : tasks_.cancel(caller, ref);
            result["task"] = task_summary(task);
            if (task.state == TaskState::succeeded) result["task"]["result"] = task.result;
        } else if (command == "task_snapshot") {
            return snapshot_json(tasks_.snapshot(caller, size_field(request, "max_bytes", 256u << 10)));
        } else if (command == "network_config_document") {
            if (!networks_ || !networks_->has_events()) throw ServiceError(ErrorCode::unavailable, "Network configuration view unavailable");
            return snapshot_json(tasks_.network_config_document(caller, size_field(request, "max_bytes", 256u << 10)));
        } else if (command == "network_config_snapshot") {
            return snapshot_json(tasks_.network_config_snapshot(caller, size_field(request, "max_bytes", 256u << 10)));
        } else if (command == "task_snapshot_page" || command == "resource_snapshot_page") {
            return snapshot_json(tasks_.snapshot_page(caller, string_field(request, "snapshot_id"),
                size_field(request, "offset", 0), size_field(request, "max_bytes", 256u << 10)));
        } else if (command == "task_snapshot_release" || command == "resource_snapshot_release") {
            tasks_.release_snapshot(caller, string_field(request, "snapshot_id"));
        } else if (command == "task_subscribe" || command == "resource_subscribe") {
            if (!session.subscription.empty()) throw ServiceError(ErrorCode::invalid_argument, "Unsubscribe before changing streams");
            auto cursor = EventCursor::parse(string_field(request, "epoch"), string_field(request, "cursor"));
            auto id = tasks_.subscribe(caller, cursor);
            session.subscription = std::move(id);
            session.cursor = cursor.sequence;
            session.resource_events = command == "resource_subscribe";
            result["epoch"] = cursor.epoch;
            result["cursor"] = std::to_string(cursor.sequence);
        } else if (command == "task_unsubscribe" || command == "resource_unsubscribe") disconnected(session);
        return result;
    } catch (const ServiceError& error) { return failure(error); }
}
std::optional<Json::Value> RequestDispatcher::events(ClientSession& session) {
    if (session.subscription.empty()) return {};
    try {
        auto batch = tasks_.poll(context(session), session.subscription);
        if (batch.covered.sequence == session.cursor) return {};
        Json::Value result;
        result["type"] = "event";
        result["event"] = session.resource_events ? "resource_events" : "task_events";
        result["epoch"] = batch.covered.epoch;
        result["cursor"] = std::to_string(batch.covered.sequence);
        auto& items = result["events"] = Json::Value(Json::arrayValue);
        for (const auto& item : batch.events) {
            auto event = wire::parse(item.encoded);
            if (session.resource_events || event["kind"].asString().starts_with("task.")) items.append(std::move(event));
        }
        session.cursor = batch.covered.sequence;
        return result;
    } catch (const ServiceError& error) {
        const bool resources = session.resource_events;
        disconnected(session);
        auto result = failure(error);
        result["type"] = "event";
        result["event"] = resources ? "resource_stream_error" : "task_stream_error";
        return result;
    }
}
void RequestDispatcher::disconnected(ClientSession& session) noexcept {
    if (session.subscription.empty()) return;
    try { tasks_.unsubscribe(context(session), session.subscription); } catch (...) {}
    session.subscription.clear();
}
}
