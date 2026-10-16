// SPDX-License-Identifier: GPL-3.0-or-later
// Port of lib/store/vm/{VMConfig,VMScreenConfig,VMSerialConfig,VMXhciConfig}
// load-time migration. DataItem accessors are type-strict; opt(key) != null
// means the key is present, even with a JSON null value.
#include "vm_config.h"
#include "network_config.h"
#include "build_metadata.h"
#include <unicode/ustring.h>
#include <array>
#include <bit>
#include <map>
#include <set>
#include <stdexcept>

namespace droidvm::config {
namespace {
const std::string edk2_firmware = "/data/data/" DROIDVM_PACKAGE_NAME "/usr/share/droidvm/edk2-gunyah.fd";
bool present(const Json::Value& object, const char* key) { return object.isObject() && object.isMember(key); }
void erase(Json::Value& object, const char* key) { if (object.isObject()) object.removeMember(key); }
Json::Value& child(Json::Value& parent, const char* key) {
    if (!parent[key].isObject()) parent[key] = Json::Value(Json::objectValue);
    return parent[key];
}
Json::Value& array_child(Json::Value& parent, const char* key) {
    if (!parent[key].isArray()) parent[key] = Json::Value(Json::arrayValue);
    return parent[key];
}
int narrow(int64_t value) { return std::bit_cast<int32_t>(static_cast<uint32_t>(value)); }
std::string upper(const std::string& text) {
    UErrorCode status = U_ZERO_ERROR;
    int32_t length = 0;
    u_strFromUTF8(nullptr, 0, &length, text.data(), static_cast<int32_t>(text.size()), &status);
    if (status != U_BUFFER_OVERFLOW_ERROR && U_FAILURE(status)) return text;
    std::u16string wide(static_cast<size_t>(length), u'\0');
    status = U_ZERO_ERROR;
    u_strFromUTF8(wide.data(), length, nullptr, text.data(), static_cast<int32_t>(text.size()), &status);
    if (U_FAILURE(status)) return text;
    status = U_ZERO_ERROR;
    const auto needed = u_strToUpper(nullptr, 0, wide.data(), length, "", &status);
    std::u16string upper(static_cast<size_t>(needed), u'\0');
    status = U_ZERO_ERROR;
    u_strToUpper(upper.data(), needed, wide.data(), length, "", &status);
    if (U_FAILURE(status)) return text;
    std::string result(static_cast<size_t>(needed) * 3, '\0');
    int32_t written = 0;
    status = U_ZERO_ERROR;
    u_strToUTF8(result.data(), static_cast<int32_t>(result.size()), &written, upper.data(), needed, &status);
    if (U_FAILURE(status)) return text;
    result.resize(static_cast<size_t>(written));
    return result;
}
const std::vector<const char*> display_backends{"NONE", "SIMPLEFB", "VIRTIO_GPU"};
const std::vector<const char*> serial_hardware{"SERIAL", "SBSA", "VIRTIO_CONSOLE"};
const std::vector<const char*> serial_backends{"SINK", "APP_CONSOLE", "FILE", "UNIX", "UNIX_STREAM", "PTY", "STDOUT", "SYSLOG", "USB_ACM"};
const std::vector<const char*> peripheral_types{"VIRTIO_SOUND", "INTEL_HDA", "VIRTIO_CAMERA", "XHCI_USB"};
constexpr const char* gpu0 = "gpu-0";
constexpr const char* simplefb = "simplefb";

void migrate_boot(Json::Value& item) {
    if (present(item, "boot")) return;
    const bool legacy = present(item, "use_uefi") || !string(item, "kernel").empty() || !string(item, "initrd").empty() ||
        !string(item, "cmdline").empty() || !string(item, "bios").empty();
    if (!legacy) return;
    auto& boot = child(item, "boot");
    auto uefi = boolean(item, "use_uefi", true);
    // Legacy QEMU: use_uefi=false + bios + no kernel booted custom firmware.
    if (!uefi && string(item, "kernel").empty() && !string(item, "bios").empty()) uefi = true;
    boot["protocol"] = uefi ? "uefi" : "linux";
    child(boot, "uefi")["firmware"] = string(item, "bios");
    child(boot, "linux")["kernel"] = string(item, "kernel");
    child(boot, "linux")["initrd"] = string(item, "initrd");
    child(boot, "linux")["cmdline"] = string(item, "cmdline");
}
void migrate_nic_forwards(Json::Value& item) {
    const auto& forwards = member(item, "port_forwards");
    const auto& nics = member(item, "networks");
    if (!present(item, "port_forwards") || !forwards.isArray() || forwards.empty() || !present(item, "networks") || !nics.isArray()) {
        erase(item, "port_forwards");
        return;
    }
    // Forwards were keyed by network only; they land on its first NIC.
    std::map<std::string, Json::ArrayIndex> nic_by_network;
    for (Json::ArrayIndex i = 0; i < nics.size(); ++i) {
        if (!nics[i].isObject()) continue;
        const auto id = string(nics[i], "network_id");
        if (!id.empty()) nic_by_network.emplace(id, i);
    }
    const auto rows = forwards;
    for (const auto& forward : rows) {
        if (!forward.isObject() || !boolean(forward, "enabled", true)) continue;
        const auto at = nic_by_network.find(string(forward, "network_id"));
        if (at == nic_by_network.end()) continue;
        auto& lease = child(item["networks"][at->second], "dhcp4_lease");
        lease["enabled"] = true; // offset is allocated at start
        auto proto = string(forward, "protocol", "tcp");
        if (proto.empty()) proto = "tcp";
        Json::Value row;
        row["proto"] = proto;
        row["host"] = std::to_string(integer(forward, "host_port", 0));
        row["guest"] = std::to_string(integer(forward, "guest_port", 0));
        array_child(lease, "forwards").append(std::move(row));
    }
    erase(item, "port_forwards");
}
Json::Value& screen(Json::Value& item, const char* id) { return child(child(item, "screens"), id); }
const Json::Value* find_screen(const Json::Value& item, const char* id) {
    const auto& screens = member(item, "screens");
    if (!screens.isObject() || !screens[id].isObject()) return nullptr;
    return &screens[id];
}
void migrate_screens(Json::Value& item) {
    const bool pre_screens = !present(item, "screens");
    if (pre_screens) {
        const auto display = boolean(item, "display_enabled", false);
        const auto backend = java_enum(item, "display_backend", "NONE", display_backends);
        const auto want_native = boolean(item, "native_display_enabled", false), want_vnc = boolean(item, "vnc_enabled", false);
        const auto gpu_enabled = boolean(item, "gpu_enabled", false);
        const char* bound = nullptr;
        if (display && backend == "VIRTIO_GPU") bound = gpu0;
        else if (display && backend == "SIMPLEFB") bound = simplefb;
        if (!bound && want_vnc && !want_native && gpu_enabled) bound = gpu0;
        screen(item, gpu0)["enabled"] = bound == gpu0;
        screen(item, simplefb)["enabled"] = bound == simplefb;
        screen(item, gpu0)["exporter"] = "none";
        screen(item, simplefb)["exporter"] = "none";
        const char* exporter = want_native ? "native" : want_vnc ? "vnc" : "none";
        if (bound && std::string(exporter) != "none") screen(item, bound)["exporter"] = exporter;
        const char* home = bound ? bound : gpu_enabled ? gpu0 : simplefb;
        const auto host = string(item, "vnc_host"), password = string(item, "vnc_password");
        const auto port = integer(item, "vnc_port", -1);
        const auto auth = boolean(item, "vnc_password_auth", false);
        auto& vnc = child(screen(item, home), "vnc");
        vnc["host"] = host; vnc["port"] = Json::Int64(port);
        vnc["password_auth"] = auth; vnc["password"] = password;
        for (const char* key : {"display_enabled", "display_backend", "native_display_enabled", "vnc_enabled",
                                "vnc_host", "vnc_port", "vnc_password_auth", "vnc_password"}) erase(item, key);
    }
    constexpr std::array geometry{"display_width", "display_height", "display_refresh_rate", "display_dpi_h", "display_dpi_v"};
    bool legacy = false;
    for (const char* key : geometry) legacy = legacy || present(item, key);
    if (legacy) {
        const auto width = integer(item, "display_width", 1280), height = integer(item, "display_height", 720);
        const auto refresh = integer(item, "display_refresh_rate", 120);
        const auto dpi_h = integer(item, "display_dpi_h", 160), dpi_v = integer(item, "display_dpi_v", 160);
        auto& gpu = screen(item, gpu0);
        gpu["width"] = Json::Int64(width); gpu["height"] = Json::Int64(height); gpu["refresh_rate"] = Json::Int64(refresh);
        gpu["dpi_h"] = Json::Int64(dpi_h); gpu["dpi_v"] = Json::Int64(dpi_v);
        auto& fb = screen(item, simplefb);
        fb["width"] = Json::Int64(width); fb["height"] = Json::Int64(height); fb["poll_hz"] = Json::Int64(30);
        for (const char* key : geometry) erase(item, key);
    }
    if (!pre_screens && !present(item, "gpu_enabled")) return;
    const auto accelerated = boolean(item, "gpu_enabled", false);
    const auto* gpu = find_screen(item, gpu0);
    if (!accelerated && gpu && boolean(*gpu, "enabled", false)) item["gpu_backend"] = "gpu_2d";
    erase(item, "gpu_enabled");
}
void ensure_serial_defaults(Json::Value& item) {
    auto& ports = array_child(item, "serial_ports");
    std::array<bool, 5> have{};
    bool console = false;
    for (const auto& port : ports) {
        const auto num = narrow(integer(port, "num", 1));
        if (java_enum(port, "hardware", "SERIAL", serial_hardware) == "SERIAL" && num >= 1 && num < 5) have[static_cast<size_t>(num)] = true;
        if (boolean(port, "console", false)) console = true;
    }
    for (int num = 1; num < 5; ++num) {
        if (have[static_cast<size_t>(num)]) continue;
        Json::Value port;
        port["hardware"] = "serial"; port["num"] = num;
        port["backend"] = num == 1 ? "app_console" : "sink";
        // The console is single-select; never add a second flag.
        if (num == 1 && !console) port["console"] = true;
        port["fixed"] = true;
        ports.append(std::move(port));
    }
}
std::vector<Json::ArrayIndex> controllers(const Json::Value& item) {
    std::vector<Json::ArrayIndex> result;
    const auto& rows = member(item, "peripherals");
    if (!rows.isArray()) return result;
    for (Json::ArrayIndex i = 0; i < rows.size(); ++i)
        if (java_enum(rows[i], "type", "VIRTIO_SOUND", peripheral_types) == "XHCI_USB") result.push_back(i);
    return result;
}
int64_t controller_index(const std::string& id) {
    if (!id.starts_with("xhci-")) return -1;
    try { return java_long(std::string_view(id).substr(5)); } catch (const std::invalid_argument&) { return -1; }
}
std::string next_controller_id(Json::Value& item) {
    auto next = integer(item, "xhci_next", 0);
    for (const auto index : controllers(item)) {
        const auto value = controller_index(string(item["peripherals"][index], "id"));
        if (value >= next) next = static_cast<int64_t>(static_cast<uint64_t>(value) + 1);
    }
    item["xhci_next"] = Json::Int64(static_cast<int64_t>(static_cast<uint64_t>(next) + 1));
    return "xhci-" + std::to_string(next);
}
void migrate_xhci(Json::Value& item) {
    // Ids first, so a half-converted entry has one before anything counts.
    for (const auto index : controllers(item)) {
        if (!string(item["peripherals"][index], "id").empty()) continue;
        const auto id = next_controller_id(item);
        item["peripherals"][index]["id"] = id;
    }
    if (!controllers(item).empty()) return;
    // The counter proves this fold already ran; never regrow a removed controller.
    if (integer(item, "xhci_next", -1) >= 0 || !boolean(item, "usb", false)) return;
    Json::Value controller;
    controller["type"] = "xhci_usb";
    controller["id"] = next_controller_id(item);
    controller["usb2_ports"] = 8; controller["usb3_ports"] = 8;
    array_child(item, "peripherals").append(std::move(controller));
}
}
std::string java_enum(const Json::Value& object, const char* key, const char* fallback, const std::vector<const char*>& names) {
    const auto& field = member(object, key);
    if (!field.isString()) return fallback;
    const auto name = upper(field.asString());
    for (const auto* candidate : names) if (name == candidate) return name;
    return fallback;
}
Json::Value migrate_vm(Json::Value item) {
    if (!item.isObject()) throw std::invalid_argument("VM config must be an object");
    if (!item.isMember("use_uefi") && string(item, "kernel") == edk2_firmware) {
        item["use_uefi"] = true;
        item.removeMember("kernel");
    }
    migrate_boot(item);
    migrate_nic_forwards(item);
    migrate_screens(item);
    ensure_serial_defaults(item);
    migrate_xhci(item);
    return item;
}
Json::Value vm_streams(const Json::Value& config) {
    Json::Value result(Json::arrayValue);
    for (const char* name : {"stdout", "stderr", "stdio"}) result.append(name);
    if (java_enum(config, "backend", "CROSVM", {"CROSVM", "QEMU"}) == "QEMU") {
        result.append("uart");
        if (boolean(config, "agent_mode", false)) result.append("agent");
        return result;
    }
    // One text console per app-console serial port, as CrosvmBackendInstance.
    std::set<std::string> seen;
    for (const auto& port : member(config, "serial_ports")) {
        if (java_enum(port, "backend", "SINK", serial_backends) != "APP_CONSOLE") continue;
        const auto hardware = java_enum(port, "hardware", "SERIAL", serial_hardware);
        const auto num = std::to_string(narrow(integer(port, "num", 1)));
        const auto name = (hardware == "SBSA" ? "sbsa" : hardware == "VIRTIO_CONSOLE" ? "vcon" : "serial") + num;
        if (seen.insert(name).second) result.append(name);
    }
    return result;
}
}
