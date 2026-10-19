// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "vm/crosvm_command.h"
#include "store/network_config.h"
#include "store/vm_config.h"
#include <json/json.h>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Pieces of the VMBackendInstance/VMConfig model shared by the backend
// command ports. DataItem semantics as in store/vm_config.cpp.
namespace droidvm::vm::command {
using config::boolean;
using config::integer;
using config::java_enum;
using config::member;
using config::string;
using Names = std::vector<const char*>;
inline const Names hypervisors{"AUTO", "SOFT", "KVM", "GUNYAH", "GENIEZONE"};
inline const Names protections{"PROTECTED_NORMAL", "PROTECTED_PROTECTED", "PROTECTED_WITHOUT_FIRMWARE", "PSEUDO_UNPROTECTED"};
inline const Names gpu_backends{"NONE", "GPU_2D", "GPU_GFXSTREAM", "GPU_VIRGLRENDERER"};
inline const Names exporters{"NATIVE", "VNC", "NONE"};
inline const Names disk_buses{"VIRTIO", "SCSI", "PMEM", "PFLASH", "CDROM"};
inline const Names dir_caches{"NEVER", "AUTO", "ALWAYS"};
inline const Names peripheral_types{"VIRTIO_SOUND", "INTEL_HDA", "VIRTIO_CAMERA", "XHCI_USB"};
inline constexpr const char* gpu0 = "gpu-0";
inline constexpr const char* simplefb = "simplefb";

inline bool present(const Json::Value& object, const char* key) { return object.isObject() && object.isMember(key); }
inline std::string decimal(int64_t value) { return std::to_string(value); }
inline std::string java_bool(bool value) { return value ? "true" : "false"; }
inline std::string lower(std::string text) {
    for (auto& c : text) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return text;
}
// StringUtils.pathJoin
inline std::string path_join(std::string base, std::string child) {
    if (!base.empty() && base.back() == '/') base.pop_back();
    if (!child.empty() && child.front() == '/') child.erase(0, 1);
    return base + "/" + child;
}
template <typename... Rest> std::string path_join(std::string base, std::string child, Rest... rest) {
    return path_join(path_join(std::move(base), std::move(child)), std::move(rest)...);
}
// String.trim
std::string trim(const std::string& text);
// DataItem iteration: array elements, or object values in HashMap order.
std::vector<const Json::Value*> items(const Json::Value& value);
// Constants.DATA_DIR unless the host names another one.
std::string data_dir(const HostFacts& host);
// VMBackendInstance.patchOptimizedPath
std::string optimized_path(std::string path, const HostFacts& host);
// Values embedded in backend option lists, not shell escaping.
std::string qemu_option_value(const std::string& value);
std::string crosvm_option_value(const std::string& value);

// --- VMScreenConfig ---
struct Screen {
    std::string id;
    const Json::Value* item;
    bool enabled() const { return boolean(*item, "enabled", false); }
    std::string exporter() const { return java_enum(*item, "exporter", "NONE", exporters); }
    bool input_enabled() const { return boolean(*item, "input_enabled", true); }
};
std::optional<Screen> find_screen(const Json::Value& config, const char* id);
// listOf: the described screens in IDS order.
std::vector<Screen> screens_of(const Json::Value& config);
bool screen_enabled(const Json::Value& config, const char* id);
// getVncHost/getVncPort/getVncPassword after VMInstance.resolveVncConfig.
struct VncBinding { std::string host; int64_t port = -1; std::string password; };
VncBinding vnc_binding(const Screen& screen, const std::map<std::string, VncRun>& run);

// VMHypervisor.valueOf(optString("hypervisor","auto").toUpperCase()) then
// resolveConfigured(backend, ...); nullopt when nothing is supported.
enum class Backend { crosvm, qemu };
// Custom listener/configuration options make the generated endpoint ambiguous.
// Unrelated CPU/device arguments do not disable the graphical connection.
bool vnc_options_overridden(const Json::Value& item, Backend backend);
std::optional<std::string> resolve_hypervisor(const Json::Value& item, const HostFacts& host, Backend backend);
// VMBackendInstance.prepareStraceArguments; returns getStraceFolder().
std::optional<std::string> strace_args(const Json::Value& item, const HostFacts& host, std::vector<std::string>& args);
// VMBackendInstance.prepareProcess environment (LD_* then applyConfiguredEnvironment).
void process_environment(const Json::Value& item, const HostFacts& host, std::vector<std::pair<std::string, std::string>>& env);
// item.opt("extra_options", newArray()).forEach(asString)
void extra_options(const Json::Value& item, std::vector<std::string>& args);
}
