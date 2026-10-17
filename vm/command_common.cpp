// SPDX-License-Identifier: GPL-3.0-or-later
#include "command_common.h"
#include "build_metadata.h"
#include <unicode/utf8.h>
#include <unicode/utf16.h>
#include <algorithm>
#include <stdexcept>

namespace droidvm::vm::command {
namespace {
// String.hashCode over UTF-16 units.
uint32_t java_hash(const std::string& text) {
    uint32_t hash = 0;
    int32_t offset = 0, length = static_cast<int32_t>(text.size());
    while (offset < length) {
        UChar32 c;
        U8_NEXT(text.data(), offset, length, c);
        if (c < 0) c = 0xfffd;
        if (c > 0xffff) {
            hash = 31 * hash + U16_LEAD(c);
            hash = 31 * hash + U16_TRAIL(c);
        } else hash = 31 * hash + static_cast<uint32_t>(c);
    }
    return hash;
}
}

std::string trim(const std::string& text) {
    size_t first = 0, last = text.size();
    while (first < last && static_cast<unsigned char>(text[first]) <= 0x20) ++first;
    while (last > first && static_cast<unsigned char>(text[last - 1]) <= 0x20) --last;
    return text.substr(first, last - first);
}
// Object values in the HashMap order a sequentially filled map has. Ties
// within one bucket fall back to key order, since jsoncpp does not keep the
// source order.
std::vector<const Json::Value*> items(const Json::Value& value) {
    std::vector<const Json::Value*> out;
    if (value.isArray()) {
        for (const auto& entry : value) out.push_back(&entry);
        return out;
    }
    if (!value.isObject()) return out;
    const auto names = value.getMemberNames();
    uint32_t capacity = 16;
    while (names.size() > capacity / 4 * 3) capacity *= 2;
    std::vector<std::pair<uint32_t, size_t>> order;
    for (size_t i = 0; i < names.size(); ++i) {
        auto hash = java_hash(names[i]);
        order.emplace_back((hash ^ (hash >> 16)) & (capacity - 1), i);
    }
    std::stable_sort(order.begin(), order.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
    for (const auto& [bucket, index] : order) out.push_back(&value[names[index]]);
    return out;
}
std::string data_dir(const HostFacts& host) {
    return host.data_dir.empty() ? std::string("/data/data/" DROIDVM_PACKAGE_NAME) : host.data_dir;
}
std::string optimized_path(std::string path, const HostFacts& host) {
    constexpr std::string_view prefix = "/storage/emulated/";
    if (host.optimize_sdcard && path.starts_with(prefix)) return "/data/media/" + path.substr(prefix.size());
    return path;
}
std::string qemu_option_value(const std::string& value) {
    if (value.find('\0') != std::string::npos) throw std::invalid_argument("NUL in QEMU option value");
    std::string result;
    for (char c : value) { result += c; if (c == ',') result += ','; }
    return result;
}
std::string crosvm_option_value(const std::string& value) {
    if (value.find('\0') != std::string::npos) throw std::invalid_argument("NUL in crosvm option value");
    if (!value.empty() && value.find_first_of(",[]\"'") == std::string::npos) return value;
    std::string result = "\"";
    for (char c : value) { if (c == '\\' || c == '"') result += '\\'; result += c; }
    return result + '"';
}

std::optional<Screen> find_screen(const Json::Value& config, const char* id) {
    const auto& screens = member(config, "screens");
    if (!screens.isObject() || !screens[id].isObject()) return std::nullopt;
    return Screen{id, &screens[id]};
}
std::vector<Screen> screens_of(const Json::Value& config) {
    std::vector<Screen> out;
    for (const char* id : {gpu0, simplefb}) if (auto screen = find_screen(config, id)) out.push_back(*screen);
    return out;
}
bool screen_enabled(const Json::Value& config, const char* id) {
    const auto screen = find_screen(config, id);
    return screen && screen->enabled();
}
VncBinding vnc_binding(const Screen& screen, const std::map<std::string, VncRun>& run) {
    const auto& vnc = member(*screen.item, "vnc");
    const auto& stored = vnc.isObject() ? vnc : Json::Value::nullSingleton();
    VncBinding out{string(stored, "host", ""), integer(stored, "port", -1), string(stored, "password", "")};
    if (const auto at = run.find(screen.id); at != run.end()) {
        if (at->second.host) out.host = *at->second.host;
        if (at->second.port) out.port = *at->second.port;
        if (at->second.password) out.password = *at->second.password;
    }
    return out;
}

std::optional<std::string> resolve_hypervisor(const Json::Value& item, const HostFacts& host, Backend backend) {
    std::string configured = "AUTO";
    if (member(item, "hypervisor").isString()) {
        configured = java_enum(item, "hypervisor", "", hypervisors);
        if (configured.empty()) throw std::invalid_argument("No enum constant VMHypervisor." + member(item, "hypervisor").asString());
    }
    if (configured != "AUTO") return configured;
    // findPreferredHypervisor: device-backed values in enum order that the
    // backend accepts, then SOFT where the backend accepts it.
    if (host.has_kvm) return "KVM";
    if (host.has_gunyah) return "GUNYAH";
    if (backend == Backend::qemu) return "SOFT";
    if (host.has_gzvm) return "GENIEZONE";
    return std::nullopt;
}
std::optional<std::string> strace_args(const Json::Value& item, const HostFacts& host, std::vector<std::string>& args) {
    if (!boolean(item, "strace", false)) return std::nullopt;
    const auto root = data_dir(host);
    std::optional<std::string> binary;
    if (host.strace_prebuilt_exists) binary = path_join(root, "usr", "bin", "strace");
    else binary = host.strace_in_path;
    if (!binary) return std::nullopt;
    const auto dir = path_join(root, "cache", "strace-" + config::uuid(item));
    for (auto arg : {*binary, std::string("-Tttrvyyff"), std::string("-s"), std::string("8192"), std::string("-o"), path_join(dir, "strace.log")})
        args.push_back(std::move(arg));
    return dir;
}
void process_environment(const Json::Value& item, const HostFacts& host, std::vector<std::pair<std::string, std::string>>& env) {
    const auto root = data_dir(host);
    env.emplace_back("LD_PRELOAD", path_join(root, "lib", "libsimpledump.so") + ":" + path_join(root, "lib", "libcompat_a" + host.android_release + ".so"));
    env.emplace_back("LD_LIBRARY_PATH", path_join(root, "usr", "lib"));
    const auto& configured = member(item, "environment_variables");
    if (!configured.isArray()) return;
    for (const auto& entry : configured) {
        if (!entry.isString()) continue;
        const auto raw = trim(entry.asString());
        const auto separator = raw.find('=');
        if (separator == std::string::npos || separator == 0) continue;
        const auto key = trim(raw.substr(0, separator));
        if (key.empty()) continue;
        env.emplace_back(key, raw.substr(separator + 1));
    }
}
void extra_options(const Json::Value& item, std::vector<std::string>& args) {
    if (!present(item, "extra_options")) return;
    const auto& extra = item["extra_options"];
    if (extra.isNull()) return;
    if (!extra.isArray() && !extra.isObject()) throw std::runtime_error("Cannot iterate over extra_options");
    for (const auto* arg : items(extra)) {
        if (!arg->isString()) throw std::runtime_error("Expected type STRING");
        args.push_back(arg->asString());
    }
}
}
