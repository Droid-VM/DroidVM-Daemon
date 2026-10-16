// SPDX-License-Identifier: GPL-3.0-or-later
// Port of daemon/vm/BootPlan and the lib/store/vm/BootConfig accessors it uses.
#include "boot_plan.h"
#include "build_metadata.h"
#include "runtime/child.h"
#include "store/json_file.h"
#include "store/network_config.h"
#include "store/vm_config.h"
#include <bit>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace droidvm::vm {
namespace {
const std::string data_dir = "/data/data/" DROIDVM_PACKAGE_NAME;
constexpr const char* default_manual_cmdline = "root=/dev/vda2";
[[noreturn]] void failure(const std::string& text) { throw std::runtime_error(text); }
Json::Value& child(Json::Value& parent, const char* key) {
    if (!parent[key].isObject()) parent[key] = Json::Value(Json::objectValue);
    return parent[key];
}
int narrow(int64_t value) { return std::bit_cast<int32_t>(static_cast<uint32_t>(value)); }
std::string compact(const Json::Value& value) {
    Json::StreamWriterBuilder builder;
    builder["indentation"] = ""; builder["emitUTF8"] = true;
    return Json::writeString(builder, value);
}
// org.json's JSON.toString(Object) for values read from lbx output.
std::string java_text(const Json::Value& value) {
    if (value.isString()) return value.asString();
    if (value.isBool()) return value.asBool() ? "true" : "false";
    if (value.isInt64()) return std::to_string(value.asInt64());
    if (value.isUInt64()) return std::to_string(value.asUInt64());
    if (value.isDouble()) {
        const auto number = value.asDouble();
        char buffer[64];
        if (std::isfinite(number) && number == std::floor(number) && std::fabs(number) < 1e7) std::snprintf(buffer, sizeof(buffer), "%.1f", number);
        else std::snprintf(buffer, sizeof(buffer), "%.17g", number);
        return buffer;
    }
    if (value.isNull()) return "null";
    return compact(value);
}
// Null-safe optStr: org.json turns JSON null into the text "null".
std::string text(const Json::Value& object, const char* key) {
    if (!object.isObject() || !object.isMember(key) || object[key].isNull()) return {};
    return java_text(object[key]);
}
bool java_boolean(const Json::Value& object, const char* key, bool fallback) {
    if (!object.isObject()) return fallback;
    const auto& value = object[key];
    if (value.isBool()) return value.asBool();
    if (value.isString()) {
        std::string lower = value.asString();
        for (auto& c : lower) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (lower == "true") return true;
        if (lower == "false") return false;
    }
    return fallback;
}
int64_t saturate(double number) {
    if (std::isnan(number)) return 0;
    if (number >= 9.2233720368547758e18) return std::numeric_limits<int64_t>::max();
    if (number <= -9.2233720368547758e18) return std::numeric_limits<int64_t>::min();
    return static_cast<int64_t>(number);
}
int64_t java_long(const Json::Value& object, const char* key, int64_t fallback) {
    if (!object.isObject() || !object.isMember(key)) return fallback;
    const auto& value = object[key];
    if (value.isInt64()) return value.asInt64();
    if (value.isUInt64()) return static_cast<int64_t>(value.asUInt64());
    if (value.isDouble()) return saturate(value.asDouble());
    if (value.isString()) {
        const auto source = value.asString();
        char* end = nullptr;
        errno = 0;
        const auto number = std::strtod(source.c_str(), &end);
        if (end != source.c_str() && *end == '\0') return saturate(number);
    }
    return fallback;
}
const Json::Value* array(const Json::Value& object, const char* key) {
    return object.isObject() && object[key].isArray() ? &object[key] : nullptr;
}
bool is_linux(const Json::Value& entry) {
    if (!entry.isObject()) return false;
    const auto type = text(entry, "type");
    return type.empty() || type == "linux";
}
const Json::Value* match_entry(const Json::Value& entries, const std::optional<std::string>& id, const std::optional<std::string>& title) {
    for (const auto& entry : entries)
        if (is_linux(entry) && id && !id->empty() && *id == text(entry, "id")) return &entry;
    for (const auto& entry : entries)
        if (is_linux(entry) && title && !title->empty() && *title == text(entry, "title")) return &entry;
    return nullptr;
}
const Json::Value* default_entry(const Json::Value& entries) {
    for (const auto& entry : entries) if (is_linux(entry) && java_boolean(entry, "default", false)) return &entry;
    for (const auto& entry : entries) if (is_linux(entry)) return &entry;
    return nullptr;
}
std::string run_lbx(const std::string& lbx, std::vector<std::string> args) {
    ChildOptions options;
    options.argv = {lbx};
    options.argv.insert(options.argv.end(), args.begin(), args.end());
    std::string joined;
    for (const auto& arg : options.argv) joined += (joined.empty() ? "" : " ") + arg;
    ChildOutput result;
    try { result = Child(options).communicate({}, std::chrono::seconds(30), 4u << 20); }
    catch (const std::exception& error) { failure(std::string("lbx failed to start: ") + error.what()); }
    if (result.timed_out) failure("lbx timed out: " + joined);
    if (result.exit_code != 0) {
        auto error = result.error;
        while (!error.empty() && static_cast<unsigned char>(error.back()) <= ' ') error.pop_back();
        size_t first = 0;
        while (first < error.size() && static_cast<unsigned char>(error[first]) <= ' ') ++first;
        error = error.substr(first);
        failure("lbx failed (" + std::to_string(result.exit_code) + "): " + (error.empty() ? joined : error));
    }
    return result.output;
}
std::string lbx_md5(const std::string& lbx, const std::string& image, const std::string& uri, bool decompress) {
    if (uri.empty()) return {};
    auto out = run_lbx(lbx, decompress ? std::vector<std::string>{"md5", image, uri, "--decompress"} : std::vector<std::string>{"md5", image, uri});
    size_t first = 0;
    while (first < out.size() && static_cast<unsigned char>(out[first]) <= ' ') ++first;
    out = out.substr(first);
    while (!out.empty() && static_cast<unsigned char>(out.back()) <= ' ') out.pop_back();
    const auto space = out.find(' ');
    return space != std::string::npos && space > 0 ? out.substr(0, space) : out;
}
std::string array_text(const Json::Value& entry, const char* key, Json::ArrayIndex index) {
    const auto* values = array(entry, key);
    if (!values || index >= values->size()) return {};
    return java_text((*values)[index]);
}
bool exists(const std::string& path) { struct stat info{}; return stat(path.c_str(), &info) == 0; }
void remove_quiet(const std::string& path) { if (exists(path)) unlink(path.c_str()); }
std::optional<Json::Value> load_json(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    std::string bytes((std::istreambuf_iterator<char>(input)), {});
    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    Json::Value value;
    std::string error;
    if (!reader->parse(bytes.data(), bytes.data() + bytes.size(), &value, &error) || !value.isObject()) return {};
    return value;
}
bool kernel_compressed(const Json::Value& entry) { return !text(entry, "kernel_compression").empty(); }
bool same_array(const Json::Value* current, const Json::Value& old, const char* key) {
    const auto* previous = array(old, key);
    if (!current || !previous) return !current && !previous;
    return *current == *previous;
}
bool cache_up_to_date(const std::string& lbx, const std::string& image, const Json::Value& entry, const std::string& manifest) {
    const auto old = load_json(manifest);
    if (!old) return false;
    if (!(*old)["image"].isString() || (*old)["image"].asString() != image) return false;
    const auto kernel = text(entry, "kernel");
    if (!(*old)["kernel"].isString() || (*old)["kernel"].asString() != kernel) return false;
    if (java_long(entry, "kernel_size", -1) != java_long(*old, "kernel_size", std::numeric_limits<int64_t>::min())) return false;
    if (!same_array(array(entry, "initrd"), *old, "initrd") || !same_array(array(entry, "initrd_size"), *old, "initrd_size")) return false;
    try {
        if (lbx_md5(lbx, image, kernel, kernel_compressed(entry)) != text(*old, "kernel_md5")) return false;
        const auto* initrds = array(entry, "initrd");
        const auto* md5s = array(*old, "initrd_md5");
        const auto count = initrds ? initrds->size() : 0;
        if (!md5s || md5s->size() != count) return false;
        for (Json::ArrayIndex i = 0; i < count; ++i)
            if (lbx_md5(lbx, image, array_text(entry, "initrd", i), false) != java_text((*md5s)[i])) return false;
    } catch (const std::runtime_error&) { return false; } // lbx md5 failed: re-extract
    return true;
}
void extract_cached(const std::string& lbx, const std::string& image, const Json::Value& entry, const std::string& directory) {
    const auto manifest = directory + "/manifest.json", kernel = directory + "/kernel";
    if (exists(manifest) && exists(kernel) && java_long(entry, "kernel_size", -1) > 0 && cache_up_to_date(lbx, image, entry, manifest)) return;
    struct stat info{};
    if (stat(directory.c_str(), &info) != 0 || !S_ISDIR(info.st_mode)) {
        // File.mkdirs: create every missing parent.
        for (size_t at = 1; at != std::string::npos; at = directory.find('/', at + 1))
            mkdir(directory.substr(0, at).c_str(), 0700);
        if (mkdir(directory.c_str(), 0700) != 0 && errno != EEXIST) failure("cannot create " + directory);
    }
    remove_quiet(manifest); // invalidate while files are in flux
    if (kernel_compressed(entry)) run_lbx(lbx, {"cp", image, text(entry, "kernel"), kernel, "--decompress"});
    else run_lbx(lbx, {"cp", image, text(entry, "kernel"), kernel});
    const auto initrd = directory + "/initrd";
    remove_quiet(initrd);
    if (const auto* initrds = array(entry, "initrd"); initrds && !initrds->empty()) {
        // Microcode early cpio and initramfs, concatenated in order.
        std::ofstream out(initrd, std::ios::binary | std::ios::trunc);
        if (!out) failure("cannot create " + initrd);
        for (Json::ArrayIndex i = 0; i < initrds->size(); ++i) {
            const auto part = directory + "/initrd." + std::to_string(i);
            run_lbx(lbx, {"cp", image, array_text(entry, "initrd", i), part});
            std::ifstream in(part, std::ios::binary);
            if (!in) failure("cannot read " + part);
            out << in.rdbuf();
            if (!out) failure("cannot write " + initrd);
            remove_quiet(part);
        }
    }
    Json::Value key;
    const auto kernel_uri = text(entry, "kernel");
    key["image"] = image; key["kernel"] = kernel_uri;
    key["kernel_size"] = Json::Int64(java_long(entry, "kernel_size", -1));
    key["kernel_md5"] = lbx_md5(lbx, image, kernel_uri, kernel_compressed(entry));
    const auto* initrds = array(entry, "initrd");
    key["initrd"] = initrds ? *initrds : Json::Value();
    key["initrd_size"] = array(entry, "initrd_size") ? entry["initrd_size"] : Json::Value();
    key["initrd_md5"] = Json::Value(Json::arrayValue);
    if (initrds) for (Json::ArrayIndex i = 0; i < initrds->size(); ++i) key["initrd_md5"].append(lbx_md5(lbx, image, array_text(entry, "initrd", i), false));
    // The manifest only speeds up the next start; a failed write is ignored.
    std::ofstream(manifest, std::ios::binary | std::ios::trunc) << config::encode_json(key);
}
std::string find_image(const Json::Value& config, int index) {
    const auto& disks = config::member(config, "disks");
    if (disks.isArray()) {
        if (index >= 0 && static_cast<Json::ArrayIndex>(index) < disks.size()) {
            const auto path = config::string(disks[static_cast<Json::ArrayIndex>(index)], "path");
            if (!path.empty()) return path;
        }
        for (const auto& disk : disks) {
            const auto path = config::string(disk, "path");
            if (!path.empty()) return path;
        }
    }
    failure("boot from disk image: VM has no disk with a path");
}
struct ImageEntry { std::optional<std::string> id, title; };
std::optional<ImageEntry> pinned_entry(Json::Value& image) {
    const auto& entry = config::member(image, "entry");
    if (!entry.isObject()) return {};
    auto field = [&](const char* key) { return entry[key].isString() ? std::optional(entry[key].asString()) : std::nullopt; };
    return ImageEntry{field("id"), field("title")};
}
std::string entry_cmdline(Json::Value& image, const Json::Value& entry) {
    const auto fixed = config::boolean(image, "vdafix", true) ? text(entry, "cmdline_fixed") : "";
    return !fixed.empty() ? fixed : text(entry, "cmdline");
}
}
const std::string& builtin_kernel() { static const std::string path = data_dir + "/usr/share/droidvm/vmlinuz"; return path; }
const std::string& builtin_initrd() { static const std::string path = data_dir + "/usr/share/droidvm/initramfs.img"; return path; }
const std::string& edk2_firmware() { static const std::string path = data_dir + "/usr/share/droidvm/edk2-gunyah.fd"; return path; }
const std::string& edk2_vars() { static const std::string path = data_dir + "/usr/share/droidvm/edk2-gunyah.vars.fd"; return path; }
Json::Value scan_boot_entries(const std::string& lbx, const std::string& image) {
    const auto out = run_lbx(lbx, {"entries", image, "--json"});
    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    Json::Value value;
    std::string error;
    if (!reader->parse(out.data(), out.data() + out.size(), &value, &error) || !value.isArray())
        failure("bad lbx output for " + image + ": " + (error.empty() ? "not a JSON array" : error));
    return value;
}
BootPlan resolve_boot(Json::Value& config, const std::optional<std::string>& entry_override, const BootTools& tools) {
    auto& boot = child(config, "boot");
    if (entry_override && *entry_override == builtin_entry_key) {
        // Built-in kernel for this disk: root= comes from the image entry.
        auto& image = child(child(boot, "linux"), "image");
        auto cmdline = config::string(image, "cmdline");
        if (cmdline.empty()) {
            try {
                const auto entries = scan_boot_entries(tools.lbx, find_image(config, narrow(config::integer(image, "disk", 0))));
                if (!entries.empty()) {
                    const auto pinned = pinned_entry(image);
                    const Json::Value* entry = pinned ? match_entry(entries, pinned->id, pinned->title) : nullptr;
                    if (!entry) entry = default_entry(entries);
                    if (entry) cmdline = entry_cmdline(image, *entry);
                }
            } catch (const std::runtime_error&) {}
            if (cmdline.empty()) cmdline = default_manual_cmdline;
        }
        return {false, "", "", false, builtin_kernel(), builtin_initrd(), cmdline, "DroidVM built-in kernel", false};
    }
    if (config::java_enum(boot, "protocol", "UEFI", {"UEFI", "LINUX"}) == "UEFI") {
        auto& uefi = child(boot, "uefi");
        const auto firmware = config::string(uefi, "firmware");
        const auto vars = config::string(child(boot, "uefi"), "vars");
        return {true, firmware, vars, config::boolean(child(boot, "uefi"), "vars_enabled", true), "", "", "", {}, false};
    }
    auto& kernel_boot = child(boot, "linux");
    if (config::java_enum(kernel_boot, "source", "MANUAL", {"IMAGE", "MANUAL"}) == "MANUAL") {
        const auto kernel = config::string(child(boot, "linux"), "kernel");
        if (kernel == edk2_firmware()) return {true, "", "", false, "", "", "", {}, false}; // pre-boot{} EDK2 kernel
        const auto initrd = config::string(child(boot, "linux"), "initrd");
        return {false, "", "", false, kernel, initrd, config::string(child(boot, "linux"), "cmdline"), {}, false};
    }
    auto& image = child(child(boot, "linux"), "image");
    const auto path = find_image(config, narrow(config::integer(image, "disk", 0)));
    const auto entries = scan_boot_entries(tools.lbx, path);
    if (entries.empty()) failure("no boot entries found in " + path);
    const auto pinned = pinned_entry(image);
    const Json::Value* entry = nullptr;
    bool fallback = false;
    if (entry_override) entry = match_entry(entries, entry_override, entry_override);
    else if (pinned) entry = match_entry(entries, pinned->id, pinned->title);
    if (!entry) {
        fallback = entry_override.has_value() || pinned.has_value();
        entry = default_entry(entries);
    }
    if (!entry) {
        bool windows = false;
        for (const auto& row : entries) windows = windows || (row.isObject() && text(row, "type") == "windows");
        failure(path + " has no boot entry a direct kernel boot can start" + (windows ? ": it boots Windows, which needs the UEFI boot protocol" : ""));
    }
    if (text(*entry, "kernel").empty()) failure("selected boot entry has no kernel");
    const auto directory = tools.cache_root + "/" + config::uuid(config);
    extract_cached(tools.lbx, path, *entry, directory);
    auto cmdline = config::string(image, "cmdline");
    if (cmdline.empty()) cmdline = entry_cmdline(image, *entry);
    const auto initrd = directory + "/initrd";
    const auto title = text(*entry, "title");
    return {false, "", "", false, directory + "/kernel", exists(initrd) ? initrd : "", cmdline,
            title.empty() ? std::nullopt : std::optional(title), fallback};
}
}
