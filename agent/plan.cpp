// SPDX-License-Identifier: GPL-3.0-or-later
#include "plan.h"
#include "services/context.h"
#include <algorithm>
#include <utility>

namespace droidvm::agent {
namespace {
[[noreturn]] void invalid() {
    // Neither a password nor caller-supplied field contents may enter errors.
    throw ServiceError(ErrorCode::invalid_argument, "Invalid rescue operation parameters");
}
std::string_view text(const Json::Value& object, const char* key) {
    const char* first = nullptr;
    const char* last = nullptr;
    if (!object.isObject() || !object[key].getString(&first, &last)) invalid();
    return {first, static_cast<size_t>(last - first)};
}
bool canonical_uuid(std::string_view value) noexcept {
    // Request IDs here intentionally accept only canonical stored UUIDs. The
    // general legacy config UUID parser also accepts short/non-ASCII spellings;
    // avoid that normalization and its ICU dependency at this bounded boundary.
    if (value.size() != 36) return false;
    for (size_t i = 0; i < value.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') return false;
        } else if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return false;
    }
    return true;
}
bool safe_name(std::string_view value) noexcept {
    if (value.empty() || value.size() > 64) return false;
    for (const auto ch : value)
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') || ch == '_' || ch == '-')) return false;
    return true;
}
bool absolute_file(std::string_view value) noexcept {
    if (value.size() < 2 || value.size() > 4096 || value.front() != '/' || value.back() == '/' ||
        value.find('\0') != std::string_view::npos) return false;
    size_t offset = 1;
    while (offset < value.size()) {
        const auto end = value.find('/', offset);
        const auto part = value.substr(offset, end == std::string_view::npos ? end : end - offset);
        if (part.empty() || part == "." || part == "..") return false;
        if (end == std::string_view::npos) break;
        offset = end + 1;
    }
    return true;
}
}
bool valid_password(std::string_view password) noexcept {
    if (password.empty() || password.size() > password_limit) return false;
    for (const auto ch : password)
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') || password_symbols.find(ch) != std::string_view::npos)) return false;
    return true;
}
Request::Request(ActionKind action, std::string disk_id, bool normal_users, std::string_view password)
    : action_(action), disk_id_(std::move(disk_id)), normal_users_(normal_users), password_size_(password.size()) {
    std::copy(password.begin(), password.end(), password_.begin());
}
Request::Request(Request&& other) noexcept
    : action_(other.action_), disk_id_(std::move(other.disk_id_)), normal_users_(other.normal_users_),
      password_(other.password_), password_size_(other.password_size_) {
    other.clear_password();
}
Request& Request::operator=(Request&& other) noexcept {
    if (this != &other) {
        clear_password();
        action_ = other.action_;
        disk_id_ = std::move(other.disk_id_);
        normal_users_ = other.normal_users_;
        password_ = other.password_;
        password_size_ = other.password_size_;
        other.clear_password();
    }
    return *this;
}
Request::~Request() { clear_password(); }
void Request::clear_password() noexcept {
    // Best effort for this owned buffer only. This cannot erase external JSON
    // bodies, allocator history, registers or copies made by an embedding caller.
    volatile char* bytes = password_.data();
    for (size_t i = 0; i < password_.size(); ++i) bytes[i] = 0;
    password_size_ = 0;
}
Json::Value Request::public_json() const {
    Json::Value result(Json::objectValue);
    result["action"] = std::string(action_name(action_));
    result["diskId"] = disk_id_;
    if (action_ == ActionKind::password) result["normalUsers"] = normal_users_;
    return result;
}
Request parse_request(const Json::Value& value) {
    if (!value.isObject() || value.size() < 2 || value.size() > 4) invalid();
    const auto action = text(value, "action");
    const bool password = action == "chpasswd";
    if (!password && action != "autogrow") invalid();
    for (const auto& key : value.getMemberNames())
        if (key != "action" && key != "diskId" && !(password && (key == "password" || key == "normalUsers"))) invalid();
    const auto id = text(value, "diskId");
    if (!canonical_uuid(id)) invalid();
    if (!password) return Request(ActionKind::autogrow, std::string(id), false, {});
    const auto secret = text(value, "password");
    if (!valid_password(secret)) invalid();
    bool normal_users = false;
    if (value.isMember("normalUsers")) {
        if (!value["normalUsers"].isBool()) invalid();
        normal_users = value["normalUsers"].asBool();
    }
    return Request(ActionKind::password, std::string(id), normal_users, secret);
}
Json::Value build_rescue_vm(const RescueVmInputs& inputs) {
    if (!canonical_uuid(inputs.vm_id) || !safe_name(inputs.name) || !absolute_file(inputs.kernel) ||
        !absolute_file(inputs.initrd) || !absolute_file(inputs.disk_path)) invalid();
    Json::Value result(Json::objectValue);
    result["id"] = inputs.vm_id;
    result["name"] = inputs.name;
    result["temporary"] = true;
    result["agent_mode"] = true;
    result["backend"] = "qemu";
    result["hypervisor"] = "soft";
    result["machine_type"] = "virt";
    result["cpu_model"] = "cortex-a710";
    result["cpu_count"] = 1;
    result["memory_mb"] = 320;
    for (const auto* flag : {"auto_up", "hugepages", "rng", "balloon", "pmu", "smt", "audio_enabled", "vpu_enabled"})
        result[flag] = false;
    result["prepare_lend_mthp"] = "disabled";
    result["boot"]["protocol"] = "linux";
    auto& linux_boot = result["boot"]["linux"];
    linux_boot["source"] = "manual";
    linux_boot["kernel"] = inputs.kernel;
    linux_boot["initrd"] = inputs.initrd;
    linux_boot["cmdline"] = "console=ttyAMA0 rdinit=/bin/sh panic=-1";
    for (const auto* key : {"disks", "networks", "peripherals", "shared_dirs", "extra_options", "environment_variables"})
        result[key] = Json::Value(Json::arrayValue);
    Json::Value disk(Json::objectValue);
    disk["path"] = inputs.disk_path;
    disk["bus"] = "virtio";
    disk["readonly"] = false;
    result["disks"].append(std::move(disk));
    result["screens"]["gpu-0"]["enabled"] = false;
    result["screens"]["simplefb"]["enabled"] = false;
    return result;
}
}
