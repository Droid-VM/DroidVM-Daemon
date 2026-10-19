// SPDX-License-Identifier: GPL-3.0-or-later
#include "agent/plan.h"
#include "services/context.h"
#include <iostream>
#include <stdexcept>
#include <type_traits>
#include <utility>

using namespace droidvm;
using namespace droidvm::agent;
namespace {
void check(bool condition, const char* detail) { if (!condition) throw std::runtime_error(detail); }
template<class Work> void rejected(Work work) {
    try { work(); }
    catch (const ServiceError& error) {
        check(error.code() == ErrorCode::invalid_argument, "wrong rejection code");
        return;
    }
    throw std::runtime_error("invalid rescue plan accepted");
}
Json::Value request(const char* action = "chpasswd") {
    Json::Value value;
    value["action"] = action;
    value["diskId"] = "12345678-1234-4234-8234-123456789abc";
    if (std::string_view(action) == "chpasswd") value["password"] = "Secret-Not-Projected!42";
    return value;
}
std::string json(const Json::Value& value) { return Json::writeString(Json::StreamWriterBuilder{}, value); }
}
int main() {
    try {
        static_assert(!std::is_copy_constructible_v<Request> && !std::is_copy_assignable_v<Request>);
        static_assert(std::is_nothrow_move_constructible_v<Request> && std::is_nothrow_move_assignable_v<Request>);
        check(valid_password("aAZz09!@#%^*+-=_.,:?"), "App password allowlist");
        check(valid_password(std::string(128, 'a')) && !valid_password(std::string(129, 'a')), "password byte bound");
        for (const auto* invalid : {"", "with space", "quote'", "double\"", "dollar$", "line\nbreak", "slash/", "back\\slash", "\xc3\xa9"})
            check(!valid_password(invalid), "unsafe password accepted");
        check(!valid_password(std::string("a\0b", 3)), "NUL password accepted");
        auto raw = request();
        auto parsed = parse_request(raw);
        check(parsed.action() == ActionKind::password && !parsed.normal_users(), "password request defaults");
        check(parsed.password() == raw["password"].asString(), "secret not retained for protocol");
        check(!parsed.public_json().isMember("password") && json(parsed.public_json()).find("Secret-Not-Projected") == std::string::npos, "public projection leaked secret");
        const auto script = rescue_script({Action{parsed.action(), false, parsed.normal_users()}});
        check(script.find("Secret-Not-Projected") == std::string::npos, "script leaked secret");
        auto moved = std::move(parsed);
        check(parsed.password().empty() && moved.password() == raw["password"].asString(), "move did not transfer and clear secret");
        auto assigned = parse_request(request("autogrow"));
        assigned = std::move(moved);
        check(moved.password().empty() && !assigned.password().empty(), "move assignment secret lifetime");
        assigned.clear_password();
        check(assigned.password().empty() && !assigned.public_json().isMember("password"), "explicit secret clear");
        raw["normalUsers"] = true;
        check(parse_request(raw).normal_users(), "normal users selection");
        const auto grow = parse_request(request("autogrow"));
        check(grow.action() == ActionKind::autogrow && grow.password().empty() && !grow.public_json().isMember("normalUsers"), "autogrow request shape");
        for (const auto* key : {"command", "script", "kernel", "backend", "params"}) {
            auto value = request(); value[key] = "injected";
            rejected([&] { (void)parse_request(value); });
        }
        for (const auto* key : {"password", "normalUsers"}) {
            auto value = request("autogrow"); value[key] = false;
            rejected([&] { (void)parse_request(value); });
        }
        for (const auto& invalid : {Json::Value(), Json::Value(42), Json::Value("false")}) {
            auto value = request(); value["normalUsers"] = invalid;
            rejected([&] { (void)parse_request(value); });
        }
        auto invalid = request(); invalid.removeMember("password");
        rejected([&] { (void)parse_request(invalid); });
        invalid = request(); invalid["diskId"] = "12345678-1234-4234-8234-123456789ABC";
        rejected([&] { (void)parse_request(invalid); });
        invalid = request(); invalid["password"] = std::string(129, 'x');
        rejected([&] { (void)parse_request(invalid); });

        const RescueVmInputs input{"abcdef12-1234-4234-8234-123456789abc", "agent-0123456789abcdef",
            "/data/app/usr/share/droidvm/vmlinuz", "/data/app/usr/share/droidvm/initramfs.img", "/data/disks/guest disk.qcow2"};
        const auto vm = build_rescue_vm(input);
        check(vm["id"] == input.vm_id && vm["name"] == input.name && vm["temporary"].asBool(), "temporary identity");
        check(vm["agent_mode"].asBool() && vm["backend"] == "qemu" && vm["hypervisor"] == "soft", "QEMU writeback rescue mode");
        check(vm["cpu_count"] == 1 && vm["memory_mb"] == 320 && vm["prepare_lend_mthp"] == "disabled", "rescue resources");
        check(vm["boot"]["protocol"] == "linux" && vm["boot"]["linux"]["source"] == "manual" &&
            vm["boot"]["linux"]["kernel"] == input.kernel && vm["boot"]["linux"]["initrd"] == input.initrd &&
            vm["boot"]["linux"]["cmdline"] == "console=ttyAMA0 rdinit=/bin/sh panic=-1", "trusted boot assets and UART");
        check(operation_stream == "uart" && operation_device == "/dev/ttyAMA0", "operation console mapping");
        check(vm["disks"].size() == 1 && vm["disks"][0]["path"] == input.disk_path && vm["disks"][0]["bus"] == "virtio" && !vm["disks"][0]["readonly"].asBool(), "registered target disk");
        for (const auto* key : {"networks", "peripherals", "shared_dirs", "extra_options", "environment_variables"})
            check(vm[key].isArray() && vm[key].empty(), "unexpected rescue peripheral or injected options");
        check(!vm["audio_enabled"].asBool() && !vm["rng"].asBool() && !vm["balloon"].asBool() &&
            !vm["hugepages"].asBool() && !vm["screens"]["gpu-0"]["enabled"].asBool() && !vm["screens"]["simplefb"]["enabled"].asBool(), "unexpected rescue devices");
        check(!vm.isMember("password") && json(vm).find("Secret-Not-Projected") == std::string::npos, "VM config leaked secret");
        for (const auto* path : {"relative", "/data/../guest", "/data//guest", "/data/./guest", "/data/"}) {
            auto bad = input; bad.disk_path = path;
            rejected([&] { (void)build_rescue_vm(bad); });
        }
        auto bad = input; bad.name = "../agent";
        rejected([&] { (void)build_rescue_vm(bad); });
        bad = input; bad.kernel = std::string("/data/ker\0nel", 13);
        rejected([&] { (void)build_rescue_vm(bad); });
        std::cout << "Agent typed request, secret lifetime and fixed rescue VM plan contract passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
