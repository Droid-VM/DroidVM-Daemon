// SPDX-License-Identifier: GPL-3.0-or-later
#include "store/network_config.h"
#include "store/vm_config.h"
#include "vm/boot_plan.h"
#include "vm/nic.h"
#include "store/json_file.h"
#include "common/wire.h"
#include "network/helper_config.h"
#include "vm/crosvm_command.h"
#include "vm/host_facts.h"
#include <sys/stat.h>
#include <fstream>
#include <iostream>

namespace {
// Fixture shape: see vm/crosvm_command.h.
std::optional<std::string> text(const Json::Value& value, const char* key) {
    if (!value.isObject() || !value[key].isString()) return std::nullopt;
    return value[key].asString();
}
void set(const Json::Value& value, const char* key, bool& out) { if (value.isObject() && value[key].isBool()) out = value[key].asBool(); }
void set(const Json::Value& value, const char* key, std::string& out) { if (auto v = text(value, key)) out = *v; }
template <typename T> void set(const Json::Value& value, const char* key, T& out) { if (value.isObject() && value[key].isIntegral()) out = static_cast<T>(value[key].asInt64()); }
droidvm::vm::CrosvmRun crosvm_run(const Json::Value& value) {
    droidvm::vm::CrosvmRun run;
    run.control_socket_path = text(value, "control_socket_path");
    run.gpu_cgroup_path = text(value, "gpu_cgroup_path");
    if (value.isObject() && value["serials"].isArray()) for (const auto& row : value["serials"]) {
        droidvm::vm::SerialRun serial;
        if (row.isObject() && row["pipe_output_fd"].isIntegral() && row["pipe_input_fd"].isIntegral())
            serial.pipe = std::pair{row["pipe_output_fd"].asInt(), row["pipe_input_fd"].asInt()};
        serial.acm_dev_path = text(row, "acm_dev_path");
        run.serials.push_back(std::move(serial));
    }
    if (value.isObject() && value["vnc"].isObject()) for (const auto& id : value["vnc"].getMemberNames()) {
        const auto& row = value["vnc"][id];
        auto& vnc = run.vnc[id];
        vnc.host = text(row, "host");
        vnc.password = text(row, "password");
        if (row.isObject() && row["port"].isIntegral()) vnc.port = row["port"].asInt64();
    }
    return run;
}
droidvm::vm::BootPlan crosvm_boot(const Json::Value& value) {
    droidvm::vm::BootPlan boot;
    set(value, "uefi", boot.uefi); set(value, "firmware", boot.firmware); set(value, "vars", boot.vars);
    set(value, "vars_enabled", boot.vars_enabled); set(value, "kernel", boot.kernel);
    set(value, "initrd", boot.initrd); set(value, "cmdline", boot.cmdline);
    return boot;
}
droidvm::vm::HostFacts crosvm_host(const Json::Value& value) {
    droidvm::vm::HostFacts host;
    set(value, "data_dir", host.data_dir);
    set(value, "has_kvm", host.has_kvm); set(value, "has_gunyah", host.has_gunyah); set(value, "has_gzvm", host.has_gzvm);
    host.soc_name = text(value, "soc_name");
    set(value, "app_uid", host.app_uid);
    if (value.isObject() && value["app_gids"].isArray()) {
        host.app_gids.emplace();
        for (const auto& gid : value["app_gids"]) host.app_gids->push_back(gid.asInt());
    }
    if (value.isObject() && value["cpu_cores"].isArray()) for (const auto& row : value["cpu_cores"]) {
        droidvm::vm::CpuCore core;
        set(row, "index", core.index); set(row, "capacity", core.capacity);
        host.cpu_cores.push_back(core);
    }
    set(value, "pflash_vars_size", host.pflash_vars_size);
    set(value, "android_release", host.android_release);
    set(value, "strace_prebuilt_exists", host.strace_prebuilt_exists);
    host.strace_in_path = text(value, "strace_in_path");
    set(value, "optimize_sdcard", host.optimize_sdcard);
    set(value, "turnip_exists", host.turnip_exists);
    host.system_vulkan_hal = text(value, "system_vulkan_hal");
    set(value, "viosnd_dump_exists", host.viosnd_dump_exists);
    return host;
}
}

int main(int argc, char** argv) {
    try {
        if (argc != 2) throw std::runtime_error("expected fixture path");
        std::ifstream input(argv[1]);
        std::string text((std::istreambuf_iterator<char>(input)), {});
        if (!input || text.size() > (4u << 20)) throw std::runtime_error("read fixtures");
        const auto fixtures = droidvm::wire::parse(text);
        Json::Value report(Json::arrayValue);
        for (const auto& test : fixtures) {
            Json::Value row;
            row["name"] = test["name"];
            try {
                auto value = test["config"];
                if (test["op"].asString() == "nic") {
                    std::vector<std::string> dropped;
                    auto sane = droidvm::vm::sanitize_nic(test["nic"], test["network"], dropped);
                    row["dropped"] = Json::Value(Json::arrayValue);
                    for (const auto& text : dropped) row["dropped"].append(text);
                    row["sanitized"] = sane;
                    try { droidvm::vm::validate_nic(sane, test["network"]); row["valid"] = true; }
                    catch (const std::invalid_argument& error) { row["valid"] = false; row["validate_message"] = error.what(); }
                    row["validated"] = sane;
                    row["status"] = "ok";
                    report.append(row); continue;
                }
                if (test["op"].asString() == "boot") {
                    auto config = droidvm::config::migrate_vm(value);
                    std::optional<std::string> entry;
                    if (test["override"].isString()) entry = test["override"].asString();
                    const auto plan = droidvm::vm::resolve_boot(config, entry, {"/data/data/" "cn.classfun.droidvm" "/bin/lbx", "/data/local/tmp/droidvm-boot-cache-unused"});
                    Json::Value out;
                    out["uefi"] = plan.uefi; out["firmware"] = plan.firmware; out["vars"] = plan.vars; out["varsEnabled"] = plan.vars_enabled;
                    out["kernel"] = plan.kernel; out["initrd"] = plan.initrd; out["cmdline"] = plan.cmdline;
                    out["entryTitle"] = plan.entry_title ? Json::Value(*plan.entry_title) : Json::Value();
                    out["entryFallback"] = plan.entry_fallback;
                    row["plan"] = out; row["config"] = config; row["status"] = "ok";
                    report.append(row); continue;
                }
                if (test["op"].asString() == "vm") {
                    row["config"] = droidvm::config::migrate_vm(value);
                    row["reloaded"] = droidvm::config::migrate_vm(droidvm::wire::parse(droidvm::config::encode_json(row["config"])));
                    row["status"] = "ok";
                    report.append(row); continue;
                }
                if (test["op"].asString() == "gvswitch") {
                    row["helper"] = droidvm::network::gvswitch_config(value);
                    row["status"] = "ok";
                    report.append(row); continue;
                }
                if (test["op"].asString() == "crosvm") {
                    const auto boot = crosvm_boot(test["boot"]);
                    auto host = crosvm_host(test["host"]);
                    if (test["host"] == "probe") {
                        // The real host, read the way the Java oracle reads it as root.
                        const std::string data = "/data/data/cn.classfun.droidvm";
                        struct stat owner{};
                        stat(data.c_str(), &owner);
                        host = droidvm::vm::probe_host({owner.st_uid, data + "/run/app-gids",
                            droidvm::config::boolean(test["app_config"], "optimize_sdcard", true),
                            boot.vars.empty() ? droidvm::vm::edk2_vars() : boot.vars});
                    }
                    auto launch = droidvm::vm::crosvm_command(droidvm::config::migrate_vm(value), crosvm_run(test["run"]), boot, host);
                    // Only prepare_process fixtures run the legacy LD_* setup (it also drops caches).
                    if (!test["prepare_process"].asBool())
                        if (launch.env.size() >= 2 && launch.env[0].first == "LD_PRELOAD" && launch.env[1].first == "LD_LIBRARY_PATH")
                            launch.env.erase(launch.env.begin(), launch.env.begin() + 2);
                    row["status"] = "ok";
                    row["argv"] = Json::Value(Json::arrayValue);
                    for (const auto& arg : launch.argv) row["argv"].append(arg);
                    row["env"] = Json::Value(Json::arrayValue);
                    for (const auto& [key, val] : launch.env) {
                        Json::Value pair(Json::arrayValue);
                        pair.append(key); pair.append(val);
                        row["env"].append(std::move(pair));
                    }
                    report.append(row); continue;
                }
                if (test["op"].asString() == "default_vlan") value = droidvm::config::default_vlan(test["vlan_id"].asInt());
                else {
                    if (test["op"].asString() == "migrate") {
                        auto migrated = droidvm::config::migrate_network(value);
                        if (!migrated) { row["status"] = "unsupported"; report.append(row); continue; }
                        value = std::move(*migrated);
                    }
                    droidvm::config::validate_network(value);
                    row["view"] = droidvm::config::network_view(value);
                    try {
                        auto reloaded = droidvm::wire::parse(droidvm::config::encode_json(value));
                        droidvm::config::validate_network(reloaded);
                        row["roundtrip_status"] = "ok";
                    } catch (const std::exception& error) {
                        row["roundtrip_status"] = "error";
                        row["roundtrip_message"] = error.what();
                    }
                }
                row["status"] = "ok";
                row["config"] = value;
            } catch (const std::exception& error) {
                row["status"] = "error";
                row["message"] = error.what();
            }
            report.append(row);
        }
        std::cout << droidvm::config::encode_json(report) << std::endl;
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << std::endl; return 1; }
}
