// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "web/package_exports.h"
#include "web/package_imports.h"
#include "common/identity.h"
#include "common/wire.h"

// Synthetic export receipts only: exercises HTTP/session/tasks, never host files.
inline droidvm::web::PackageExportOperations fixture_package_exports(droidvm::TaskService& tasks) {
    using namespace droidvm;
    return web::package_exports(tasks,
        [](const CallContext&, const std::string& id) {
            if (id != "native-http-vm") throw ServiceError(ErrorCode::not_found, "VM not found");
            Json::Value plan;
            plan["vm_id"] = id; plan["vm_name"] = "原生 HTTP 虚拟机";
            plan["vm_revision"] = "fixture-config";
            plan["disk_revision"] = "fixture-disk-revision";
            plan["network_revision"] = "fixture-network-revision";
            plan["disks"] = Json::Value(Json::arrayValue);
            Json::Value disk; disk["index"] = 0; disk["readonly"] = false;
            disk["path"] = "/fixture/disk.qcow2"; plan["disks"].append(disk);
            return plan;
        },
        [&tasks](const CallContext& caller, const Json::Value& request,
            const pkg::ExportConfirmation& confirmed, const std::string& id) {
            TaskSpec spec{"vm_export", "package", 4096};
            spec.request_id = id; spec.request_signature = random_id(true);
            return tasks.submit(caller, std::move(spec), [request, confirmed](TaskControl& control) {
                if (confirmed.vm_revision != "fixture-config" || confirmed.disk_revision != "fixture-disk-revision"
                    || confirmed.network_revision != "fixture-network-revision")
                    throw ServiceError(ErrorCode::conflict, "Package export configuration changed");
                for (const auto& disk : request["disks"])
                    if (disk.asUInt() != 0) throw ServiceError(ErrorCode::invalid_argument, "Unavailable disk");
                if (!control.enter_commit()) return TaskCompletion::cancelled();
                Json::Value result;
                result["volume_total"] = request["volume_size"].asInt64() == 0 ? 0 : 2;
                return TaskCompletion::success(result);
            });
        });
}

inline droidvm::web::PackageImportOperations fixture_package_imports(droidvm::TaskService& tasks) {
    using namespace droidvm;
    return web::package_imports(tasks,
        [&tasks](const CallContext& caller, const std::string& source, const std::string& id) {
            TaskSpec spec{"package_import_plan", "package", 16384};
            spec.request_id = id; spec.request_signature = random_id(true);
            return tasks.submit(caller, std::move(spec), [source](TaskControl&) {
                auto result = wire::parse(R"({"vm_name":"待导入的虚拟机","app_version":"1.0",
                    "manifest_version":2,"compression":"ZSTD","volume_count":2,
                    "vm_revision":"fixture-config","disk_revision":"fixture-disk-revision",
                    "network_revision":"fixture-network-revision","backend":"qemu","cpu_count":4,
                    "memory_mib":2048,"notes":"包内备注 <script>仅作为文本显示</script>",
                    "disks":[{"name":"系统磁盘.qcow2","size_bytes":"8589934592","attached":true,"readonly":false}],
                    "boots":[],"networks":[{"ref":"network-0","name":"包内网络","bridge_type":"linux",
                    "uplink_mode":"l3","create_allowed":true,"conflict_kind":"",
                    "candidates":[{"id":"fixture-existing-network","name":"现有网络"}]}],
                    "private":"fixture-internal-source-observation"})");
                result["source_path"] = source.ends_with(".001") ? source.substr(0, source.size() - 4) : source;
                return TaskCompletion::success(result);
            });
        },
        [&tasks](const CallContext& caller, const Json::Value& request, const std::string& plan_id, const std::string& id) {
            const auto plan = tasks.find_request(caller, plan_id);
            if (!plan || plan->owner != caller.principal || plan->kind != "package_import_plan"
                || plan->state != TaskState::succeeded)
                throw ServiceError(ErrorCode::conflict, "Preview unavailable");
            TaskSpec spec{"vm_import", "package", 4096};
            spec.request_id = id; spec.request_signature = random_id(true);
            return tasks.submit(caller, std::move(spec), [request](TaskControl& control) {
                const auto& choices = request["network_plan"];
                if (choices.size() != 1 || choices[0]["ref"] != "network-0"
                    || (choices[0]["action"] == "join" && choices[0]["network_id"] != "fixture-existing-network"))
                    throw ServiceError(ErrorCode::invalid_argument, "Invalid network choice");
                if (!control.enter_commit()) return TaskCompletion::cancelled();
                Json::Value result;
                result["registered"] = false; result["registration_uncertain"] = false;
                result["recovery_required"] = false; result["cleanup_complete"] = true;
                result["total"] = 1; result["done"] = 0;
                if (request["target_dir"] == "/fixture/uncertain") {
                    result["registration_uncertain"] = true; result["recovery_required"] = true;
                    result["cleanup_complete"] = false; result["retained_directory"] = "/fixture/uncertain/retained-vm";
                    return TaskCompletion::failure(ErrorCode::commit_uncertain, "Synthetic uncertain commit", result);
                }
                result["registered"] = true; result["done"] = 1; result["vm_id"] = "native-http-vm";
                return TaskCompletion::success(result);
            });
        });
}
