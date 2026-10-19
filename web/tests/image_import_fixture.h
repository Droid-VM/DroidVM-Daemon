// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "web/image_imports.h"
#include "disk_fixture.h"

// Synthetic image observations and registry only; no host file/tool access.
struct FixtureImageImport : std::enable_shared_from_this<FixtureImageImport> {
    std::mutex mutex;
    unsigned plans = 0, commits = 0;
    std::shared_ptr<FixtureDisks> disks;
    explicit FixtureImageImport(std::shared_ptr<FixtureDisks> value) : disks(std::move(value)) {}
    droidvm::web::ImageImportBindings bindings() {
        const auto self = shared_from_this();
        return {
            [self](const droidvm::CallContext&, const std::string& source, const std::function<bool()>& cancelled) {
                if (cancelled()) throw droidvm::ServiceError(droidvm::ErrorCode::unavailable, "Cancelled fixture preview");
                std::lock_guard lock(self->mutex); ++self->plans;
                Json::Value plan;
                plan["source"] = source; plan["vmRevision"] = "fixture-reference-revision";
                plan["diskRevision"] = "fixture-disk-revision";
                plan["diskId"] = droidvm::random_id(true);
                const auto parent = droidvm::random_id(true);
                auto member = [](const std::string& id, const std::string& path, const std::string& name, Json::Value parent_id, bool existing) {
                    Json::Value row;
                    row["id"] = id; row["path"] = path; row["name"] = name; row["parentId"] = std::move(parent_id);
                    row["existing"] = existing; row["format"] = "qcow2"; row["virtualSizeBytes"] = "9007199254740993";
                    return row;
                };
                if (source == "/fixture/standalone.qcow2") {
                    plan["members"].append(member(plan["diskId"].asString(), source, "standalone.qcow2", Json::Value(), false));
                    plan["attachments"] = Json::Value(Json::arrayValue);
                } else {
                    plan["members"].append(member(plan["diskId"].asString(), source, source.substr(source.find_last_of('/') + 1), parent, false));
                    plan["members"].append(member(parent, "/fixture/import-parent.qcow2", "import-parent.qcow2", "fixture-disk", false));
                    plan["members"].append(member("fixture-disk", "/fixture/registered.qcow2", "测试磁盘.qcow2", Json::Value(), true));
                    plan["attachments"] = droidvm::wire::parse(R"([{"vmId":"native-http-vm","slot":0,"beforePath":"/fixture/registered.qcow2","afterPath":"/fixture/registered.qcow2","beforeReadOnly":false,"afterReadOnly":true}])");
                }
                plan["_files"] = "fixture-image-private-proof";
                return plan;
            },
            [self](const droidvm::CallContext&, const Json::Value& plan, droidvm::TaskControl& control) {
                if (plan["_files"] != "fixture-image-private-proof")
                    throw droidvm::ServiceError(droidvm::ErrorCode::internal, "Lost private image proof");
                if (!control.enter_commit()) return droidvm::TaskCompletion::cancelled();
                std::lock_guard lock(self->mutex); ++self->commits;
                Json::Value receipt;
                receipt["diskId"] = plan["diskId"]; receipt["registered"] = false;
                receipt["registrationUncertain"] = false; receipt["recoveryRequired"] = false; receipt["added"] = 0;
                receipt["private"] = "fixture-image-private-result";
                if (plan["source"] == "/fixture/uncertain.qcow2") {
                    receipt["registrationUncertain"] = true; receipt["recoveryRequired"] = true;
                    return droidvm::TaskCompletion::failure(droidvm::ErrorCode::commit_uncertain, "Synthetic uncertain image registry", receipt);
                }
                std::lock_guard disks_lock(self->disks->mutex);
                unsigned added = 0;
                for (const auto& item : plan["members"]) if (!item["existing"].asBool()) {
                    Json::Value row;
                    row["id"] = item["id"]; row["name"] = item["name"]; row["test_path"] = item["path"];
                    row["parent"] = item["parentId"]; row["format"] = item["format"]; row["size"] = Json::UInt64(9007199254740993ULL);
                    row["compression"] = "zstd";
                    self->disks->added.append(std::move(row));
                    ++added;
                }
                receipt["registered"] = true; receipt["added"] = added;
                return droidvm::TaskCompletion::success(receipt);
            }
        };
    }
    Json::Value stats() {
        std::lock_guard lock(mutex); Json::Value result;
        result["plans"] = plans; result["commits"] = commits; return result;
    }
};
