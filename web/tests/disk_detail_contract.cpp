// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/resource_catalog.h"
#include "common/wire.h"
#include "services/context.h"
#include <iostream>
#include <source_location>
#include <stdexcept>
void require(bool value, const std::source_location& at = std::source_location::current()) {
    if (!value) throw std::runtime_error("Disk detail contract failed at line " + std::to_string(at.line()));
}
int main() {
    using namespace droidvm;
    try {
        DiskConfigSnapshot disks; disks.revision = "disks";
        disks.document = wire::parse(R"({"disks":[
            {"id":"base","name":"base","path":"/base"},
            {"id":"child","name":"child","path":"/child","parent":"base"},
            {"id":"grandchild","name":"grandchild","path":"/grandchild","parent":"child"},
            {"id":"broken","name":"broken","path":"/broken","parent":"missing"}
        ]})");
        const auto catalog = web::disk_catalog(disks, [](const Json::Value& row) { return row["path"].asString(); }, {"/base", "/child", "/grandchild"}, {"/base", "/child"});
        VmConfigSnapshot vms; vms.revision = "vms";
        vms.document = wire::parse(R"({"vms":[{"id":"vm","name":"VM","disks":[
            {"path":"/base","readonly":true}, {"path":"/grandchild"}, {"path":"/grandchild","readonly":true}, {"path":"/other"}
        ]}]})");
        const auto image = wire::parse(R"({"format":"qcow2","virtual-size":18446744073709551615,"actual-size":0,"encrypted":false,"filename":"/private/fd","backing-filename":"private-header"})");
        const auto base = web::disk_detail(catalog, vms, "base", "ready", image);
        require(base["chain"].size() == 1 && base["chainComplete"].asBool());
        require(base["children"].size() == 1 && base["children"][0]["id"] == "child");
        require(base["attachments"].size() == 3 && base["attachments"][1]["diskId"] == "grandchild");
        require(base["readOnlyRequired"].asBool());
        require(base["inspection"]["virtualBytes"] == "18446744073709551615" && base["inspection"]["allocatedBytes"] == "0");
        require(base["inspection"]["dirty"].isNull() && base["inspection"]["encrypted"] == false);
        require(!base["inspection"].isMember("filename") && !base["inspection"].isMember("backing-filename"));
        require(base["inspection"]["effectiveCompression"].isNull());
        auto declared = image;
        declared["format-specific"]["data"]["compression-type"] = "zlib";
        require(web::disk_detail(catalog, vms, "base", "ready", declared)["inspection"]["effectiveCompression"].isNull());
        require(web::disk_detail(catalog, vms, "base", "ready", declared, "none")["inspection"]["effectiveCompression"] == "none");
        require(web::disk_detail(catalog, vms, "base", "ready", declared, "deflate")["inspection"]["effectiveCompression"] == "deflate");
        require(web::disk_detail(catalog, vms, "base", "ready", declared, "invalid")["inspection"]["effectiveCompression"].isNull());
        require(web::disk_detail(catalog, vms, "base", "busy", declared, "zstd")["inspection"]["effectiveCompression"].isNull());
        const auto leaf = web::disk_detail(catalog, vms, "grandchild", "busy", image);
        require(leaf["chain"].size() == 3 && leaf["chain"][2]["id"] == "base");
        require(leaf["attachments"].size() == 2 && leaf["readOnlyRequired"].asBool());
        require(leaf["inspection"]["format"].isNull() && leaf["inspection"]["virtualBytes"].isNull());
        require(!web::disk_detail(catalog, vms, "broken", "invalid-chain", {})["chainComplete"].asBool());
        auto cycle = catalog;
        cycle["items"][0]["parentId"] = "grandchild";
        require(!web::disk_detail(cycle, vms, "base", "invalid-chain", {})["chainComplete"].asBool());
        require(web::disk_detail(catalog, vms, "base", "ready", wire::parse(R"({"format":"raw","virtual-size":1.5})"))["inspection"]["state"] == "unavailable");
        bool missing = false;
        try { (void)web::disk_detail(catalog, vms, "absent", "ready", image); }
        catch (const ServiceError& error) { missing = error.code() == ErrorCode::not_found; }
        require(missing);
        std::cout << "Disk ancestry, descendant references, read-only rules, exact sizes and unknown-state contract passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
