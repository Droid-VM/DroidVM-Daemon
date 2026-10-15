// SPDX-License-Identifier: GPL-3.0-or-later
#include "store/network_config.h"
#include "store/json_file.h"
#include "common/wire.h"
#include "network/helper_config.h"
#include <fstream>
#include <iostream>

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
                if (test["op"].asString() == "gvswitch") {
                    row["helper"] = droidvm::network::gvswitch_config(value);
                    row["status"] = "ok";
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
