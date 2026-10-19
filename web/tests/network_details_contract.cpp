// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/network_details.h"
#include "common/wire.h"
#include "services/context.h"
#include <iostream>
#include <limits>
#include <source_location>
#include <stdexcept>

void require(bool value, const std::source_location& at = std::source_location::current()) {
    if (!value) throw std::runtime_error("Network detail contract failed at line " + std::to_string(at.line()));
}
int main() {
    using namespace droidvm;
    try {
        const auto config = wire::parse(R"({"id":"network","name":"Network","bridge_name":"br0","bridge_type":"linux","uplink_mode":"l3","auto_up":true,"private":"not public"})");
        VmConfigSnapshot vms; vms.revision = "vm-revision";
        vms.document = wire::parse(R"({"vms":[{"id":"vm","name":"VM","networks":[{"network_id":"other"},{"network_id":"network","vlan_id":4095,"mac_address":"02:00:00:00:00:01","secret":"not public"}]}]})");
        const web::NetworkObservation running{"network", "RUNNING", std::numeric_limits<uint64_t>::max(), true};
        const auto live = wire::parse(R"({
            "address_entries":[{"addr":"192.0.2.1/24","family":4,"vlan":0,"bound":true,"source":"configured"}],
            "live_interfaces":[{"name":"tap0","state":"UP"}],
            "pd":[{"vlan":10,"state":"bound","prefix":"2001:db8::/56"}],
            "neighbors":[{"dst":"192.0.2.3","lladdr":"02:00:00:00:00:03","dev":"br0","state":["REACHABLE"]}],
            "dhcp_leases":[{"ip":"192.0.2.3","expires":9223372036854775807},{"ip":"2001:db8::3","expires":"2026-10-19T00:00:00Z","vlan":10}],
            "gvswitch_socket":"/private/control.sock","tools":[{"command":"private"}]
        })");
        const auto view = web::network_detail(config, vms, running, running, live, "net-revision");
        require(view["configurationRevision"] == "net-revision" && view["vmRevision"] == "vm-revision");
        require(view["runtime"]["generation"] == "18446744073709551615");
        require(view["liveState"] == "observed" && view["observationComplete"] == false);
        require(view["addresses"][0]["bound"] == true && view["interfaces"][0]["address"].isNull());
        require(view["leases"][0]["expires"] == "9223372036854775807" && view["leases"][0]["expiresFormat"] == "unix-seconds");
        require(view["leases"][1]["expiresFormat"] == "rfc3339");
        require(view["attachments"].size() == 1 && view["attachments"][0]["slot"].asUInt() == 1 && view["attachments"][0]["vlan"].asInt() == 4095);
        require(!view.isMember("tools") && !view.isMember("gvswitch_socket") && !view["network"].isMember("private") && !view["attachments"][0].isMember("secret"));
        const auto busy = web::network_detail(config, vms, running, running, Json::Value(Json::objectValue), "net-revision");
        require(busy["liveState"] == "busy" && busy["addresses"].isNull() && busy["leases"].isNull());
        auto previous = running; --previous.generation;
        const auto changed = web::network_detail(config, vms, previous, running, live, "net-revision");
        require(changed["liveState"] == "changed" && changed["interfaces"].isNull());
        const web::NetworkObservation failed{"network", "FAILED", 1, true};
        require(web::network_detail(config, vms, failed, failed, live, "net-revision")["liveState"] == "inactive");
        auto excessive = live;
        excessive["dhcp_leases"].resize(4097);
        bool bounded = false;
        try { (void)web::network_detail(config, vms, running, running, excessive, "net-revision"); }
        catch (const ServiceError& error) { bounded = error.code() == ErrorCode::resource_exhausted; }
        require(bounded);
        std::cout << "Network observations, unknown state, exact counters, attachment scope and whitelist contract passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
