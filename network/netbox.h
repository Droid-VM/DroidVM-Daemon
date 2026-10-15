// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "runtime/child.h"
#include "link_attributes.h"
#include <json/json.h>

namespace droidvm::network {
// Blocking operations: invoke only from a service worker. The binary is the
// existing app-data/bin/netbox; never search PATH or invoke an OEM shell tool.
class Netbox {
public:
    explicit Netbox(std::string executable, std::chrono::milliseconds timeout = std::chrono::seconds(10),
                    size_t capture_bytes = 1u << 20);
    static void interface_name(const std::string& name);
    void add_bridge(const std::string& name) const;
    void add_vlan(const std::string& parent, const std::string& name, int vid) const;
    void add_tap(const std::string& name) const;
    void delete_link(const std::string& name) const;
    void state(const std::string& name, bool up) const;
    void master(const std::string& name, const std::string& bridge) const;
    void nomaster(const std::string& name) const;
    void mac(const std::string& name, const std::string& address) const;
    void stp(const std::string& name, bool on) const;
    void isolated(const std::string& name, bool on) const;
    void locked(const std::string& name, bool on) const;
    void address(const std::string& name, const std::string& cidr, bool add) const;
    void route(const std::string& name, const std::string& destination, uint32_t table, bool v6) const;
    void rule(const std::string& name, uint32_t table, uint32_t priority, bool v6, bool add) const;
    void fdb(const std::string& name, const std::string& address) const;
    Json::Value links(const std::string& master = {}, bool bridges_only = false) const;
    Json::Value addresses(const std::string& name = {}, std::optional<uint32_t> metric = {}) const;
    Json::Value neighbors(const std::string& name) const;
    Json::Value rules(bool v6) const;
    Json::Value host_ips(const std::vector<std::string>& prefixes, std::optional<uint32_t> excluded_metric = {}) const;
    ChildOptions monitor(const std::vector<std::string>& prefixes, std::optional<uint32_t> excluded_metric = {}) const;
private:
    std::string executable_;
    std::chrono::milliseconds timeout_;
    size_t capture_bytes_;
    ChildOptions command(std::vector<std::string> args) const;
    std::string run(std::vector<std::string> args) const;
    Json::Value query(std::vector<std::string> args, bool object = false) const;
    void toggle(const std::string& name, bool on, const char* operation, BridgeFlag flag) const;
};
}
