// SPDX-License-Identifier: GPL-3.0-or-later
#include "pd_state.h"
#include "common/wire.h"
#include "services/context.h"
#include "store/network_config.h"
#include <set>

namespace droidvm::network {
void PdState::reset(std::map<int, std::string> devices) {
    for (const auto& [id, name] : devices) {
        if (id < 0 || id > 4094) throw ServiceError(ErrorCode::invalid_argument, "invalid PD VLAN");
        Netbox::interface_name(name);
    }
    devices_ = std::move(devices); snapshot_ = {}; dirty_ = true;
}
PdAddresses PdState::parse(const Json::Value& status) const {
    auto invalid = [] { throw ServiceError(ErrorCode::io_error, "invalid or incomplete PD status snapshot"); };
    if (!status.isObject() || !status["ifaces"].isArray()) invalid();
    std::set<int> seen; PdAddresses addresses;
    for (const auto& row : status["ifaces"]) {
        if (!row.isObject() || !row["name"].isString() || !row["tag"].isString()) invalid();
        for (const auto& [id, name] : devices_) if (row["name"] == name || row["tag"] == std::to_string(id)) {
            if (row["name"] != name || row["tag"] != std::to_string(id) || !seen.insert(id).second) invalid();
            for (const char* key : {"pd_address", "pd_prefix"})
                if (row.isMember(key) && !row[key].isString()) invalid();
            // Current helpers report only pd_prefix; the router address is its
            // base OR the configured "::1" suffix (helper composePD).
            const auto address = row.get("pd_address", "").asString(), delegated = row.get("pd_prefix", "").asString();
            try {
                if (!address.empty()) {
                    const auto prefix = config::NetworkPrefix::parse(address, true);
                    addresses[id] = prefix.address() + "/" + std::to_string(prefix.prefix());
                } else if (!delegated.empty()) {
                    const auto prefix = config::NetworkPrefix::parse(delegated, true);
                    if (prefix.prefix() > 127) invalid();
                    addresses[id] = prefix.address_at(1) + "/" + std::to_string(prefix.prefix());
                }
            } catch (const std::invalid_argument&) { invalid(); }
        }
    }
    if (seen.size() != devices_.size()) invalid();
    return addresses;
}
PdSnapshot PdState::poll(const ProcessOutput& output, const std::function<Json::Value()>& fetch, bool force) {
    if (output.status.generation < snapshot_.generation) return snapshot_;
    if (!output.status.generation || !output.status.running) {
        snapshot_.addresses.clear(); dirty_ = true;
        throw ServiceError(ErrorCode::unavailable, "PD helper is not running");
    }
    if (output.status.generation != snapshot_.generation) {
        snapshot_ = {output.status.generation, {}}; dirty_ = true;
    }
    dirty_ = dirty_ || force || output.resync_required || output.dropped;
    for (const auto& line : output.lines) {
        if (line.generation != snapshot_.generation || line.stream != ProcessStream::output) continue;
        if (line.truncated || line.text.size() > ManagedProcess::line_limit) { dirty_ = true; continue; }
        const auto first = line.text.find_first_not_of(" \t\r\n");
        if (first == std::string::npos || line.text[first] != '{') continue;
        try {
            const auto event = wire::parse(line.text);
            if (!event.isObject() || !event["event"].isString()) { dirty_ = true; continue; }
            if (event["event"] == "pd_prefix" || event["event"] == "pd_lost") dirty_ = true;
        } catch (const std::exception&) { dirty_ = true; }
    }
    if (devices_.empty()) { snapshot_.addresses.clear(); dirty_ = false; return snapshot_; }
    if (dirty_) {
        // Fetch/parse failures retain dirty=true and never publish an empty
        // success. A later call retries even though the mailbox was drained.
        auto addresses = parse(fetch());
        snapshot_.addresses = std::move(addresses); dirty_ = false;
    }
    return snapshot_;
}
}
