// SPDX-License-Identifier: GPL-3.0-or-later
#include "vm_read_model.h"
#include "services/context.h"
#include <array>
#include <algorithm>
#include <set>
#include <string_view>
#include <chrono>
#include <cctype>
#include <map>
#include <optional>
#include <vector>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <ctime>
#include <unistd.h>

namespace droidvm::web {
namespace {
[[noreturn]] void invalid_inventory() { throw ServiceError(ErrorCode::unavailable, "VM inventory cannot be represented"); }
Json::Value configured_quantity(const Json::Value& row, const char* key) {
    const auto& value = row[key];
    // These are reported configured quantities, not usage or inferred runtime
    // defaults. Invalid / missing / unsafe values remain unknown to the client.
    if ((value.type() != Json::intValue && value.type() != Json::uintValue) || !value.isUInt64()) return {};
    const auto number = value.asUInt64();
    if (number == 0 || number > 9007199254740991ULL) return {};
    return value;
}
struct ProcessStat { int64_t parent = 0; uint64_t ticks = 0; };
std::optional<ProcessStat> process_stat(const std::string& pid) {
    std::ifstream input("/proc/" + pid + "/stat");
    std::string line;
    if (!std::getline(input, line)) return {};
    const auto end = line.rfind(')');
    if (end == std::string::npos) return {};
    std::istringstream fields(line.substr(end + 1));
    std::string state;
    ProcessStat result;
    uint64_t skip = 0, user = 0, system = 0;
    fields >> state >> result.parent;
    for (int i = 0; i < 9; ++i) fields >> skip;
    fields >> user >> system;
    if (!fields) return {};
    result.ticks = user + system;
    return result;
}
std::pair<uint64_t, uint64_t> process_io(const std::string& pid) {
    std::ifstream input("/proc/" + pid + "/io");
    std::string key;
    uint64_t value = 0, read = 0, write = 0;
    while (input >> key >> value) {
        if (key == "read_bytes:") read = value;
        else if (key == "write_bytes:") write = value;
    }
    return {read, write};
}
}
Json::Value vm_process_usage(int64_t pid) {
    if (pid <= 0) return {};
    const auto root = std::to_string(pid);
    const auto main = process_stat(root);
    if (!main) return {};
    std::map<int64_t, std::vector<std::string>> children;
    if (auto* directory = opendir("/proc")) {
        while (auto* entry = readdir(directory)) {
            const std::string name = entry->d_name;
            if (name.empty() || !std::all_of(name.begin(), name.end(), [](char c) { return c >= '0' && c <= '9'; })) continue;
            if (const auto stat = process_stat(name)) children[stat->parent].push_back(name);
        }
        closedir(directory);
    }
    uint64_t ticks = 0, read = 0, write = 0;
    std::vector<std::string> pending{root};
    std::set<std::string> seen;
    while (!pending.empty() && seen.size() < 4096) {
        const auto current = pending.back(); pending.pop_back();
        if (!seen.insert(current).second) continue;
        const auto stat = current == root ? main : process_stat(current);
        if (!stat) continue;
        ticks += stat->ticks;
        const auto [r, w] = process_io(current);
        read += r; write += w;
        for (const auto& child : children[std::stoll(current)]) pending.push_back(child);
    }
    uint64_t pages = 0, resident = 0;
    { std::ifstream statm("/proc/" + root + "/statm"); statm >> pages >> resident; }
    const auto hz = sysconf(_SC_CLK_TCK);
    const auto page = sysconf(_SC_PAGESIZE);
    timespec now{};
    clock_gettime(CLOCK_MONOTONIC, &now);
    Json::Value result;
    result["cpuTimeMs"] = std::to_string(hz > 0 ? ticks * 1000 / static_cast<uint64_t>(hz) : 0);
    result["rssBytes"] = std::to_string(resident * static_cast<uint64_t>(page > 0 ? page : 4096));
    result["readBytes"] = std::to_string(read);
    result["writeBytes"] = std::to_string(write);
    result["sampledAtMs"] = std::to_string(static_cast<uint64_t>(now.tv_sec) * 1000 + static_cast<uint64_t>(now.tv_nsec) / 1000000);
    return result;
}
Json::Value vm_snapshot(const Json::Value& inventory, const VmConfigSnapshot* configuration, VmLeaseLookup leases, VmCurrentObservation current, VmUsageLookup usage) {
    if (!inventory.isArray()) invalid_inventory();
    constexpr std::array<std::string_view, 6> states{"STOPPED", "STARTING", "RUNNING", "SUSPENDED", "STOPPING", "REBOOTING"};
    Json::Value result(Json::objectValue);
    auto& items = result["items"] = Json::Value(Json::arrayValue);
    std::set<std::string> ids;
    std::map<std::string, Json::Value> network_leases;
    size_t lease_budget = 65536;
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    for (const auto& row : inventory) {
        if (!row.isObject() || !row["id"].isString() || row["id"].asString().empty() || !row["state"].isString()) invalid_inventory();
        const auto id = row["id"].asString(), state = row["state"].asString();
        if (!ids.insert(id).second || std::find(states.begin(), states.end(), state) == states.end()) invalid_inventory();
        Json::Value view(Json::objectValue);
        view["id"] = id;
        view["name"] = row["name"].isString() && !row["name"].asString().empty() ? row["name"] : Json::Value(id);
        view["state"] = state;
        view["backend"] = row["backend"].isString() && !row["backend"].asString().empty() ? row["backend"] : Json::Value();
        view["cpuCount"] = configured_quantity(row, "cpu_count");
        view["memoryMiB"] = configured_quantity(row, "memory_mb");
        view["uptimeMs"] = Json::Value();
        if ((state == "RUNNING" || state == "SUSPENDED" || state == "STOPPING") && row["runtime_uptime_ms"].isString()) {
            const auto text = row["runtime_uptime_ms"].asString();
            if (!text.empty() && text.size() <= 19 && std::all_of(text.begin(), text.end(), [](char c) { return c >= '0' && c <= '9'; }))
                view["uptimeMs"] = text;
        }
        if (usage && state == "RUNNING" && row["pid"].isInt64() && row["pid"].asInt64() > 0) {
            Json::Value counters;
            try { counters = usage(row["pid"].asInt64()); } catch (const std::exception&) {}
            if (counters.isObject()) view["usage"] = std::move(counters);
        }
        view["ipAddresses"] = Json::Value();
        if (state == "RUNNING" && leases && current && row["runtime_instance"].isString() && row["runtime_revision"].isString() &&
            row["networks"].isArray() && row["networks"].size() <= 64) {
            std::set<std::string> addresses;
            bool observed = false;
            for (const auto& nic : row["networks"]) {
                if (!nic.isObject() || !nic["network_id"].isString() || !nic["mac_address"].isString()) continue;
                const auto network = nic["network_id"].asString();
                auto mac = nic["mac_address"].asString();
                if (network.empty() || network.size() > 128 || mac.size() != 17) continue;
                std::transform(mac.begin(), mac.end(), mac.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                const auto vlan = nic["vlan_id"].isInt() ? nic["vlan_id"].asInt() : 0;
                const auto resolved_vlan = vlan == 4095 ? 0 : vlan;
                auto found = network_leases.find(network);
                if (found == network_leases.end()) {
                    if (network_leases.size() >= 256) continue;
                    Json::Value snapshot;
                    try { snapshot = leases(network); } catch (const std::exception&) {}
                    found = network_leases.emplace(network, std::move(snapshot)).first;
                }
                if (!found->second.isArray() || found->second.size() > 4096) continue;
                if (found->second.size() > lease_budget) continue;
                lease_budget -= found->second.size();
                observed = true;
                for (const auto& lease : found->second) {
                    if (!lease.isObject() || lease["mac"] != mac || !lease["vlan"].isInt() || lease["vlan"].asInt() != resolved_vlan ||
                        !lease["expires"].isInt64() || lease["expires"].asInt64() <= now || !lease["ip"].isString()) continue;
                    const auto ip = lease["ip"].asString();
                    if (!ip.empty() && ip.size() <= 45 && std::all_of(ip.begin(), ip.end(), [](unsigned char c) { return std::isxdigit(c) || c == ':' || c == '.'; }) && addresses.size() < 64)
                        addresses.insert(ip);
                }
            }
            bool same = false;
            try { same = current(id, row["runtime_instance"].asString(), row["runtime_revision"].asString()); } catch (const std::exception&) {}
            if (observed && same) {
                auto& output = view["ipAddresses"] = Json::Value(Json::arrayValue);
                for (const auto& ip : addresses) output.append(ip);
            }
        }
        if (configuration) {
            if (!row["runtime_instance"].isString() || !row["runtime_revision"].isString() ||
                !row["runtime_actions"].isArray() || !row["runtime_uncertain"].isBool()) invalid_inventory();
            auto& control = view["lifecycle"];
            control["instanceId"] = row["runtime_instance"];
            control["revision"] = row["runtime_revision"];
            control["uncertain"] = row["runtime_uncertain"];
            control["configRevision"] = Json::Value();
            for (const auto& definition : configuration->document["vms"]) if (definition["id"] == id) {
                control["configRevision"] = configuration->revision; break;
            }
            auto& actions = control["actions"] = Json::Value(Json::arrayValue);
            for (const auto& action : row["runtime_actions"]) {
                if (action != "start" && action != "stop" && action != "reboot" && action != "suspend" && action != "resume" &&
                    action != "powerbtn" && action != "sleepbtn") invalid_inventory();
                if (action == "start" && control["configRevision"].isNull()) continue;
                actions.append(action);
            }
        }
        items.append(std::move(view));
    }
    return result;
}
}
