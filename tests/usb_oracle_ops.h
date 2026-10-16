// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
// The usb_* ops of droidvm_config_probe; the Java side is
// migration-tests/.../UsbOracle.java. A RequestError is a row value.
#include "usb/control.h"
#include "usb/device.h"
#include "usb/engine.h"
#include "usb/host.h"
#include "usb/rules.h"
#include "usb/service.h"
#include "store/vm_config.h"
#include <algorithm>
#include <map>
#include <mutex>

namespace droidvm::usb::oracle {
inline TargetExists exists(const Json::Value& test) {
    if (!test["vms"].isArray()) return nullptr;
    const auto vms = test["vms"];
    return [vms](const std::string& vm, const std::optional<std::string>&) {
        for (const auto& id : vms) if (id.asString() == vm) return true;
        return false;
    };
}
inline std::optional<VmState> vm_state(const std::string& name) {
    static const std::map<std::string, VmState> names{{"STOPPED", VmState::stopped}, {"STARTING", VmState::starting},
        {"RUNNING", VmState::running}, {"SUSPENDED", VmState::suspended}, {"STOPPING", VmState::stopping}, {"REBOOTING", VmState::rebooting}};
    auto it = names.find(name);
    return it == names.end() ? std::nullopt : std::optional(it->second);
}
inline std::optional<DeviceState> device_state(const std::string& key) {
    for (auto state : {DeviceState::hostuse, DeviceState::vmuse, DeviceState::idle}) if (key == state_key(state)) return state;
    return std::nullopt;
}
inline void rules(const Json::Value& test, Json::Value& row) {
    try {
        const auto parsed = Rules::from_json(test["rules"], exists(test));
        row["rules"] = parsed.to_json();
        row["enabled"] = parsed.enabled();
        row["empty"] = parsed.is_empty();
    } catch (const RequestError& error) { row["error"] = error.what(); }
}
inline void engine(const Json::Value& test, Json::Value& row) {
    RuleEngine engine;
    engine.set_rules(Rules::from_json(test["rules"], nullptr));
    const auto states = test["states"];
    const auto controllers = test["controllers"];
    StateOf state_of = [states](const std::string& vm) -> std::optional<VmState> {
        if (!states.isMember(vm)) return std::nullopt;
        return vm_state(states[vm].asString());
    };
    HasController has = [controllers](const std::string& vm, const std::optional<std::string>& controller) {
        const auto& list = controllers[vm];
        if (!list.isArray() || list.empty()) return false;
        if (!controller) return true;
        for (const auto& c : list) if (c.isString() && c.asString() == *controller) return true;
        return false;
    };
    for (const auto& op : test["ops"]) {
        const auto name = op[0].asString();
        if (name == "lock") engine.lock(op[1].asString(), op[2].asInt());
        else if (name == "unlock") engine.unlock(op[1].asString());
        else if (name == "fail") engine.mark_failed(op[1].asString(), op[2].asString());
        else if (name == "forget_failures") engine.forget_failures_for(op[1].asString());
        else if (name == "forget") engine.forget(op[1].asString());
        else if (name == "clear_locks") engine.clear_locks();
        else throw std::invalid_argument("engine op");
    }
    std::vector<EngineDevice> devices;
    Json::Value decisions(Json::arrayValue), locked(Json::arrayValue), candidate(Json::arrayValue);
    for (const auto& spec : test["devices"]) {
        const auto state = device_state(spec["state"].asString());
        if (!state) throw std::invalid_argument("device state");
        EngineDevice device{spec["sysfs"].asString(), spec["id"].asString(), spec["port"].asString(), spec["devnum"].asInt(), *state};
        devices.push_back(device);
        const auto decision = engine.decide(device, state_of, has);
        decisions.append(decision ? UsbService::decision_json(*decision) : Json::Value());
        locked.append(engine.is_locked(device.sysfs, device.devnum));
        candidate.append(engine.is_candidate(device));
    }
    Json::Value plan(Json::arrayValue);
    for (const auto& decision : engine.plan(devices, state_of, has)) {
        auto item = UsbService::decision_json(decision);
        item["sysfs"] = decision.device.sysfs;
        item["where"] = decision.where();
        plan.append(std::move(item));
    }
    row["decisions"] = decisions; row["locked"] = locked; row["candidate"] = candidate; row["plan"] = plan;
    if (!test["next"].isNull()) {
        const auto owes = engine.save_owes(Rules::from_json(test["next"], nullptr));
        row["save_owes"] = owes == SaveOwes::nothing ? "NOTHING" : owes == SaveOwes::release ? "RELEASE" : "PASS";
    }
    row["recovers"] = Json::Value(Json::arrayValue);
    row["recovers"].append(engine.recovers_idle_devices(false));
    row["recovers"].append(engine.recovers_idle_devices(true));
}
inline void scan(const Json::Value& test, Json::Value& row) {
    const auto root = test["root"].asString();
    const auto devices = root + "/sys/bus/usb/devices", dev = root + "/dev/bus/usb";
    row["devices"] = Json::Value(Json::arrayValue);
    for (const auto& device : scan_devices(devices, dev)) {
        auto item = device.to_json();
        item["hub"] = device.is_hub();
        item["authorized"] = device.authorized;
        row["devices"].append(std::move(item));
    }
    row["read"] = Json::Value(Json::arrayValue);
    for (const auto& name : test["read"]) {
        Json::Value item(Json::objectValue);
        try { item["device"] = read_device(devices + "/" + name.asString(), dev).to_json(); }
        catch (const std::exception& error) { item["io_error"] = error.what(); }
        row["read"].append(std::move(item));
    }
}
inline void probe(const Json::Value& test, Json::Value& row) {
    Json::Value writes(Json::arrayValue);
    Probe probe(test["root"].asString() + "/sys/bus/usb/devices", [&](const std::string& name) { writes.append(name); },
                std::chrono::milliseconds(50), std::chrono::milliseconds(10), nullptr);
    Json::Value results(Json::arrayValue);
    for (const auto& call : test["calls"]) {
        const auto name = call[0].asString(), arg = call[1].asString();
        if (name == "interfacesOf") {
            Json::Value list(Json::arrayValue);
            for (const auto& i : probe.interfaces_of(arg)) list.append(i);
            results.append(list);
        } else if (name == "isConfigured") results.append(probe.is_configured(arg));
        else if (name == "driverOf") results.append(probe.driver_of(arg));
        else if (name == "probeDevice") results.append(probe.probe_device(arg));
        else if (name == "probeInterfaces") results.append(probe.probe_interfaces(arg));
        else if (name == "giveToHost") results.append(probe.give_to_host(arg));
        else if (name == "configureForVm") results.append(probe.configure_for_vm(arg));
        else throw std::invalid_argument("probe call");
    }
    row["results"] = results;
    row["writes"] = writes;
}
inline void uevent(const Json::Value& test, Json::Value& row) {
    std::string message;
    for (const auto& field : test["fields"]) { message += field.asString(); message.push_back('\0'); }
    const auto event = Uevent::parse(message);
    if (!event) { row["event"] = Json::Value(); return; }
    Json::Value out(Json::objectValue);
    out["action"] = event->action; out["name"] = event->name; out["devtype"] = event->devtype; out["driver"] = event->driver;
    out["driver_change"] = event->driver_change();
    out["text"] = event->text();
    row["event"] = out;
}
inline void control(const Json::Value& test, Json::Value& row) {
    const auto kind = test["kind"].asString();
    const auto text = test["text"].isString() ? test["text"].asString() : std::string();
    try {
        if (kind == "ok_port") row["port"] = parse_ok_port(text);
        else if (kind == "list") {
            Json::Value entries(Json::arrayValue);
            for (const auto& entry : parse_list(text)) {
                Json::Value item(Json::objectValue);
                item["port"] = entry.port; item["vid"] = entry.vid; item["pid"] = entry.pid;
                entries.append(std::move(item));
            }
            row["entries"] = std::move(entries);
        } else if (kind == "first_error") {
            const auto line = first_error_line(text);
            row["line"] = line ? Json::Value(*line) : Json::Value();
        } else if (kind == "failure_message") {
            row["message"] = attach_failure_message(test["token"].asString(), test["stderr"].asString(), test["vmm_log"].asString());
        } else if (kind == "require_output") {
            require_output(text, test["stderr"].asString());
            row["passed"] = true;
        } else throw std::invalid_argument("control kind");
    } catch (const ControlRefused& error) { row["token"] = error.token; }
    catch (const VmmUnreachable& error) { row["unreachable"] = error.what(); }
    catch (const ControlIoError& error) { row["io_error"] = error.what(); }
}
inline void leftovers(const Json::Value& test, Json::Value& row) {
    Leftovers left;
    Json::Value results(Json::arrayValue);
    const auto pairs = [](const std::vector<std::pair<std::string, std::string>>& rows) {
        Json::Value out(Json::arrayValue);
        for (const auto& [a, b] : rows) { Json::Value p(Json::arrayValue); p.append(a); p.append(b); out.append(p); }
        return out;
    };
    const auto names = [](const std::vector<std::string>& list) {
        Json::Value out(Json::arrayValue);
        for (const auto& n : list) out.append(n);
        return out;
    };
    for (const auto& op : test["ops"]) {
        const auto name = op[0].asString();
        if (name == "leave") { left.leave(op[1].asString(), op[2].asString()); results.append(Json::Value()); }
        else if (name == "contains") results.append(left.contains(op[1].asString()));
        else if (name == "left_by") results.append(names(left.left_by(op[1].asString())));
        else if (name == "take") {
            std::vector<std::string> list;
            for (const auto& n : op[1]) list.push_back(n.asString());
            results.append(pairs(left.take(list)));
        } else if (name == "scan") {
            std::map<std::string, std::string> drivers;
            for (const auto& key : op[1].getMemberNames()) drivers[key] = op[1][key].asString();
            const auto found = left.scan(drivers);
            Json::Value out(Json::objectValue);
            out["free"] = names(found.free);
            out["reclaimed"] = pairs(found.reclaimed);
            results.append(out);
        } else if (name == "forget_device") results.append(names(left.forget_device(op[1].asString())));
        else if (name == "size") results.append(static_cast<Json::UInt64>(left.size()));
        else if (name == "device_of") results.append(Leftovers::device_of(op[1].asString()));
        else throw std::invalid_argument("leftovers op");
    }
    row["results"] = results;
}

// The fixture's VMs; sockets exist only while the attachments are filed,
// because the Java oracle's VMs have no backend instance.
struct FakeVms : UsbVms {
    mutable std::mutex mutex;
    std::vector<UsbVm> vms;
    bool sockets = true;
    std::optional<UsbVm> find(const std::string& id) const override {
        std::string lowered = id;
        for (auto& c : lowered) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        std::lock_guard lock(mutex);
        for (auto vm : vms) if (vm.id == lowered) { if (!sockets) vm.control_socket.reset(); return vm; }
        return std::nullopt;
    }
    std::vector<UsbVm> list() const override { std::lock_guard lock(mutex); return vms; }
};
struct FakeControl : UsbControl {
    int port = 1;
    int attach(const std::string&, const std::string&) override { return port; }
    int detach(const std::string&, int p) override { return p; }
    std::vector<ListEntry> list(const std::string&) override { return {}; }
    bool ready(const std::string&) override { return true; }
};
struct NoWrites : SysfsWriter {
    std::string write(const std::string&, std::string_view) override { return {}; }
};
inline void handlers(const Json::Value& test, Json::Value& row) {
    const auto root = test["root"].asString();
    FakeVms vms;
    for (const auto& spec : test["vm_list"]) {
        UsbVm vm;
        vm.id = spec["id"].asString();
        vm.name = spec["name"].asString();
        const auto state = vm_state(spec["state"].asString());
        if (!state) throw std::invalid_argument("vm state");
        vm.state = *state;
        auto config = spec["config"];
        config["id"] = vm.id; config["name"] = vm.name;
        vm.config = config::migrate_vm(config);
        vm.control_socket = "/dev/null/" + vm.name + ".sock";
        vms.vms.push_back(std::move(vm));
    }
    FakeControl control;
    UsbOptions options;
    options.sys_root = test["real_sysfs"].asBool() ? "/sys" : root + "/sys";
    options.dev_root = root + "/dev/bus/usb";
    options.files_dir = root + "/files";
    options.vms = &vms;
    options.control = &control;
    options.writer = std::make_shared<NoWrites>();
    options.timing.interfaces_timeout = std::chrono::milliseconds(50);
    options.timing.interfaces_poll = std::chrono::milliseconds(10);
    UsbService service(std::move(options));
    service.load_rules();
    for (const auto& a : test["attachments"]) {
        control.port = a["port"].asInt();
        Json::Value params;
        params["vm_id"] = a["vm"]; params["device"] = a["sysfs"];
        service.usb_attach(params);
    }
    { std::lock_guard lock(vms.mutex); vms.sockets = false; }
    Json::Value results(Json::arrayValue);
    for (const auto& call : test["calls"]) {
        const auto command = call[0].asString();
        const auto& params = call[1];
        Json::Value out(Json::objectValue);
        try {
            if (command == "usb_attach") out["result"] = service.usb_attach(params);
            else if (command == "usb_detach") out["result"] = service.usb_detach(params);
            else if (command == "usb_host_list") out["result"] = service.usb_host_list(params);
            else if (command == "usb_rules_get") out["result"] = service.usb_rules_get(params);
            else if (command == "usb_rules_set") out["result"] = service.usb_rules_set(params);
            else if (command == "usb_rules_test") out["result"] = service.usb_rules_test(params);
            else if (command == "usb_set_target") out["result"] = service.usb_set_target(params);
            else if (command == "usb_vm_list") out["result"] = service.usb_vm_list(params);
            else throw std::invalid_argument("command");
        } catch (const RequestError& error) { out["error"] = error.what(); }
        catch (const std::exception&) { out["internal"] = true; }
        results.append(std::move(out));
    }
    row["results"] = results;
}
// True when [test] was a usb_* op and [row] is filled.
inline bool evaluate(const Json::Value& test, Json::Value& row) {
    const auto op = test["op"].asString();
    if (op == "usb_rules") rules(test, row);
    else if (op == "usb_engine") engine(test, row);
    else if (op == "usb_scan") scan(test, row);
    else if (op == "usb_probe") probe(test, row);
    else if (op == "usb_uevent") uevent(test, row);
    else if (op == "usb_control") control(test, row);
    else if (op == "usb_leftovers") leftovers(test, row);
    else if (op == "usb_handlers") handlers(test, row);
    else return false;
    row["status"] = "ok";
    return true;
}
}
