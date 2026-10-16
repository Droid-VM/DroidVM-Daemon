// SPDX-License-Identifier: GPL-3.0-or-later
#include "usb/service.h"
#include "store/network_config.h"
#include "store/vm_config.h"
#include <algorithm>
#include <thread>

namespace droidvm::usb {
namespace {
const std::vector<const char*> peripheral_types{"VIRTIO_SOUND", "INTEL_HDA", "VIRTIO_CAMERA", "XHCI_USB"};
Json::Value text_or_null(const std::optional<std::string>& value) { return value ? Json::Value(*value) : Json::Value(); }
std::string strip(std::string path) {
    while (path.size() > 1 && path.back() == '/') path.pop_back();
    return path;
}
std::string ms(std::chrono::milliseconds value) { return std::to_string(value.count()); }
// String.hashCode, then HashMap.hash.
uint32_t java_hash(const std::string& text) {
    uint32_t hash = 0;
    for (unsigned char c : text) hash = 31 * hash + c;
    return hash ^ (hash >> 16);
}
}
std::optional<std::string> find_controller(const Json::Value& config, const std::optional<std::string>& wanted) {
    const auto& rows = config::member(config, "peripherals");
    if (!rows.isArray()) return std::nullopt;
    std::optional<std::string> first;
    for (const auto& row : rows) {
        if (config::java_enum(row, "type", "VIRTIO_SOUND", peripheral_types) != "XHCI_USB") continue;
        const auto id = config::string(row, "id");
        if (!wanted) return id;
        if (id == *wanted) return id;
    }
    return std::nullopt;
}

UsbService::UsbService(UsbOptions options)
    : options_(std::move(options)),
      devices_(strip(options_.sys_root) + "/bus/usb/devices"), drivers_(strip(options_.sys_root) + "/bus/usb/drivers"),
      probe_path_(strip(options_.sys_root) + "/bus/usb/drivers_probe"), autoprobe_path_(strip(options_.sys_root) + "/bus/usb/drivers_autoprobe"),
      rules_file_(options_.files_dir, [this](const char* level, const std::string& message) { log(level, message); }),
      writer_(options_.writer ? options_.writer : std::make_shared<SysfsWriter>()),
      probe_(devices_, [this](const std::string& name) { drivers_probe(name); }, options_.timing.interfaces_timeout,
             options_.timing.interfaces_poll, [this] { return worker_.interrupted(); }) {}
UsbService::~UsbService() {
    // Workers first: their tasks use every member below them.
    if (options_.watch) options_.watch->stop();
    inventory_worker_.shutdown(std::chrono::milliseconds(0));
    worker_.shutdown(std::chrono::milliseconds(0));
}

void UsbService::put_attachment(Attachment attachment) {
    const auto sysfs = attachment.sysfs;
    if (!attachments_.contains(sysfs)) {
        attach_order_[sysfs] = attach_sequence_++;
        if (attachments_.size() + 1 > attach_capacity_ / 4 * 3) attach_capacity_ *= 2;
    }
    attachments_[sysfs] = std::move(attachment);
}
void UsbService::erase_attachment(const std::string& sysfs) {
    attachments_.erase(sysfs);
    attach_order_.erase(sysfs);
}
std::vector<UsbService::Attachment> UsbService::ordered_attachments() const {
    std::vector<std::pair<std::pair<uint32_t, uint64_t>, const Attachment*>> rows;
    for (const auto& [sysfs, attachment] : attachments_)
        rows.push_back({{java_hash(sysfs) & (attach_capacity_ - 1), attach_order_.at(sysfs)}, &attachment});
    std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
    std::vector<Attachment> out;
    for (const auto& row : rows) out.push_back(*row.second);
    return out;
}
std::optional<UsbVm> UsbService::find_vm(const std::string& id) const {
    return options_.vms ? options_.vms->find(id) : std::nullopt;
}
std::optional<VmState> UsbService::state_of(const std::string& vm) const {
    auto found = find_vm(vm);
    return found ? std::optional(found->state) : std::nullopt;
}
bool UsbService::vm_has_controller(const std::string& vm, const std::optional<std::string>& controller) const {
    auto found = find_vm(vm);
    return found && find_controller(found->config, controller).has_value();
}
Scheduler UsbService::scheduler() {
    return [this](std::function<void()> task, std::chrono::milliseconds delay) { schedule(std::move(task), delay); };
}
void UsbService::schedule(std::function<void()> task, std::chrono::milliseconds delay) {
    if (!worker_.schedule(std::move(task), delay)) log("I", "USB rules task dropped: shutting down");
}
bool UsbService::settle(std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    // A rescan can queue manager work and a pass can rescan: settle both twice.
    for (int round = 0; round < 3; ++round) {
        const auto left = [&] { return std::max(std::chrono::milliseconds(0), std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now())); };
        if (!inventory_worker_.wait_idle(left()) || !worker_.wait_idle(left())) return false;
    }
    return true;
}

// --- UsbHostInventory ---
std::vector<HostDevice> UsbService::scan() const {
    return scan_devices(devices_, options_.dev_root, [this](const std::string& message) { log("W", message); });
}
std::vector<HostDevice> UsbService::rescan_now() {
    bool buses;
    { std::lock_guard lock(watch_mutex_); buses = std::exchange(buses_moved_, false); }
    Diff diff;
    {
        std::lock_guard lock(rescan_mutex_);
        diff = Diff::between(snapshot_, scan());
        snapshot_ = diff.all;
    }
    bool listening;
    { std::lock_guard lock(watch_mutex_); listening = watching_; }
    if (buses && listening) {
        try { schedule_auto_attach("controller"); } catch (const std::exception& error) { log("W", std::string("USB bus listener failed: ") + error.what()); }
    }
    if (diff.empty() || !listening) return diff.all;
    try { on_inventory_changed(diff); } catch (const std::exception& error) { log("W", std::string("USB inventory listener failed: ") + error.what()); }
    return diff.all;
}
void UsbService::schedule_rescan(bool buses_moved) {
    std::lock_guard lock(watch_mutex_);
    if (buses_moved) buses_moved_ = true;
    if (pending_rescan_) *pending_rescan_ = true;
    pending_rescan_ = std::make_shared<std::atomic<bool>>(false);
    if (!inventory_worker_.schedule([this] {
            try { rescan_now(); } catch (const std::exception& error) { log("W", std::string("USB inventory rescan failed: ") + error.what()); }
        }, options_.timing.quiet_period, pending_rescan_))
        pending_rescan_.reset();
}

// --- start / shutdown ---
void UsbService::load_rules() {
    auto rules = rules_file_.load();
    std::lock_guard lock(lock_);
    engine_.set_rules(std::move(rules));
}
void UsbService::start() {
    try {
        load_rules();
        bool enabled;
        { std::lock_guard lock(lock_); enabled = engine_.rules_enabled(); started_ = true; }
        // Written either way: the flag outlives this process.
        set_autoprobe(!enabled);
        try {
            size_t present;
            { std::lock_guard lock(rescan_mutex_); snapshot_ = scan(); present = snapshot_.size(); }
            { std::lock_guard lock(watch_mutex_); watching_ = true; }
            if (options_.watch) options_.watch->start([this](const WatchEvent& event) {
                if (event.uevent && event.uevent->driver_change()) log("D", "uevent " + event.uevent->text());
                schedule_rescan(event.buses_changed);
            });
            log("I", "Watching " + options_.dev_root + " (" + std::to_string(present) + " device(s) present)");
            std::vector<HostDevice> devices;
            { std::lock_guard lock(rescan_mutex_); devices = snapshot_; }
            std::string summary;
            for (const auto& device : devices) summary += (summary.empty() ? "" : ", ") + device.vid + ":" + device.pid + " " + device.sysfs;
            log("I", "Host USB devices: " + std::to_string(devices.size()) + " [" + summary + "]");
        } catch (const std::exception& error) {
            log("W", std::string("Failed to start the USB host inventory: ") + error.what());
        }
        auto migrated = authorize_what_an_older_build_hid();
        if (options_.vms) for (const auto& vm : options_.vms->list()) if (vm.state == VmState::running) queue_auto_attach_when_ready(vm);
        // The one pass that also runs with the switch off: it repairs what a
        // killed daemon or an unfinished release left idle.
        schedule([this, migrated] { await_interfaces(migrated); run_pass_quietly("start", true); });
    } catch (const std::exception& error) {
        log("W", std::string("usb: manager failed to start: ") + error.what());
    }
}
void UsbService::shutdown() {
    bool started;
    { std::lock_guard lock(lock_); started = started_; if (shut_down_) return; shut_down_ = true; }
    // The gate first: the host is owed it back whatever else happens.
    if (started) set_autoprobe(true);
    try { if (options_.watch) options_.watch->stop(); } catch (const std::exception& error) { log("W", std::string("Failed to stop the USB host inventory: ") + error.what()); }
    { std::lock_guard lock(watch_mutex_); watching_ = false; }
    inventory_worker_.shutdown(std::chrono::milliseconds(0));
    if (!worker_.shutdown(options_.timing.shutdown_wait)) log("W", "USB releases did not finish before shutdown");
}
std::vector<std::string> UsbService::authorize_what_an_older_build_hid() {
    std::vector<HostDevice> devices;
    { std::lock_guard lock(rescan_mutex_); devices = snapshot_; }
    std::vector<std::string> migrated;
    for (const auto& device : devices) {
        if (device.authorized) continue;
        log("I", "USB " + device.sysfs + " was left deauthorized by an older build; authorizing it");
        if (set_authorized(device.sysfs)) migrated.push_back(device.sysfs);
    }
    return migrated;
}
void UsbService::await_interfaces(const std::vector<std::string>& devices) {
    if (devices.empty()) return;
    const auto deadline = std::chrono::steady_clock::now() + options_.timing.interfaces_timeout;
    for (const auto& sysfs : devices) {
        if (probe_.await_interfaces(sysfs, deadline)) continue;
        if (worker_.interrupted()) return;
        if (!is_directory(devices_ + "/" + sysfs)) continue;
        log("W", "USB " + sysfs + " published no interface within " + ms(options_.timing.interfaces_timeout) +
            " ms of being authorized; the rules have nothing to give anybody until it is replugged");
        return;
    }
}
bool UsbService::set_authorized(const std::string& sysfs) {
    const auto path = devices_ + "/" + sysfs + "/authorized";
    const auto error = writer_->write(path, "1");
    if (error.empty()) return true;
    log("W", "Cannot write " + path + ": " + error);
    return false;
}
void UsbService::set_autoprobe(bool autoprobe) {
    const auto error = writer_->write(autoprobe_path_, autoprobe ? "1" : "0");
    if (error.empty()) log("I", std::string("USB drivers_autoprobe = ") + (autoprobe ? "1" : "0"));
    else log("W", "Cannot write " + autoprobe_path_ + ": " + error);
}

// --- lists ---
Json::Value UsbService::rule_json(const Decision& decision) {
    Json::Value obj(Json::objectValue);
    obj["layer"] = decision.layer ? Json::Value(layer_key(*decision.layer)) : Json::Value();
    obj["index"] = decision.index;
    obj["controller"] = text_or_null(decision.controller);
    return obj;
}
Json::Value UsbService::decision_json(const Decision& decision) {
    auto obj = rule_json(decision);
    obj["target"] = target_key(decision.target);
    obj["vm"] = text_or_null(decision.vm);
    return obj;
}
Json::Value UsbService::host_row(const HostDevice& device, const Attachment* attachment, bool locked) {
    auto obj = device.to_json();
    obj["attached_vm"] = attachment ? Json::Value(attachment->vm_id) : Json::Value();
    obj["attached_vm_name"] = attachment ? Json::Value(attachment->vm_name) : Json::Value();
    obj["attached_port"] = attachment ? Json::Value(attachment->port) : Json::Value();
    obj["attached_controller"] = attachment ? text_or_null(attachment->controller) : Json::Value();
    obj["lock"] = locked;
    obj["auto_rule"] = attachment && attachment->rule ? rule_json(*attachment->rule) : Json::Value();
    return obj;
}
Json::Value UsbService::test_row(const HostDevice& device, const Attachment* attachment, bool locked, const std::optional<Decision>& decision) {
    Json::Value obj(Json::objectValue);
    obj["sysfs"] = device.sysfs; obj["id"] = device.id; obj["port"] = device.port;
    obj["state"] = state_key(device.state());
    obj["lock"] = locked;
    obj["attached_vm"] = attachment ? Json::Value(attachment->vm_id) : Json::Value();
    obj["result"] = decision ? decision_json(*decision) : Json::Value();
    return obj;
}
Json::Value UsbService::host_list() {
    Json::Value array(Json::arrayValue);
    // A fresh scan: driver binds move no node, so the snapshot goes stale.
    for (const auto& device : scan_host()) {
        if (device.is_hub()) continue;
        std::optional<Attachment> attachment;
        bool locked;
        {
            std::lock_guard lock(lock_);
            auto it = attachments_.find(device.sysfs);
            if (it != attachments_.end()) attachment = it->second;
            locked = engine_.is_locked(device.sysfs, device.devnum);
        }
        array.append(host_row(device, attachment ? &*attachment : nullptr, locked));
    }
    return array;
}
Json::Value UsbService::test_rules() {
    Json::Value array(Json::arrayValue);
    const auto devices = scan_host();
    std::lock_guard lock(lock_);
    for (const auto& device : devices) {
        if (device.is_hub()) continue;
        auto it = attachments_.find(device.sysfs);
        const auto decision = engine_.decide(device.engine(), state_fn(), controller_fn());
        array.append(test_row(device, it == attachments_.end() ? nullptr : &it->second, engine_.is_locked(device.sysfs, device.devnum), decision));
    }
    return array;
}
Json::Value UsbService::vm_list(const std::string& vm_id) const {
    Json::Value array(Json::arrayValue);
    std::vector<Attachment> owned;
    {
        std::lock_guard lock(lock_);
        for (auto& attachment : ordered_attachments()) if (attachment.vm_id == vm_id) owned.push_back(std::move(attachment));
    }
    for (const auto& attachment : owned) {
        Json::Value obj(Json::objectValue);
        obj["sysfs"] = attachment.sysfs; obj["vid"] = attachment.vid; obj["pid"] = attachment.pid;
        obj["port"] = attachment.port; obj["node"] = attachment.node;
        obj["controller"] = text_or_null(attachment.controller);
        array.append(std::move(obj));
    }
    return array;
}
std::optional<std::string> UsbService::attached_controller(const std::string& sysfs) const {
    std::lock_guard lock(lock_);
    auto it = attachments_.find(sysfs);
    return it == attachments_.end() ? std::nullopt : it->second.controller;
}

// --- rules ---
int UsbService::set_rules(const Json::Value& json) {
    // A VM it knows about; the controller is not checked (see legacy targetExists).
    auto rules = Rules::from_json(json, [this](const std::string& vm, const std::optional<std::string>&) { return find_vm(vm).has_value(); });
    SaveOwes owed;
    {
        std::lock_guard lock(lock_);
        owed = engine_.save_owes(rules);
        engine_.set_rules(rules);
    }
    try { rules_file_.save(rules); } catch (const std::exception& error) {
        // The rules are in force regardless; only the copy for the next start is missing.
        log("W", "Failed to write " + rules_file_.path() + ": " + error.what());
    }
    log("I", std::string("USB rules set: enabled=") + (rules.enabled() ? "true" : "false") +
        " exact=" + std::to_string(rules.layer(Layer::exact).size()) + " port=" + std::to_string(rules.layer(Layer::port).size()) +
        " device=" + std::to_string(rules.layer(Layer::device).size()) + " any=" + std::to_string(rules.layer(Layer::any).size()));
    set_autoprobe(!rules.enabled());
    switch (owed) {
    case SaveOwes::release: return release_everything_and_wait();
    case SaveOwes::nothing: return 0;
    default: return run_auto_attach_and_wait("rules");
    }
}

// --- attach / detach ---
int UsbService::attach(const UsbVm& vm, const std::string& sysfs) {
    try { return attach(vm, sysfs, std::nullopt, std::nullopt); }
    catch (const VmmUnreachable& error) { throw RequestError(std::string("crosvm usb attach failed: ") + error.what()); }
}
int UsbService::attach(const UsbVm& requested, const std::string& sysfs, const std::optional<std::string>& wanted, const std::optional<Decision>& rule) {
    // The legacy instance is live: read the VM as it is now.
    const auto live = find_vm(requested.id);
    const UsbVm& vm = live ? *live : requested;
    if (vm.state != VmState::running) throw RequestError("VM is not running");
    const auto controller = find_controller(vm.config, wanted);
    if (!controller) throw RequestError(!wanted ? "VM has no USB controller" : "VM has no USB controller " + *wanted);
    if (!vm.control_socket) throw RequestError("VM has no control socket");
    const auto socket = *vm.control_socket;
    // A fresh scan: bus/device numbers are reassigned on re-enumeration.
    std::optional<HostDevice> device;
    for (auto& candidate : rescan_now()) if (candidate.sysfs == sysfs) { device = std::move(candidate); break; }
    if (!device) device = read_unlisted_device(sysfs);
    if (device->is_hub()) throw RequestError("refusing to attach a hub");
    const auto vm_id = vm.id, vm_name = vm.name;
    int epoch;
    {
        std::lock_guard lock(lock_);
        auto existing = attachments_.find(sysfs);
        if (existing != attachments_.end()) throw RequestError("device already attached to VM " + existing->second.vm_name);
        epoch = stop_epoch(vm_id);
    }
    // A device under the shut gate has no configuration; give it the host's choice.
    if (!probe_.configure_for_vm(sysfs))
        throw RequestError("USB " + sysfs + " has no configuration and published no interface within " + ms(probe_.timeout()) + " ms of being probed");
    const auto mark = options_.vms ? options_.vms->stderr_mark(vm_id) : std::nullopt;
    int port;
    try {
        if (!options_.control) throw ControlIoError("no USB control channel");
        port = options_.control->attach(socket, device->node);
    } catch (const VmmUnreachable&) {
        // The CLI claims nothing before the VMM has the fd: nothing to give back.
        throw;
    } catch (const ControlRefused& error) {
        // A refusal can follow a partial claim, and nothing else will release it.
        restore_host_drivers(sysfs, vm_id);
        throw RequestError(attach_failure_message(error.token, error.stderr_text, vmm_log_since(vm_id, mark)));
    } catch (const ControlIoError& error) {
        restore_host_drivers(sysfs, vm_id);
        throw RequestError(std::string("crosvm usb attach failed: ") + error.what());
    }
    std::optional<std::string> lost_to;
    bool stopped = false;
    {
        std::lock_guard lock(lock_);
        auto existing = attachments_.find(sysfs);
        if (existing != attachments_.end()) lost_to = existing->second.vm_name;
        else if (stop_epoch(vm_id) != epoch) stopped = true;
        else {
            put_attachment({vm_id, vm_name, port, sysfs, device->vid, device->pid, device->node,
                controller->empty() ? std::nullopt : controller, rule});
            leftovers_.forget_device(sysfs);
        }
    }
    if (stopped) {
        // The VM went down inside the CLI and its release already ran.
        restore_host_drivers(sysfs, vm_id);
        throw RequestError("VM is not running");
    }
    if (lost_to) {
        try { options_.control->detach(socket, port); } catch (const std::exception& error) {
            log("W", "Failed to undo a lost attach on port " + std::to_string(port) + ": " + error.what());
        }
        throw RequestError("device already attached to VM " + *lost_to);
    }
    log("I", "Attached USB " + sysfs + " (" + device->vid + ":" + device->pid + ") to VM " + vm_name + " on port " +
        std::to_string(port) + " (" + (rule ? "auto, " + rule->where() : std::string("manual")) + ")");
    broadcast_vm(vm_id, vm_name);
    broadcast_host();
    return port;
}
HostDevice UsbService::read_unlisted_device(const std::string& sysfs) const {
    // [sysfs] comes from the request; keep the read inside the device root.
    const auto name = child_name(sysfs);
    if (!name) throw RequestError("no such USB device: " + sysfs);
    try { return read_device(devices_ + "/" + *name, options_.dev_root); }
    catch (const std::exception&) { throw RequestError("no such USB device: " + sysfs); }
}
std::optional<HostDevice> UsbService::fresh_device_at(const std::string& sysfs) const {
    const auto name = child_name(sysfs);
    if (!name || !is_directory(devices_ + "/" + *name)) return std::nullopt;
    try { return read_device(devices_ + "/" + *name, options_.dev_root); } catch (const std::exception&) { return std::nullopt; }
}
int UsbService::stop_epoch(const std::string& vm_id) const {
    auto it = stop_epochs_.find(vm_id);
    return it == stop_epochs_.end() ? 0 : it->second;
}
void UsbService::detach(const UsbVm& vm, const std::optional<std::string>& sysfs, std::optional<int> port) {
    std::optional<Attachment> attachment;
    {
        std::lock_guard lock(lock_);
        for (auto& candidate : ordered_attachments()) {
            if (candidate.vm_id != vm.id) continue;
            if (sysfs && !sysfs->empty()) {
                if (candidate.sysfs != *sysfs) continue;
            } else if (!port || candidate.port != *port) {
                continue;
            }
            attachment = std::move(candidate);
            break;
        }
    }
    if (!attachment) throw RequestError("device not attached to this VM");
    // Locked before the VMM is told: a pass must not take it in between.
    lock_device(attachment->sysfs);
    drop_attachment(*attachment, vm);
    log("I", "Detached USB " + attachment->sysfs + " from VM " + vm.name + "; locked until unplugged");
    restore_host_drivers(attachment->sysfs, vm.id);
    broadcast_vm(vm.id, vm.name);
    broadcast_host();
}
void UsbService::drop_attachment(const Attachment& attachment, const UsbVm& requested) {
    const auto live = find_vm(requested.id);
    const auto socket = live ? live->control_socket : std::nullopt;
    const auto state = live ? live->state : VmState::stopped;
    if (!socket || state == VmState::stopping || state == VmState::stopped || state == VmState::rebooting) {
        // No VMM left to take it from; this may be the last path that drops the record.
        { std::lock_guard lock(lock_); erase_attachment(attachment.sysfs); }
        log("I", "Dropped USB " + attachment.sysfs + ": VM " + requested.name + " is gone");
        return;
    }
    try {
        if (!options_.control) throw ControlIoError("no USB control channel");
        options_.control->detach(*socket, attachment.port);
    } catch (const ControlRefused& error) {
        if (error.token != "no_such_port" && error.token != "no_such_device") throw RequestError("crosvm usb detach failed: " + error.token);
        log("I", "VMM had already dropped port " + std::to_string(attachment.port) + " (" + error.token + ")");
    } catch (const ControlIoError& error) {
        throw RequestError(std::string("crosvm usb detach failed: ") + error.what());
    }
    std::lock_guard lock(lock_);
    erase_attachment(attachment.sysfs);
}

// --- set_target ---
Json::Value UsbService::set_target(const std::string& sysfs, Target target, const std::optional<UsbVm>& vm, const std::optional<std::string>& controller) {
    const auto device = read_unlisted_device(sysfs);
    if (target != Target::host && device.is_hub()) throw RequestError("refusing to take a hub away from the host");
    std::optional<Attachment> previous;
    bool was_locked;
    {
        std::lock_guard lock(lock_);
        auto it = attachments_.find(sysfs);
        if (it != attachments_.end()) previous = it->second;
        was_locked = engine_.is_locked(sysfs, device.devnum);
    }
    Json::Value res(Json::objectValue);
    res["device"] = sysfs;
    res["target"] = target_key(target);
    Json::Value before(Json::objectValue);
    before["state"] = state_key(device.state());
    before["vm_id"] = previous ? Json::Value(previous->vm_id) : Json::Value();
    before["port"] = previous ? Json::Value(previous->port) : Json::Value();
    res["previous"] = std::move(before);
    std::optional<int> port;
    switch (target) {
    case Target::sink: set_target_sink(device, previous); break;
    case Target::vm:
        if (!vm) throw RequestError("missing vm_id");
        port = set_target_vm(*vm, device, controller, previous, was_locked);
        break;
    default: set_target_host(device, previous); break;
    }
    std::optional<std::string> landed_on;
    if (target == Target::vm) {
        std::lock_guard lock(lock_);
        auto it = attachments_.find(sysfs);
        if (it != attachments_.end()) landed_on = it->second.controller;
    }
    res["vm_id"] = vm ? Json::Value(vm->id) : Json::Value();
    res["controller"] = text_or_null(landed_on);
    res["port"] = port ? Json::Value(*port) : Json::Value();
    // Read back: the kernel may not have honoured every write.
    const auto after = fresh_device_at(sysfs);
    res["state"] = after ? Json::Value(state_key(after->state())) : Json::Value();
    return res;
}
void UsbService::set_target_host(const HostDevice& device, const std::optional<Attachment>& previous) {
    const auto& sysfs = device.sysfs;
    lock_device(sysfs, device.devnum);
    if (previous) {
        if (auto holder = find_vm(previous->vm_id)) { detach(*holder, sysfs, std::nullopt); return; }
        { std::lock_guard lock(lock_); erase_attachment(sysfs); }
        restore_host_drivers(sysfs, previous->vm_id);
        broadcast_vm(previous->vm_id, previous->vm_name);
        broadcast_host();
        return;
    }
    // With the gate shut nothing binds by itself: the host rule's writes.
    probe_.give_to_host(sysfs);
    broadcast_host();
}
void UsbService::set_target_sink(const HostDevice& device, const std::optional<Attachment>& previous) {
    const auto& sysfs = device.sysfs;
    lock_device(sysfs, device.devnum);
    if (previous) {
        drop_from_holder(*previous);
        await_vmm_released(sysfs);
        broadcast_vm(previous->vm_id, previous->vm_name);
    }
    unbind_host_drivers(sysfs);
    broadcast_host();
}
int UsbService::set_target_vm(const UsbVm& vm, const HostDevice& device, const std::optional<std::string>& controller,
                              const std::optional<Attachment>& previous, bool was_locked) {
    const auto& sysfs = device.sysfs;
    // crosvm takes no controller argument: a move inside one VM changes nothing.
    if (previous && previous->vm_id == vm.id) {
        std::lock_guard lock(lock_);
        engine_.unlock(sysfs);
        return previous->port;
    }
    lock_device(sysfs, device.devnum);
    bool landed = false;
    const auto finish = [&] {
        // A move that did not land leaves the device on the host, and the
        // lock goes back to what the request found.
        if (!landed && previous) restore_host_drivers(sysfs, previous->vm_id);
        std::lock_guard lock(lock_);
        if (landed || !was_locked) engine_.unlock(sysfs);
    };
    try {
        if (previous) {
            drop_from_holder(*previous);
            // The claim outlives the detach; wait it out without a drivers_probe.
            await_vmm_released(sysfs);
            log("I", "Took USB " + sysfs + " from VM " + previous->vm_name + " for VM " + vm.name);
            broadcast_vm(previous->vm_id, previous->vm_name);
        }
        const int port = attach(vm, sysfs, controller, std::nullopt);
        landed = true;
        finish();
        return port;
    } catch (const VmmUnreachable& error) {
        finish();
        throw RequestError(std::string("crosvm usb attach failed: ") + error.what());
    } catch (...) {
        finish();
        throw;
    }
}
void UsbService::drop_from_holder(const Attachment& attachment) {
    if (auto holder = find_vm(attachment.vm_id)) { drop_attachment(attachment, *holder); return; }
    std::lock_guard lock(lock_);
    erase_attachment(attachment.sysfs);
}

// --- VM hooks and releases ---
void UsbService::on_vm_state(const std::string& vm_id, VmState state) {
    try {
        const auto vm = find_vm(vm_id);
        if (state == VmState::running) {
            // The failure was against the instance that is gone.
            { std::lock_guard lock(lock_); engine_.forget_failures_for(vm ? vm->id : vm_id); }
            if (vm) queue_auto_attach_when_ready(*vm);
            return;
        }
        if (state != VmState::stopping && state != VmState::stopped && state != VmState::rebooting) return;
        const auto id = vm ? vm->id : vm_id;
        const auto name = vm ? vm->name : std::string();
        // Ordered before the release so an attach inside the CLI sees it.
        { std::lock_guard lock(lock_); stop_epochs_[id] = stop_epoch(id) + 1; }
        if (state == VmState::stopping) return;
        if (!worker_.schedule([this, id, name] { release_all(id, name); })) log("W", "Failed to schedule the USB release of a stopping VM");
    } catch (const std::exception& error) {
        log("W", std::string("usb: state hook failed: ") + error.what());
    }
}
void UsbService::release_all(const std::string& vm_id, const std::string& vm_name) {
    try {
        std::vector<Attachment> released;
        std::vector<std::string> left;
        {
            std::lock_guard lock(lock_);
            for (auto& attachment : ordered_attachments()) {
                if (attachment.vm_id != vm_id) continue;
                erase_attachment(attachment.sysfs);
                released.push_back(std::move(attachment));
            }
            left = leftovers_.left_by(vm_id);
        }
        for (const auto& attachment : released) {
            log("I", "Released USB " + attachment.sysfs + " (" + attachment.vid + ":" + attachment.pid + ", " + attachment.source() + ") from VM " + vm_name);
            // A stop never hands a device to another VM, but a sink keeps it idle.
            if (rules_leave_it_idle(attachment.sysfs)) {
                log("I", "USB " + attachment.sysfs + " stays idle: the rules sink it");
                continue;
            }
            restore_host_drivers(attachment.sysfs, vm_id);
        }
        const int recovered = left.empty() ? 0 : recover_leftovers(left, "VM " + vm_name + " stopped");
        if (released.empty() && recovered == 0) return;
        broadcast_vm(vm_id, vm_name);
        broadcast_host();
    } catch (const std::exception& error) {
        log("W", std::string("Failed to release the USB devices of a stopping VM: ") + error.what());
    }
}
void UsbService::on_inventory_changed(const Diff& diff) {
    for (const auto& device : diff.removed) {
        std::optional<Attachment> attachment;
        std::vector<std::string> dropped;
        {
            std::lock_guard lock(lock_);
            auto it = attachments_.find(device.sysfs);
            if (it != attachments_.end()) attachment = it->second;
            // The instance a lock, a failure or a leftover was about is gone.
            engine_.forget(device.sysfs);
            dropped = leftovers_.forget_device(device.sysfs);
        }
        if (!dropped.empty())
            log("I", "USB " + device.sysfs + " was unplugged with " + std::to_string(dropped.size()) + " interface(s) still owed to the host");
        if (!attachment) continue;
        worker_.schedule([this, released = *attachment] { release_unplugged(released); });
    }
    // Every difference owes a pass; the kind only names it.
    schedule_auto_attach(diff.reason());
    broadcast_host();
}
std::vector<HostDevice> UsbService::scan_host() {
    auto devices = scan();
    notice_leftovers(devices);
    return devices;
}
void UsbService::notice_leftovers(const std::vector<HostDevice>& devices) {
    Leftovers::Scan found;
    {
        std::lock_guard lock(lock_);
        if (leftovers_.empty()) return;
        std::map<std::string, std::string> drivers;
        for (const auto& device : devices) for (const auto& iface : device.interfaces) drivers[iface.name] = iface.driver;
        found = leftovers_.scan(drivers);
    }
    for (const auto& [iface, driver] : found.reclaimed) log("I", "USB " + iface + " is back with " + driver + "; nothing left to restore");
    if (found.free.empty()) return;
    schedule([this, free = found.free] { if (recover_leftovers(free, "claim gone") > 0) broadcast_host(); });
}
int UsbService::recover_leftovers(const std::vector<std::string>& ifaces, const std::string& reason) {
    std::vector<std::pair<std::string, std::string>> taken;
    {
        std::lock_guard lock(lock_);
        taken = leftovers_.take(ifaces);
        // A device attached again is released whole by that attachment.
        std::erase_if(taken, [&](const auto& entry) { return attachments_.contains(Leftovers::device_of(entry.first)); });
    }
    if (taken.empty()) return 0;
    const auto probed = restore_interfaces(taken, true);
    if (!probed.empty()) {
        std::string names;
        for (const auto& name : probed) names += (names.empty() ? "" : ", ") + name;
        log("I", "Recovered " + std::to_string(probed.size()) + " USB interface(s) left unbound earlier (" + reason + "): " + names);
    }
    return static_cast<int>(probed.size());
}
bool UsbService::vm_gone(const std::string& vm_id) const {
    const auto state = state_of(vm_id);
    return !state || *state == VmState::stopped || *state == VmState::rebooting;
}

// --- passes ---
void UsbService::schedule_auto_attach(const std::string& reason) {
    std::lock_guard lock(lock_);
    if (pending_auto_) *pending_auto_ = true;
    pending_auto_ = std::make_shared<std::atomic<bool>>(false);
    if (!worker_.schedule([this, reason] { run_pass_quietly(reason, false); }, options_.timing.auto_attach_debounce, pending_auto_))
        pending_auto_.reset();
}
void UsbService::queue_auto_attach_when_ready(const UsbVm& vm) {
    const auto reason = "VM " + vm.name + " running";
    const auto id = vm.id;
    const auto& timing = options_.timing;
    auto wait = std::make_shared<Wait>();
    wait->wanted = [this, id] { const auto now = find_vm(id); return now && now->state == VmState::running; };
    wait->ready = [this, id] {
        const auto now = find_vm(id);
        return now && now->control_socket && options_.control && options_.control->ready(*now->control_socket);
    };
    wait->then = [this, reason] { run_pass_quietly(reason, false); };
    wait->abandoned = [this, reason] { log("I", "USB rules pass (" + reason + ") dropped: VM left RUNNING"); };
    const auto seconds = std::to_string(timing.ready_poll.count() * timing.ready_max_polls / 1000);
    wait->gave_up = [this, reason, seconds] { log("W", "USB rules pass (" + reason + ") skipped: control socket not ready after " + seconds + " s"); };
    when_ready(scheduler(), wait, timing.ready_poll, timing.ready_max_polls);
}
int UsbService::run_auto_attach_and_wait(const std::string& reason) {
    try {
        auto result = worker_.submit([this, reason] { return run_pass(reason, false); });
        return result ? *result : 0;
    } catch (const std::exception& error) {
        log("W", "USB rules pass (" + reason + ") failed: " + error.what());
        return 0;
    }
}
int UsbService::release_everything_and_wait() {
    try {
        auto result = worker_.submit([this] { return release_everything(); });
        return result ? *result : 0;
    } catch (const std::exception& error) {
        log("W", std::string("Giving the USB devices back to the host failed: ") + error.what());
        return 0;
    }
}
int UsbService::release_everything() {
    std::vector<Attachment> held;
    { std::lock_guard lock(lock_); held = ordered_attachments(); }
    int given = 0;
    std::vector<std::pair<std::string, std::string>> vms; // LinkedHashMap
    for (const auto& attachment : held) {
        try {
            drop_from_holder(attachment);
            restore_host_drivers(attachment.sysfs, attachment.vm_id);
            auto at = std::find_if(vms.begin(), vms.end(), [&](const auto& row) { return row.first == attachment.vm_id; });
            if (at != vms.end()) at->second = attachment.vm_name; else vms.emplace_back(attachment.vm_id, attachment.vm_name);
            ++given;
            log("I", "Took USB " + attachment.sysfs + " (" + attachment.vid + ":" + attachment.pid + ") back from VM " + attachment.vm_name);
        } catch (const std::exception& error) {
            log("W", "Could not take USB " + attachment.sysfs + " back from VM " + attachment.vm_name + ": " + error.what());
        }
    }
    // Root hubs first and not from the scan: their buses list nothing yet.
    for (const auto& hub : driverless_root_hubs()) {
        try {
            if (probe_.give_to_host(hub) == 0) continue;
            ++given;
            log("I", "USB root hub " + hub + " had no driver; the host gets its bus back");
        } catch (const std::exception& error) {
            log("W", "Could not give USB root hub " + hub + " back to the host: " + error.what());
        }
    }
    for (const auto& device : scan_host()) {
        if (device.state() != DeviceState::idle) continue;
        try {
            if (probe_.give_to_host(device.sysfs) == 0) continue;
            ++given;
            log("I", "USB " + device.sysfs + " was idle; the host gets it back");
        } catch (const std::exception& error) {
            log("W", "Could not give USB " + device.sysfs + " back to the host: " + error.what());
        }
    }
    { std::lock_guard lock(lock_); engine_.clear_locks(); }
    log("I", "USB passthrough turned off: " + std::to_string(given) + " device(s) given back to the host");
    for (const auto& [id, name] : vms) broadcast_vm(id, name);
    broadcast_host();
    return given;
}
int UsbService::run_pass(const std::string& reason, bool daemon_start) {
    const auto result = run_auto_attach(reason, daemon_start);
    if (result.unreachable) {
        const auto again = reason + ", retry";
        retry(scheduler(), [this, again, daemon_start] {
            const auto r = run_auto_attach_or_null(again, daemon_start);
            return !r || !r->unreachable;
        }, options_.timing.retry_delay, options_.timing.max_retries);
    }
    return result.applied;
}
void UsbService::run_pass_quietly(const std::string& reason, bool daemon_start) {
    try { run_pass(reason, daemon_start); }
    catch (const std::exception& error) { log("W", "USB rules pass (" + reason + ") failed: " + error.what()); }
}
std::optional<UsbService::PassResult> UsbService::run_auto_attach_or_null(const std::string& reason, bool daemon_start) {
    try { return run_auto_attach(reason, daemon_start); }
    catch (const std::exception& error) {
        log("W", "USB rules pass (" + reason + ") failed: " + error.what());
        return std::nullopt;
    }
}
UsbService::PassResult UsbService::run_auto_attach(const std::string& reason, bool daemon_start) {
    const auto devices = scan_host();
    std::vector<Decision> plan;
    std::vector<EngineDevice> probe_back;
    bool recover;
    {
        std::lock_guard lock(lock_);
        const bool enabled = engine_.rules_enabled();
        recover = engine_.recovers_idle_devices(daemon_start);
        std::vector<EngineDevice> plugged;
        for (const auto& device : devices) {
            // The record is this daemon's own word on who has it.
            if (attachments_.contains(device.sysfs)) continue;
            if (enabled && !device.is_hub()) { plugged.push_back(device.engine()); continue; }
            if (!recover) continue;
            if (device.state() != DeviceState::idle) continue;
            // A sink by hand is the user's answer too.
            if (engine_.is_locked(device.sysfs, device.devnum)) continue;
            probe_back.push_back(device.engine());
        }
        if (enabled) plan = engine_.plan(plugged, state_fn(), controller_fn());
    }
    int attached = 0, probed = 0, idle = 0;
    std::vector<std::string> unreachable;
    for (const auto& device : probe_back) {
        if (!still_free(device.sysfs, device.devnum)) continue;
        if (probe_.give_to_host(device.sysfs) == 0) continue;
        ++probed;
        log("I", "USB " + device.sysfs + " was idle and no rule speaks for it; the host gets it");
    }
    if (recover)
        for (const auto& hub : driverless_root_hubs()) {
            if (probe_.give_to_host(hub) == 0) continue;
            ++probed;
            log("I", "USB root hub " + hub + " had no driver; the host gets its bus back");
        }
    for (const auto& decision : plan) {
        const auto& device = decision.device;
        const auto where = decision.where();
        // Asked again now: an attach spends seconds in the CLI meanwhile.
        if (!still_free(device.sysfs, device.devnum)) continue;
        if (decision.target == Target::sink) { ++idle; continue; }
        if (decision.target == Target::host) {
            if (probe_.give_to_host(device.sysfs) == 0) continue;
            ++probed;
            log("I", "USB " + device.sysfs + " (" + device.id + ") goes to the host by " + where);
            continue;
        }
        if (!decision.vm || std::find(unreachable.begin(), unreachable.end(), *decision.vm) != unreachable.end()) continue;
        const auto inst = find_vm(*decision.vm);
        if (!inst) continue;
        try {
            attach(*inst, device.sysfs, decision.controller, decision);
            ++attached;
            broadcast_auto("usb_auto_attached", *inst, decision, std::nullopt);
        } catch (const VmmUnreachable& error) {
            unreachable.push_back(*decision.vm);
            log("W", "Auto attach of USB " + device.sysfs + " (" + device.id + ") to VM " + inst->name + " by rule " + where + ": " + error.what() + "; will retry");
        } catch (const std::exception& error) {
            { std::lock_guard lock(lock_); engine_.mark_failed(device.sysfs, *decision.vm); }
            log("W", "Auto attach of USB " + device.sysfs + " (" + device.id + ") to VM " + inst->name + " by rule " + where + " failed: " + error.what());
            broadcast_auto("usb_auto_failed", *inst, decision, std::string(error.what()));
        }
    }
    if (probed > 0) broadcast_host();
    const auto summary = "USB rules pass (" + reason + "): " + std::to_string(plan.size()) + " decision(s), " + std::to_string(attached) +
        " attached, " + std::to_string(probed) + " given to the host, " + std::to_string(idle) + " left idle" + (unreachable.empty() ? "" : ", VMM unreachable");
    log(attached > 0 || probed > 0 || !unreachable.empty() ? "I" : "D", summary);
    return {attached + probed, !unreachable.empty()};
}
void UsbService::broadcast_auto(const char* event, const UsbVm& vm, const Decision& decision, const std::optional<std::string>& error) {
    try {
        Json::Value data(Json::objectValue);
        data["vm_id"] = vm.id;
        data["vm_name"] = vm.name;
        data["target"] = target_key(decision.target);
        data["sysfs"] = decision.device.sysfs;
        data["id"] = decision.device.id;
        data["port"] = decision.device.port;
        data["layer"] = decision.layer ? Json::Value(layer_key(*decision.layer)) : Json::Value();
        data["index"] = decision.index;
        data["controller"] = text_or_null(decision.controller);
        if (error) data["error"] = *error;
        broadcast(event, std::move(data));
    } catch (const std::exception& e) {
        log("W", std::string("Failed to build ") + event + ": " + e.what());
    }
}
void UsbService::release_unplugged(const Attachment& attachment) {
    try {
        const auto inst = find_vm(attachment.vm_id);
        const auto socket = inst ? inst->control_socket : std::nullopt;
        if (socket && options_.control) {
            try { options_.control->detach(*socket, attachment.port); } catch (const std::exception& error) {
                log("W", "Detach of unplugged " + attachment.sysfs + " failed: " + error.what());
            }
        }
        { std::lock_guard lock(lock_); erase_attachment(attachment.sysfs); }
        log("I", "USB " + attachment.sysfs + " (" + attachment.vid + ":" + attachment.pid + ") was unplugged while attached to VM " + attachment.vm_name);
        broadcast_vm(attachment.vm_id, attachment.vm_name);
        broadcast_host();
    } catch (const std::exception& error) {
        log("W", std::string("Failed to release an unplugged USB device: ") + error.what());
    }
}

// --- sysfs writes ---
int UsbService::unbind_host_drivers(const std::string& sysfs) {
    int unbound = 0;
    for (const auto& name : probe_.interfaces_of(sysfs)) {
        const auto driver = probe_.driver_of(name);
        if (driver.empty() || driver == "usbfs") continue;
        const auto error = writer_->write(drivers_ + "/" + driver + "/unbind", name + "\n");
        log("I", "unbind " + name + " from " + driver + ": code=" + (error.empty() ? "0" : "1") + " " + error);
        ++unbound;
    }
    return unbound;
}
std::vector<std::string> UsbService::driverless_root_hubs() const {
    std::vector<std::string> found;
    for (const auto& name : list_directory(devices_)) if (is_root_hub_name(name) && needs_host_drivers(name)) found.push_back(name);
    std::sort(found.begin(), found.end());
    return found;
}
bool UsbService::needs_host_drivers(const std::string& sysfs) const {
    if (probe_.driver_of(sysfs).empty()) return true;
    // No configuration: no interfaces to find unbound, and the most broken of all.
    if (!probe_.is_configured(sysfs)) return true;
    for (const auto& name : probe_.interfaces_of(sysfs)) if (probe_.driver_of(name).empty()) return true;
    return false;
}
void UsbService::drivers_probe(const std::string& name) {
    const auto error = writer_->write(probe_path_, name + "\n");
    log("I", "drivers_probe " + name + ": code=" + (error.empty() ? "0" : "1") + " " + error);
}
void UsbService::lock_device(const std::string& sysfs) {
    if (const auto device = fresh_device_at(sysfs)) lock_device(sysfs, device->devnum);
}
void UsbService::lock_device(const std::string& sysfs, int devnum) {
    std::lock_guard lock(lock_);
    engine_.lock(sysfs, devnum);
}
bool UsbService::still_free(const std::string& sysfs, int devnum) const {
    std::lock_guard lock(lock_);
    return !attachments_.contains(sysfs) && !engine_.is_locked(sysfs, devnum);
}
bool UsbService::rules_leave_it_idle(const std::string& sysfs) {
    const auto device = fresh_device_at(sysfs);
    if (!device) return false;
    std::lock_guard lock(lock_);
    if (engine_.is_locked(sysfs, device->devnum)) return false;
    const auto decision = engine_.decide(device->engine(), state_fn(), controller_fn());
    return decision && decision->target == Target::sink;
}
void UsbService::restore_host_drivers(const std::string& sysfs, const std::string& vm_id) {
    try {
        std::vector<std::pair<std::string, std::string>> iface_to_vm;
        for (const auto& name : probe_.interfaces_of(sysfs)) iface_to_vm.emplace_back(name, vm_id);
        restore_interfaces(iface_to_vm, false);
    } catch (const std::exception& error) {
        log("W", "Failed to hand the interfaces of " + sysfs + " back to the host: " + error.what());
    }
}
std::vector<std::string> UsbService::restore_interfaces(const std::vector<std::pair<std::string, std::string>>& iface_to_vm, bool recovery) {
    std::vector<std::string> probed, again;
    for (const auto& [name, vm_id] : iface_to_vm) {
        if (!is_directory(devices_ + "/" + name)) continue;
        const auto claim = await_released(name);
        if (claim == Claim::host) continue;
        if (claim == Claim::none) {
            probe_.probe_interface(name);
            probed.push_back(name);
            continue;
        }
        { std::lock_guard lock(lock_); leftovers_.leave(name, vm_id); }
        // The VM's exit already passed: nobody else will queue the retry.
        if (!recovery && vm_gone(vm_id)) again.push_back(name);
    }
    if (!again.empty()) schedule([this, again] { if (recover_leftovers(again, "VM already gone") > 0) broadcast_host(); });
    return probed;
}
void UsbService::await_vmm_released(const std::string& sysfs) {
    for (const auto& name : probe_.interfaces_of(sysfs)) if (is_directory(devices_ + "/" + name)) await_released(name);
}
UsbService::Claim UsbService::await_released(const std::string& iface) {
    const auto deadline = std::chrono::steady_clock::now() + options_.timing.usbfs_release_timeout;
    while (true) {
        const auto driver = probe_.driver_of(iface);
        if (driver.empty()) return Claim::none;
        if (driver != "usbfs") return Claim::host;
        if (std::chrono::steady_clock::now() >= deadline) {
            log("W", iface + " is still claimed through usbfs after " + ms(options_.timing.usbfs_release_timeout) +
                " ms; leaving it unbound until the claim is gone");
            return Claim::vmm;
        }
        std::this_thread::sleep_for(options_.timing.usbfs_poll);
        if (worker_.interrupted()) return Claim::vmm;
    }
}
std::string UsbService::vmm_log_since(const std::string& vm_id, std::optional<uint64_t> mark) {
    if (!mark || !options_.vms) return {};
    auto text = options_.vms->stderr_since(vm_id, *mark);
    if (first_error_line(text)) return text;
    // The VMM logs before it answers; its reader may not have run yet.
    std::this_thread::sleep_for(options_.timing.vmm_log_grace);
    return options_.vms->stderr_since(vm_id, *mark);
}

// --- events ---
void UsbService::broadcast_host() {
    try {
        Json::Value data(Json::objectValue);
        data["devices"] = host_list();
        broadcast("usb_host_changed", std::move(data));
    } catch (const std::exception& error) {
        log("W", std::string("Failed to build usb_host_changed: ") + error.what());
    }
}
void UsbService::broadcast_vm(const std::string& vm_id, const std::optional<std::string>& vm_name) {
    try {
        Json::Value data(Json::objectValue);
        data["vm_id"] = vm_id;
        data["vm_name"] = text_or_null(vm_name);
        data["devices"] = vm_list(vm_id);
        broadcast("usb_vm_changed", std::move(data));
    } catch (const std::exception& error) {
        log("W", std::string("Failed to build usb_vm_changed: ") + error.what());
    }
}
void UsbService::broadcast(const char* event, Json::Value data) {
    if (!options_.publish) return;
    try {
        data["event"] = event;
        options_.publish(data);
    } catch (const std::exception& error) {
        log("W", std::string("Failed to broadcast ") + event + ": " + error.what());
    }
}

// --- handlers (ipc/usb/*Handler) ---
Json::Value UsbService::usb_attach(const Json::Value& params) {
    const auto vm_id = opt_string(params, "vm_id", "");
    if (vm_id.empty()) throw RequestError("missing vm_id");
    const auto vm = find_vm(vm_id);
    if (!vm) throw RequestError("VM not found: " + vm_id);
    const auto device = opt_string(params, "device", "");
    if (device.empty()) throw RequestError("missing device");
    const int port = attach(*vm, device);
    Json::Value res(Json::objectValue);
    res["vm_id"] = vm_id;
    res["device"] = device;
    res["port"] = port;
    res["controller"] = text_or_null(attached_controller(device));
    return res;
}
Json::Value UsbService::usb_detach(const Json::Value& params) {
    const auto vm_id = opt_string(params, "vm_id", "");
    if (vm_id.empty()) throw RequestError("missing vm_id");
    const auto vm = find_vm(vm_id);
    if (!vm) throw RequestError("VM not found: " + vm_id);
    const auto device = opt_string(params, "device", "");
    // A JSON null port is no address.
    std::optional<int> port;
    if (present(params, "port")) port = opt_int(params, "port", -1);
    if (device.empty() && !port) throw RequestError("missing device or port");
    detach(*vm, device.empty() ? std::nullopt : std::optional(device), port);
    return Json::Value(Json::objectValue);
}
Json::Value UsbService::usb_host_list(const Json::Value&) {
    Json::Value res(Json::objectValue);
    res["devices"] = host_list();
    return res;
}
Json::Value UsbService::usb_rules_get(const Json::Value&) {
    Json::Value res(Json::objectValue);
    std::lock_guard lock(lock_);
    res["rules"] = engine_.rules().to_json();
    return res;
}
Json::Value UsbService::usb_rules_set(const Json::Value& params) {
    if (!params.isObject() || !params["rules"].isObject()) throw RequestError("missing rules");
    const int applied = set_rules(params["rules"]);
    Json::Value res(Json::objectValue);
    res["applied"] = applied;
    return res;
}
Json::Value UsbService::usb_rules_test(const Json::Value&) {
    Json::Value res(Json::objectValue);
    { std::lock_guard lock(lock_); res["enabled"] = engine_.rules_enabled(); }
    res["devices"] = test_rules();
    return res;
}
Json::Value UsbService::usb_set_target(const Json::Value& params) {
    const auto device = opt_string(params, "device", "");
    if (device.empty()) throw RequestError("missing device");
    const auto wanted = opt_string(params, "target", "");
    const auto target = target_from_key(wanted);
    if (!target) throw RequestError("unknown target: " + wanted);
    const auto vm_id = opt_string(params, "vm_id", "");
    const auto inst = vm_id.empty() ? std::nullopt : find_vm(vm_id);
    if (*target == Target::vm) {
        if (vm_id.empty()) throw RequestError("missing vm_id");
        if (!inst) throw RequestError("VM not found: " + vm_id);
    }
    const auto controller = opt_string(params, "controller", "");
    return set_target(device, *target, *target == Target::vm ? inst : std::nullopt, controller.empty() ? std::nullopt : std::optional(controller));
}
Json::Value UsbService::usb_vm_list(const Json::Value& params) {
    const auto vm_id = opt_string(params, "vm_id", "");
    if (vm_id.empty()) throw RequestError("missing vm_id");
    if (!find_vm(vm_id)) throw RequestError("VM not found: " + vm_id);
    Json::Value res(Json::objectValue);
    res["vm_id"] = vm_id;
    res["devices"] = vm_list(vm_id);
    return res;
}
}
