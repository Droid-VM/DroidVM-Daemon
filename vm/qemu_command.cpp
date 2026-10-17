// SPDX-License-Identifier: GPL-3.0-or-later
// Port of daemon/vm/backend/QemuBackendInstance.buildCommand and the launch
// environment. DataItem semantics as in store/vm_config.cpp.
#include "qemu_command.h"
#include "command_common.h"
#include <algorithm>
#include <stdexcept>

namespace droidvm::vm {
namespace {
using namespace command;
constexpr int max_ports = 15; // VMXhciConfig.MAX_PORTS
constexpr const char* pci = "disable-legacy=on,disable-modern=off";

std::string or_null(const std::optional<std::string>& text) { return text ? *text : "null"; }
// VMPeripheralConfig.getUsb2Ports/getUsb3Ports, then qemuPorts.
int64_t qemu_ports(const Json::Value& controller, const char* key) {
    const auto ports = std::clamp<int64_t>(integer(controller, key, 8), 0, max_ports);
    return ports >= 1 ? std::min<int64_t>(ports, max_ports) : 1;
}

struct Builder {
    const Json::Value& item;
    const QemuRun& run;
    const BootPlan& boot;
    const HostFacts& host;
    const bool agent;
    std::vector<std::string> args;
    int io_threads = 0, drives = 0;

    void add(std::initializer_list<std::string> values) { for (const auto& value : values) args.push_back(value); }
    bool any_screen() const {
        for (const auto& screen : screens_of(item)) if (screen.enabled()) return true;
        return false;
    }
    std::vector<const Json::Value*> peripherals() const {
        const auto& list = member(item, "peripherals");
        if (!list.isArray()) return {};
        return items(list);
    }

    void disks() {
        if (!present(item, "disks")) return;
        if (run.disk_graph) args.insert(args.end(), run.disk_graph->argv.begin(), run.disk_graph->argv.end());
        int boot_index = 1, pmem = 0;
        bool scsi = false;
        const auto scsi_controller = [&] {
            if (scsi) return;
            add({"-device", std::string("virtio-scsi-pci,id=scsi0,") + pci});
            scsi = true;
        };
        for (const auto* disk : items(item["disks"])) {
            auto path = string(*disk, "path", "");
            if (path.empty()) continue;
            if (!run.preserve_disk_paths && !run.disk_graph) path = optimized_path(std::move(path), host);
            const auto file_path = path;
            path = qemu_option_value(path);
            const bool readonly = boolean(*disk, "readonly", false);
            const auto bus = java_enum(*disk, "bus", "VIRTIO", disk_buses);
            std::optional<std::string> retained_node;
            if (run.disk_graph) {
                if (bus == "PFLASH" || bus == "PMEM") {
                    const auto found = run.direct_disk_fds.find(file_path);
                    if (found == run.direct_disk_fds.end() || found->second < 3)
                        throw std::invalid_argument("Missing retained raw disk descriptor");
                    path = "/proc/self/fd/" + std::to_string(found->second);
                } else {
                    const auto found = run.disk_graph->nodes.find(file_path);
                    if (found == run.disk_graph->nodes.end()) throw std::invalid_argument("Missing retained disk graph node");
                    retained_node = found->second;
                }
            }
            if (bus == "PFLASH") {
                add({"-drive", "file=" + path + ",if=pflash,format=raw" + (readonly ? ",readonly=on" : "")});
            } else if (bus == "CDROM") {
                scsi_controller();
                const auto id = "cd" + decimal(drives++);
                if (!retained_node) add({"-drive", "file=" + path + ",if=none,id=" + id + ",media=cdrom,readonly=on"});
                add({"-device", "scsi-cd,drive=" + retained_node.value_or(id) + ",bus=scsi0.0"});
            } else if (bus == "SCSI") {
                scsi_controller();
                const auto id = "scsi" + decimal(drives++);
                if (!retained_node) add({"-drive", "file=" + path + ",if=none,id=" + id + (readonly ? ",readonly=on" : "")});
                add({"-device", "scsi-hd,drive=" + retained_node.value_or(id) + ",bus=scsi0.0,bootindex=" + decimal(boot_index++)});
            } else if (bus == "PMEM") {
                const auto id = "pmem" + decimal(pmem++);
                int64_t size = run.file_length ? run.file_length(file_path) : 0;
                if (size <= 0) size = 64LL * 1024 * 1024;
                add({"-object", "memory-backend-file,id=" + id + ",mem-path=" + path + ",share=on,size=" + decimal(size)
                    + (readonly ? ",readonly=on" : "")});
                add({"-device", "virtio-pmem-pci,memdev=" + id + "," + pci});
            } else {
                const auto io = "io" + decimal(io_threads++), id = "dr" + decimal(drives++);
                add({"-object", "iothread,id=" + io});
                auto drive = "file=" + path + ",if=none,id=" + id;
                drive += agent ? ",cache=writeback,aio=threads,discard=unmap" : ",cache=unsafe,aio=threads,discard=unmap";
                if (readonly) drive += ",readonly=on";
                if (!retained_node) add({"-drive", drive});
                add({"-device", "virtio-blk-pci,drive=" + retained_node.value_or(id) + ",iothread=" + io + "," + pci + ",bootindex=" + decimal(boot_index++)});
            }
        }
    }
    void input() {
        if (!any_screen()) return;
        add({"-device", std::string("virtio-multitouch-pci,") + pci, "-device", std::string("virtio-keyboard-pci,") + pci});
    }
    void usb() {
        size_t index = 0;
        for (const auto* controller : peripherals()) {
            if (java_enum(*controller, "type", "VIRTIO_SOUND", peripheral_types) != "XHCI_USB") continue;
            const auto bus = index == 0 ? std::string("usb-bus") : "usb-" + string(*controller, "id", "");
            add({"-device", "qemu-xhci,id=" + bus + ",p2=" + decimal(qemu_ports(*controller, "usb2_ports")) +
                ",p3=" + decimal(qemu_ports(*controller, "usb3_ports"))});
            if (index++ == 0 && any_screen()) add({"-device", "usb-tablet,bus=" + bus + ".0", "-device", "usb-kbd,bus=" + bus + ".0"});
        }
    }
    void shared_dirs() {
        if (!present(item, "shared_dirs")) return;
        for (const auto* dir : items(item["shared_dirs"])) {
            const auto path = string(*dir, "path", ""), tag = string(*dir, "tag", "");
            if (path.empty() || tag.empty()) continue;
            auto arg = "local,path=" + path + ",mount_tag=" + tag + ",security_model=mapped-xattr";
            const auto cache = java_enum(*dir, "cache", "AUTO", dir_caches);
            if (cache == "NEVER") arg += ",writeout=immediate";
            else if (cache == "ALWAYS") arg += ",writeout=immediate,fmode=0644,dmode=0755";
            if (boolean(*dir, "readonly", false)) arg += ",readonly=on";
            add({"-virtfs", arg});
        }
    }
    void audio() {
        bool any = false;
        for (const auto* peripheral : peripherals())
            any = any || java_enum(*peripheral, "type", "VIRTIO_SOUND", peripheral_types) == "VIRTIO_SOUND";
        if (!any && !boolean(item, "audio_enabled", any_screen())) return;
        add({"-audiodev", "aaudio,id=snd0", "-device", std::string("virtio-sound-pci,audiodev=snd0,") + pci});
    }
    void networks() {
        bool any = false;
        // An absent (or null) "networks" and one with no tap both get the default NIC.
        if (present(item, "networks")) for (const auto* net : items(item["networks"])) {
            const auto tap = string(*net, "tap_name", "");
            if (tap.empty()) continue;
            any = true;
            const auto mac = string(*net, "mac_address", "");
            add({"-device", "virtio-net-pci,netdev=net_" + tap + (mac.empty() ? "" : ",mac=" + mac) + "," + pci});
            add({"-netdev", "tap,ifname=" + tap + ",script=no,downscript=no,id=net_" + tap});
        }
        if (!any) add({"-device", std::string("virtio-net-pci,") + pci});
    }
    void gpu() {
        const bool gpu_screen = screen_enabled(item, gpu0), fb_screen = screen_enabled(item, simplefb);
        if (gpu_screen) {
            const auto& screen = *find_screen(item, gpu0)->item;
            const auto backend = java_enum(item, "gpu_backend", "NONE", gpu_backends);
            const bool use3d = backend == "GPU_VIRGLRENDERER" || backend == "GPU_GFXSTREAM";
            std::string arg = backend == "GPU_VIRGLRENDERER" ? "virtio-gpu-gl-pci" : backend == "GPU_GFXSTREAM" ? "virtio-gpu-rutabaga-pci" : "virtio-gpu-pci";
            arg += std::string(",") + pci + ",xres=" + decimal(integer(screen, "width", 1280)) + ",yres=" + decimal(integer(screen, "height", 720)) + ",edid=on";
            if (use3d) {
                arg += ",blob=on";
                add({"-display", "egl-headless"});
            }
            add({"-device", arg});
        }
        if (fb_screen) add({"-device", "ramfb"});
    }
    void vnc() {
        for (const auto& screen : screens_of(item)) {
            if (!screen.enabled() || screen.exporter() != "VNC") continue;
            auto binding = vnc_binding(screen, run.vnc);
            if (binding.host.empty()) binding.host = "0.0.0.0";
            const auto display = std::max<int64_t>(std::max<int64_t>(binding.port, 1) - 5900, 0);
            if (binding.host.find(':') != std::string::npos) binding.host = "[" + binding.host + "]";
            auto arg = binding.host + ":" + decimal(display);
            if (!binding.password.empty()) {
                add({"-object", "secret,id=vnc-password,data=" + binding.password});
                arg += ",password-secret=vnc-password";
            }
            add({"-vnc", arg});
            return;
        }
    }

    void command(QemuLaunch& launch) {
        launch.strace_dir = strace_args(item, host, args);
        const auto& name = member(item, "name");
        if (!name.isString()) throw std::invalid_argument("VM name is not a string");
        const auto root = data_dir(host);
        add({path_join(root, "usr", "bin", "qemu-system-aarch64"), "-name", name.asString(), "-L", path_join(root, "usr", "share", "qemu")});
        const auto hypervisor = resolve_hypervisor(item, host, Backend::qemu);
        if (!hypervisor) throw std::runtime_error("No supported hypervisor found for QEMU backend");
        args.push_back("-accel");
        std::string def_protected = "PROTECTED_NORMAL";
        if (*hypervisor == "KVM") args.push_back("kvm");
        else if (*hypervisor == "GUNYAH") {
            args.push_back("gunyah");
            def_protected = "PROTECTED_WITHOUT_FIRMWARE";
        } else if (*hypervisor == "SOFT") args.push_back("tcg,thread=multi,tb-size=128");
        else throw std::invalid_argument("Unsupported hypervisor: " + *hypervisor);
        const bool soft = *hypervisor == "SOFT";
        auto machine = string(item, "machine_type", "virt");
        auto protection = java_enum(item, "protected_vm", def_protected.c_str(), protections);
        if (soft) protection = "PROTECTED_NORMAL";
        const bool confidential = protection == "PROTECTED_PROTECTED" || protection == "PROTECTED_WITHOUT_FIRMWARE";
        if (confidential) machine += ",confidential-guest-support=prot0";
        add({"-machine", machine});
        std::string cpu = soft ? string(item, "cpu_model", "cortex-a710") : "host";
        if (!boolean(item, "pmu", false)) cpu += ",pmu=off";
        add({"-cpu", cpu});
        const auto cpus = std::max<int64_t>(integer(item, "cpu_count", 1), 1);
        const int64_t threads = boolean(item, "smt", true) && cpus % 2 == 0 ? 2 : 1;
        add({"-smp", decimal(cpus) + ",sockets=1,cores=" + decimal(cpus / threads) + ",threads=" + decimal(threads)});
        add({"-m", decimal(std::max<int64_t>(integer(item, "memory_mb", 512), 64)) + "M"});
        if (confidential)
            add({"-object", "arm-confidential-guest,id=prot0,swiotlb-size=" + decimal(std::max<int64_t>(integer(item, "swiotlb_mb", 256), 1)) + "M"});
        if (boot.uefi) {
            add({"-bios", boot.firmware.empty() ? path_join(root, "/usr/share/droidvm/edk2-qemu.fd") : boot.firmware});
            if (boot.vars_enabled)
                add({"-drive", "file=" + (boot.vars.empty() ? path_join(root, "/usr/share/droidvm/edk2-gunyah.vars.fd") : boot.vars) + ",if=pflash,format=raw"});
        }
        if (!boot.kernel.empty()) add({"-kernel", boot.kernel});
        if (!boot.initrd.empty()) add({"-initrd", boot.initrd});
        if (!boot.cmdline.empty()) add({"-append", boot.cmdline});
        if (boolean(item, "hugepages", true)) args.push_back("-mem-prealloc");
        if (!agent && boolean(item, "rng", true))
            add({"-object", "rng-random,filename=/dev/urandom,id=rng0", "-device", std::string("virtio-rng-pci,rng=rng0,") + pci});
        if (boolean(item, "balloon", false)) add({"-device", std::string("virtio-balloon-pci,") + pci});
        if (!agent) {
            input();
            usb();
        }
        disks();
        if (!agent) {
            networks();
            shared_dirs();
            audio();
            gpu();
            vnc();
        } else {
            add({"-chardev", "socket,id=agent0,path=" + or_null(run.agent_socket_path) + ",server=on,wait=off"});
            add({"-device", "virtio-serial-pci,id=agent-bus," + std::string(pci)});
            add({"-device", "virtconsole,chardev=agent0,name=org.droidvm.agent"});
        }
        add({"-chardev", "socket,id=uart0,path=" + or_null(run.uart_socket_path) + ",server=on,wait=on", "-serial", "chardev:uart0"});
        add({"-qmp", "unix:" + or_null(run.qmp_socket_path) + ",server,nowait", "-nodefaults"});
        extra_options(item, args);
    }
};
}

QemuRun qemu_sockets(const Json::Value& config, const HostFacts& host) {
    const auto& name = member(config, "name");
    const auto prefix = path_join(data_dir(host), "run", name.isString() ? name.asString() : "null");
    QemuRun run;
    run.qmp_socket_path = prefix + "-qmp.sock";
    run.uart_socket_path = prefix + "-uart.sock";
    if (boolean(config, "agent_mode", false)) run.agent_socket_path = prefix + "-agent.sock";
    return run;
}
QemuLaunch qemu_command(const Json::Value& config, const QemuRun& run, const BootPlan& boot, const HostFacts& host) {
    if (!config.isObject()) throw std::invalid_argument("VM config must be an object");
    // The constructor's console streams read their logs by config.getId().
    config::uuid(config);
    QemuLaunch launch;
    launch.agent = boolean(config, "agent_mode", false);
    Builder builder{config, run, boot, host, launch.agent, {}, 0, 0};
    builder.command(launch);
    launch.argv = std::move(builder.args);
    if (run.disk_graph) {
        launch.preserve_fds = run.disk_graph->preserve_fds;
        for (const auto& [path, fd] : run.direct_disk_fds) launch.preserve_fds.push_back(fd);
    }
    process_environment(config, host, launch.env);
    return launch;
}
}
