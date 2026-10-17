// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "vm/boot_plan.h"
#include "vm/crosvm_command.h"
#include <json/json.h>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// Port of QemuBackendInstance.buildCommand plus the environment set up by
// VMBackendInstance.prepareProcess. Pure: every host read and per-launch
// value is an explicit input.
//
// config_probe fixture ("op":"qemu"); absent fields keep struct defaults:
//   {"op":"qemu","name":"...","config":{VM config, pre-migration},
//    "run":{"qmp_socket_path":s,"uart_socket_path":s,"agent_socket_path":s,
//           "vnc":{"<screen id>":{"host":s,"port":n,"password":s}}} or "start",
//    "boot":{as for "crosvm"},"host":"probe" or {as for "crosvm"},"prepare_process":b}
// "run":"start" takes the socket paths from qemu_sockets.
// Output: {"name":...,"status":"ok","argv":[...],"env":[["KEY","VALUE"],...]}
// or {"name":...,"status":"error","message":...}.
namespace droidvm::vm {
struct QemuDiskImage {
    int fd = -1; // Borrowed, >= 3; caller retains lease and preserves FD across exec.
    std::string format; // Actual inspected format, not filename extension.
    std::optional<std::string> parent; // Key of another entry, never a header path.
    bool readonly = true;
};
struct QemuDiskGraph {
    std::vector<std::string> argv;
    std::map<std::string, std::string> nodes;
    std::vector<int> preserve_fds;
};
// Parent-first, explicit graph. qcow2 roots have backing=null, so QEMU never
// follows an implicit backing filename. No filesystem opens in this builder.
// Caller must verify metadata and reject auxiliary dependencies not represented
// here (for example qcow2 external data files) before constructing this input.
QemuDiskGraph qemu_disk_graph(const std::map<std::string, QemuDiskImage>& images);
struct QemuRun {
    // Set by QemuBackendInstance.start(); unset renders as Java's "null".
    std::optional<std::string> qmp_socket_path, uart_socket_path, agent_socket_path;
    std::map<std::string, VncRun> vnc; // per screen id, overrides screens.<id>.vnc
    // new File(path).length() for PMEM disks (0 when missing); null = always 0.
    std::function<int64_t(const std::string&)> file_length;
    // Managed disks must use the same paths admitted by the file lease.
    bool preserve_disk_paths = false;
};
struct QemuLaunch {
    std::vector<std::string> argv;
    // NativeProcess.Builder.environment calls in order; later keys win when merged.
    std::vector<std::pair<std::string, std::string>> env;
    std::optional<std::string> strace_dir; // getStraceFolder(): caller recreates the directory
    // agent_mode: QEMU serves the agent socket (connect it before the UART).
    bool agent = false;
};
// The socket paths start() assigns: DATA_DIR/run/<name>-{qmp,uart,agent}.sock,
// the agent one only in agent_mode. The caller deletes stale files.
QemuRun qemu_sockets(const Json::Value& config, const HostFacts& host);
// Expects droidvm::config::migrate_vm output. Throws std::runtime_error or
// std::invalid_argument where the Java constructor or start would fail.
QemuLaunch qemu_command(const Json::Value& config, const QemuRun& run, const BootPlan& boot, const HostFacts& host);
}
