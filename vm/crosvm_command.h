// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "vm/boot_plan.h"
#include <json/json.h>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// Port of CrosvmBackendInstance.buildCommand plus the environment set up by
// prepareProcess/applyGfxstreamEnv/applyDisplayBlitEnv/applyGpuRtPrioEnv.
// Pure: every host read and per-launch value is an explicit input.
//
// config_probe fixture ("op":"crosvm"); absent fields keep struct defaults,
// null means "absent" for optional fields:
//   {"op":"crosvm","name":"...","config":{VM config, pre-migration},
//    "run":{"control_socket_path":s,"gpu_cgroup_path":s,
//           "serials":[{"pipe_output_fd":n,"pipe_input_fd":n,"acm_dev_path":s},...],
//           "vnc":{"<screen id>":{"host":s,"port":n,"password":s}}},
//    "boot":{"uefi":b,"firmware":s,"vars":s,"vars_enabled":b,"kernel":s,"initrd":s,"cmdline":s},
//    "host":{"data_dir":s,"has_kvm":b,"has_gunyah":b,"has_gzvm":b,"soc_name":s,
//            "app_uid":n,"app_gids":[n,...],"cpu_cores":[{"index":n,"capacity":n},...],
//            "pflash_vars_size":n,"android_release":s,"strace_prebuilt_exists":b,
//            "strace_in_path":s,"optimize_sdcard":b,"turnip_exists":b,
//            "system_vulkan_hal":s,"viosnd_dump_exists":b}}
// Output: {"name":...,"status":"ok","argv":[...],"env":[["KEY","VALUE"],...]}
// or {"name":...,"status":"error","message":...}.
namespace droidvm::vm {
struct CpuCore {
    int index = 0; // CpuUtils.CpuCore.index
    int64_t capacity = 0; // CpuUtils.CpuCore.capacity
};
struct HostFacts {
    std::string data_dir; // Constants.DATA_DIR; empty = compile-time /data/data/<package>
    bool has_kvm = false; // VMHypervisor.KVM.isSupported(): shellCheckExists("/dev/kvm")
    bool has_gunyah = false; // VMHypervisor.GUNYAH.isSupported(): shellCheckExists("/dev/gunyah")
    bool has_gzvm = false; // VMHypervisor.GENIEZONE.isSupported(): shellCheckExists("/dev/gzvm")
    std::optional<std::string> soc_name; // HostSocName.get()
    int app_uid = -1; // CrosvmBackendInstance.getAppUid()
    std::optional<std::vector<int>> app_gids; // AppGroups.resolve(app_uid), only read when app_uid > 0
    std::vector<CpuCore> cpu_cores; // CpuUtils.getCores()
    int64_t pflash_vars_size = 0; // new File(<vars path>).length() in pflashBlockSize
    std::string android_release; // Build.VERSION.RELEASE
    bool strace_prebuilt_exists = false; // new File(getPrebuiltBinaryPath("strace")).exists()
    std::optional<std::string> strace_in_path; // FileUtils.findExecute("strace", null)
    bool optimize_sdcard = true; // context.appConfig.optBoolean(KEY_OPTIMIZE_SDCARD, true)
    bool turnip_exists = false; // new File(DATA_DIR/usr/lib/libvulkan_freedreno.so).exists()
    std::optional<std::string> system_vulkan_hal; // resolveSystemVulkanHal()
    bool viosnd_dump_exists = false; // new File("/data/local/tmp/viosnd_dump").exists()
};
struct SerialRun {
    std::optional<std::pair<int, int>> pipe; // ResolvedSerial.pipe: {getOutputRemoteFd(), getInputRemoteFd()}
    std::optional<std::string> acm_dev_path; // ResolvedSerial.acmDevPath
};
struct VncRun {
    std::optional<std::string> host; // VMScreenConfig.setVncHost before start
    std::optional<int64_t> port; // VMInstance.resolveVncConfig setVncPort
    std::optional<std::string> password; // VMInstance.resolveVncConfig setVncPassword
};
struct CrosvmRun {
    // Managed disks must use the same paths admitted by the file lease.
    bool preserve_disk_paths = false;
    // Retained leaf descriptors. No pathname fallback is allowed when present.
    std::optional<std::map<std::string, int>> disk_fds;
    // Immediate parent first; empty explicitly requires a root image. Requires
    // the crosvm backing-chain extension for block/SCSI (PMEM remains raw).
    std::optional<std::map<std::string, std::vector<int>>> disk_backing_fds;
    std::optional<std::string> control_socket_path; // CrosvmBackendInstance.controlSocketPath
    std::optional<std::string> gpu_cgroup_path; // gpuCgroupPath after prepareGpuCgroup()
    std::vector<SerialRun> serials; // resolvedSerials, index-aligned with serial_ports; missing = unresolved
    std::map<std::string, VncRun> vnc; // per screen id, overrides screens.<id>.vnc
};
// NativeDisplay channels: MULTITOUCH 0, KEYBOARD 1, MOUSE 2, TABLET 3.
struct InputSocket { std::string screen; int channel = 0; std::string path; };
struct CrosvmLaunch {
    std::vector<std::string> argv;
    std::vector<int> preserve_fds;
    // NativeProcess.Builder.environment calls in order; later keys win when merged.
    std::vector<std::pair<std::string, std::string>> env;
    std::optional<std::string> strace_dir; // getStraceFolder(): caller recreates the directory
    std::optional<int64_t> udmabuf_limit_mb; // applyGfxstreamEnv's size_limit_mb write, left to the caller
    bool input_bridge = false; // isInputBridgeNeeded()
    std::vector<std::string> touch_screens, native_input_screens; // touchscreenScreens()/nativeInputScreens()
    std::vector<InputSocket> input_sockets; // every socket the input bridge pre-binds
};
// Expects droidvm::config::migrate_vm output. Throws std::runtime_error or
// std::invalid_argument where the Java start would fail.
CrosvmLaunch crosvm_command(const Json::Value& config, const CrosvmRun& run, const BootPlan& boot, const HostFacts& host);
// PoolPreflight.appliesTo: the configured or preferred hypervisor is Gunyah.
bool resolves_to_gunyah(const Json::Value& item, const HostFacts& host);
// GuestPoolSizing.bootGuestPreallocMb, budgeted by the huge-page preflight.
int64_t boot_guest_prealloc_mb(const Json::Value& item);
// VMScreenConfig.getTransportCap().getToken() for vm_vnc_info.
std::string screen_transport_cap(const Json::Value& config, const std::string& id);
}
