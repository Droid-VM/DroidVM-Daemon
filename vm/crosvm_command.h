// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "vm/boot_plan.h"
#include "vm/vnc_stream.h"
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
//            "app_uid":n,"app_gids":[n,...],"cpu_cores":[{"index":n,"capacity":n,"max_frequency_khz":n},...],
//            "pflash_vars_size":n,"android_release":s,"strace_prebuilt_exists":b,
//            "strace_in_path":s,"optimize_sdcard":b,"turnip_exists":b,
//            "system_vulkan_hal":s,"viosnd_dump_exists":b,"crosvm_uvc_camera":b,
//            "crosvm_motion_magnetometer":b,"crosvm_virtio_mmio_snd":b,
//            "crosvm_serial_name":b,"crosvm_input_vibrator":b,"crosvm_mbi_spis":b,
//            "firmware_code_offset":n,"crosvm_sound_performance":b,
//            "crosvm_virtio_mmio_console":b,"crosvm_media_backend":b,
//            "crosvm_media_vidc":b}}
// Output: {"name":...,"status":"ok","argv":[...],"env":[["KEY","VALUE"],...]}
// or {"name":...,"status":"error","message":...}.
namespace droidvm::vm {
struct CpuCore {
    int index = 0; // CpuUtils.CpuCore.index
    int64_t capacity = 0; // CpuUtils.CpuCore.capacity
    // cpuinfo_max_freq; 0 = unknown (no cpufreq). Cores of one value share a
    // frequency domain (CpuUtils.CpuCore.tier).
    int64_t max_frequency_khz = 0;
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
    // droidvm.virtiomedia / droidvm.virtiomedia.hostmb: a host-side override on
    // top of a VM's own vpu_enabled / vpu_host_pool_mb (VpuConfig). The
    // properties are runtime-only and die with the tablet, so they can only
    // override, never replace, the persisted per-VM choice.
    std::optional<bool> virtio_media_override; // absent = follow the VM config
    std::optional<int64_t> virtio_media_host_mb_override; // 1..65536 MiB
    // The installed crosvm lists --uvc-camera in `run --help`. Builds without
    // it reject the whole command line, so camera rows are skipped instead.
    bool crosvm_uvc_camera = false;
    // The installed crosvm's motion device takes magnetometer=BOOL (its
    // `run --help` lists it). Without it the device is emitted without the
    // magnetometer rather than refused.
    bool crosvm_motion_magnetometer = false;
    // The installed crosvm lists --virtio-mmio-snd; an MMIO VM's sound cards
    // stay on PCI without it.
    bool crosvm_virtio_mmio_snd = false;
    // The installed crosvm's --serial takes name=NAME (a named virtio-console
    // port). Without it the GNSS receiver's port is left out.
    bool crosvm_serial_name = false;
    // The installed crosvm's --input takes the vibrator device (a
    // force-feedback virtio-input device). Without it the row is skipped.
    bool crosvm_input_vibrator = false;
    // The installed crosvm lists --mbi-spis (a GICv2m-style MSI frame for
    // Gunyah). Without it a Gunyah VM's PCI devices keep INTx.
    bool crosvm_mbi_spis = false;
    // firmware_code_offset() of the UEFI image this launch boots (the
    // configured firmware or edk2-gunyah.fd); -1 unknown or not an
    // edk2-gunyah-style image. Only read for a UEFI boot.
    int64_t firmware_code_offset = -1;
    // The installed crosvm's AAudio backend knows a sound endpoint's
    // performance= attribute (power_saving|none|low_latency in host_device
    // after '#'). It is not in `run --help`; the launcher looks for the
    // values in the binary. Without it the attribute is stripped.
    bool crosvm_sound_performance = false;
    // The installed crosvm lists --virtio-mmio-console; an MMIO VM's
    // virtio-console ports stay on PCI without it.
    bool crosvm_virtio_mmio_console = false;
    // The installed crosvm's virtio-media codec devices take backend=NAME
    // (mediacodec|auto|msm-vidc). A value inside the option string, so the
    // launcher looks for "msm-vidc" in the binary itself.
    bool crosvm_media_backend = false;
    // The installed crosvm's decoder takes vidc=BOOL (`run --help` lists
    // "vidc="): the older spelling of the msm_vidc decoder backend, which has
    // no AUTO and no encoder choice.
    bool crosvm_media_vidc = false;
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
    // KMS exporter: the host touch node crosvm grabs directly (evdev). Resolved
    // by the launcher; absent means the screen gets no touch input at all.
    std::optional<std::string> kms_touch_device;
    // The read end of the VM's GNSS port (GnssPort): a VIRTIO_GNSS row's
    // named virtio-console port takes its input from it. Absent: no receiver.
    std::optional<int> gnss_input_fd;
};
// A --webrtc-server listener: crosvm serves its viewer page at http://host:port/?token=.
struct WebrtcEndpoint {
    std::string screen, host;
    int64_t port = -1;
    std::string token;
    bool input_enabled = true;
};
// NativeDisplay channels: MULTITOUCH 0, KEYBOARD 1, MOUSE 2, TABLET 3, SENSOR 4
// (the VM-wide motion sensors a console overrides crosvm's host readings with),
// PEN 5 and TRACKPAD 6 (reserved for the console's pen and trackpad), VIBRATOR 7
// (VM-wide; nothing is written to it, the guest's rumble is read back from it).
inline constexpr int input_channel_vibrator = 7;
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
    std::vector<VncEndpoint> vnc_endpoints; // Exact listeners emitted by this launch.
    std::vector<WebrtcEndpoint> webrtc_endpoints;
    // Set when a screen is exported straight to the panel (--kms-display). The
    // launcher must own the Android display before spawning this command.
    bool kms = false;
    // Devices left out or reduced because the installed crosvm cannot take
    // them; the launcher logs each one.
    std::vector<std::string> warnings;
    // The GNSS port is on the command line: the launcher hands the pipe to
    // the hub once crosvm runs (and drops it otherwise).
    bool gnss = false;
};
// The gpu-0 screen is exported to the panel over DRM/KMS. Throws
// std::invalid_argument for combinations crosvm would refuse.
bool crosvm_kms_screen(const Json::Value& config);
// Screen keys of the KMS exporter; absent fields keep these defaults.
inline constexpr const char* kms_card_default = "/dev/dri/card0";
// Expects droidvm::config::migrate_vm output. Throws std::runtime_error or
// std::invalid_argument where the Java start would fail.
CrosvmLaunch crosvm_command(const Json::Value& config, const CrosvmRun& run, const BootPlan& boot, const HostFacts& host);
bool crosvm_retained_chain_supported(const Json::Value& capabilities);
// PoolPreflight.appliesTo: the configured or preferred hypervisor is Gunyah.
bool resolves_to_gunyah(const Json::Value& item, const HostFacts& host);
// What the huge-page preflight budgets beside --mem: GuestPoolSizing.
// bootGuestPreallocMb plus boot_media_guest_mb (PoolPreflight.neededPages).
int64_t boot_guest_prealloc_mb(const Json::Value& item);
// VpuConfig.bootMediaGuestMb: the media-guest-mb a VM is passed at boot -- the
// VM's own VPU switch on and a protection mode whose memory the host cannot
// read (an absent protected_vm is a Gunyah VM's default,
// PROTECTED_WITHOUT_FIRMWARE) -- else 0. The host pool is not counted: it is
// consume_system_mem and comes out of --mem. Read from the config alone, so
// the virtio-media system-property override never adds an unbudgeted pool.
int64_t boot_media_guest_mb(const Json::Value& item);
// VMScreenConfig.getTransportCap().getToken() for vm_vnc_info.
std::string screen_transport_cap(const Json::Value& config, const std::string& id);
}
