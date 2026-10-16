// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <optional>
#include <string>

namespace droidvm::vm {
// daemon/vm/BootPlan: firmware to run, or a kernel/initrd/cmdline to boot.
struct BootPlan {
    bool uefi = false;
    std::string firmware, vars; // empty = builtin EDK2 firmware / vars
    bool vars_enabled = false;
    std::string kernel, initrd, cmdline;
    std::optional<std::string> entry_title; // image mode: entry actually booted
    bool entry_fallback = false; // image mode: pinned/override entry missing
};
struct BootTools {
    std::string lbx; // AssetUtils.getAssetBinaryPath("lbx")
    std::string cache_root; // DATA_DIR/cache/boot
};
// The legacy constants are built from the compile-time DATA_DIR, not the
// daemon's --data-dir spelling, so paths stay byte-identical.
const std::string& builtin_kernel();
const std::string& builtin_initrd();
const std::string& edk2_firmware();
const std::string& edk2_vars();
inline constexpr const char* builtin_entry_key = "@droidvm:builtin-kernel";
// BootPlan.resolve. Like BootConfig's accessors it creates the boot/uefi/
// linux/image objects it reads. Image mode runs lbx and extracts into
// cache_root/<vm id>; failures throw std::runtime_error with the legacy text.
BootPlan resolve_boot(Json::Value& config, const std::optional<std::string>& entry_override, const BootTools& tools);
// lbx entries --json for one image (vm_bootscan).
Json::Value scan_boot_entries(const std::string& lbx, const std::string& image);
}
