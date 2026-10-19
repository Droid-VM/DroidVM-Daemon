// SPDX-License-Identifier: GPL-3.0-or-later
#include "vm/defaults.h"
#include <iostream>
#include <stdexcept>

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
}
int main() {
    try {
        const auto gunyah = droidvm::vm::new_vm_defaults("/test/app/", "GUNYAH", " sm8650 ");
        const auto kvm = droidvm::vm::new_vm_defaults("/test/app", "KVM", "unknown");
        const auto gz = droidvm::vm::new_vm_defaults("/test/app", "GENIEZONE", "SM8850");
        require(gunyah["id"].asString().size() == 36 && gunyah["id"] != kvm["id"], "fresh UUIDs");
        require(gunyah["created_at"].asInt64() > 0 && gunyah["name"] == "", "draft identity");
        require(gunyah["hypervisor"] == "gunyah" && gunyah["protected_vm"] == "pseudo_unprotected", "Gunyah protection");
        require(kvm["protected_vm"] == "protected_normal" && gz["hypervisor"] == "geniezone", "hardware defaults");
        require(gunyah["prepare_lend_mthp"] == "single" && kvm["prepare_lend_mthp"] == "chunked"
            && gz["prepare_lend_mthp"] == "chunked", "SoC capability selection");
        require(gunyah["boot"]["linux"]["kernel"] == "/test/app/usr/share/droidvm/vmlinuz", "host kernel path");
        require(gunyah["boot"]["linux"]["initrd"] == "/test/app/usr/share/droidvm/initramfs.img", "host initrd path");
        require(gunyah["backend"] == "crosvm" && gunyah["memory_mb"] == 512 && gunyah["cpu_count"] == 1, "App template");
        require(!gunyah["auto_up"].asBool() && gunyah["disks"].empty() && gunyah["networks"].empty(), "no host attachments");
        require(gunyah["peripherals"].size() == 2 && gunyah["serial_ports"].size() == 4, "default devices");
        std::cout << "VM defaults contract passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
