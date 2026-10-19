// SPDX-License-Identifier: GPL-3.0-or-later
#include "vm_lifecycle.h"
#include "vm.h"
#include "vm_config.h"
#include "store/vm_config.h"
#include "vm/crosvm_command.h"
#include <unistd.h>

namespace droidvm {
VmLifecycleService::VmLifecycleService(VmConfigService& config, VmService& runtime)
    : VmLifecycleService(Dependencies{
        [&config](const CallContext& caller) { return config.snapshot(caller); },
        [&config](const CallContext& caller, const Snapshot& observed) {
            return config.replace(caller, observed->revision, observed->document);
        },
        [](const Json::Value& row) {
            vm::HostFacts facts;
            facts.has_kvm = access("/dev/kvm", F_OK) == 0;
            facts.has_gunyah = access("/dev/gunyah", F_OK) == 0;
            return config::java_enum(row, "backend", "CROSVM", {"CROSVM", "QEMU"}) == "CROSVM" && vm::resolves_to_gunyah(row, facts);
        },
        [&runtime](const CallContext& caller, const ConfiguredVmStart& request, const Json::Value& row) {
            return runtime.start_configured(caller, request.vm_id, row, request.overrides,
                request.boot_entry.empty() ? std::nullopt : std::optional(request.boot_entry), request.clear_logs, request.observed);
        }
    }) {}
}
