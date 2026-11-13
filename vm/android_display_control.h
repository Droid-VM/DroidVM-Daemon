// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <memory>
#include <string>

namespace droidvm::vm {
// Android display ownership for a KMS-exported VM. The host service stops the
// Android display stack before crosvm is spawned and restores it after crosvm
// has exited; crosvm itself never mutates Android (takeover=external).
class AndroidDisplayLease {
public:
    virtual ~AndroidDisplayLease() = default;
    // The VMM pid the sentinel kills before any forced restoration.
    virtual void watch(int pid) = 0;
};
class AndroidDisplayControl {
public:
    virtual ~AndroidDisplayControl() = default;
    // Blocks for the stop sequence (seconds). Throws std::runtime_error when
    // Android cannot be stopped; nothing is left half-stopped in that case.
    // Destroying the lease starts restoration without blocking the caller.
    virtual std::unique_ptr<AndroidDisplayLease> acquire(const std::string& vm_id, const std::string& vm_name, bool stop_zygote = false) = 0;
};
}
