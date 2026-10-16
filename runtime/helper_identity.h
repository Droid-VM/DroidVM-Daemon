// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "child.h"
#include "store/json_file.h"

namespace droidvm {
// One launch per private runtime directory. The caller holds the instance
// lock and keeps the directory until recovery succeeds. Tools must retain the
// explicitly inherited identity FD; this does not adopt arbitrary descendants.
class HelperIdentity {
public:
    using Observer = std::function<void(const char*)>;
    HelperIdentity(int directory, uid_t owner, Observer observer = {});
    // Keep this object alive until Child construction/ManagedProcess::start
    // returns; the prepared callback and inherited FD belong to this object.
    void arm(ChildOptions& options);
    // Reopen the journal after owner death, verify birth + inherited FD, then
    // TERM/KILL only that pidfd. Missing/reused PIDs are harmless; unverifiable
    // live identities fail closed. Does not remove the caller's runtime files.
    static void recover(int directory, uid_t owner, std::chrono::milliseconds grace = std::chrono::seconds(3));
private:
    Fd directory_, marker_;
    uid_t owner_;
    Observer observer_;
    bool armed_ = false;
};
}
