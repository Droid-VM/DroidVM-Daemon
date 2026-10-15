// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "common/fd.h"
#include <sys/types.h>
#include <string>

namespace droidvm {
// The caller supplies an existing app-owned data directory. Keep directory FDs
// pinned so later opens do not resolve the supplied pathname again.
class RuntimeLayout {
public:
    explicit RuntimeLayout(const std::string& data_directory);
    Fd take_run_directory() { return std::move(run_); }
    int cache_fd() const { return cache_.get(); }
    uid_t owner() const { return owner_; }
    // Call only after taking the instance lock.
    void prepare_cache();
    Fd open_files();
private:
    Fd data_, run_, cache_;
    uid_t owner_;
    bool cache_created_ = false;
};
}
