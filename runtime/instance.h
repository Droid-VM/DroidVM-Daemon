// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "common/fd.h"
#include <string>
#include <string_view>

namespace droidvm {
std::string random_id(bool uuid);
std::string apk_sha256(const std::string& path);
class Instance {
public:
    explicit Instance(const std::string& directory, bool force);
    ~Instance();
    void publish(std::string_view name, std::string_view value);
    void publish_discovery(unsigned port, const std::string& token);
    bool token_exists() const;
    std::string read_token() const;
    Instance(const Instance&) = delete;
    Instance& operator=(const Instance&) = delete;
private:
    Fd directory_, lock_;
    bool owns_ = false, published_ = false;
    bool try_lock();
    int lock_owner() const;
};
}
