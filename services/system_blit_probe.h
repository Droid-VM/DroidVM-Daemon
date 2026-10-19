// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <atomic>
#include <json/json.h>
#include <mutex>
#include <thread>

namespace droidvm {
// Lazy, once per daemon lifetime, isolated driver observation. HTTP never
// waits for Vulkan; reads observe the cached pending/final result.
class SystemBlitProbe {
public:
    SystemBlitProbe();
    ~SystemBlitProbe();
    Json::Value snapshot();
    static int child_main();
private:
    std::atomic<bool> stopping_{false};
    std::mutex mutex_;
    std::thread worker_;
    bool started_ = false;
    Json::Value value_;
    void run() noexcept;
};
}
