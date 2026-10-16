// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

namespace droidvm::platform {
// HostAudioTable: keeps <run>/audio_devices current for crosvm's audio
// backend, which re-resolves a pinned endpoint by its stable key on each
// stream open. Polls the native AudioSystem snapshot (P1 audio probe) and
// atomically replaces the file whenever the table or service changes; the
// default rows are published while audio_policy is unavailable.
class AudioTable {
public:
    using Log = std::function<void(const std::string&)>;
    ~AudioTable();
    bool start(int run_directory, Log log = {}); // false when Binder APIs are missing
    void stop();
    unsigned publications() const { return publications_; }
private:
    int directory_ = -1;
    Log log_;
    std::thread worker_;
    std::mutex mutex_;
    std::condition_variable wake_;
    bool stopping_ = false;
    std::atomic<unsigned> publications_{0};
    void run();
};
}
