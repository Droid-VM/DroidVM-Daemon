// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <functional>
#include <string>

namespace droidvm {
struct AndroidDisplayIo;
struct AndroidRescueStatus {
    std::string adapter; // empty = no observed boot-loop counter implementation
    std::string reason;  // nonempty = detected but unsafe/unverified; never bypass
};
inline constexpr const char* rescue_module = "/apex/com.android.crashrecovery/javalib/service-crashrecovery.jar";
inline constexpr const char* rescue_count = "crashrecovery.rescue_boot_count";
inline constexpr const char* rescue_start = "crashrecovery.rescue_boot_start";
inline constexpr const char* rescue_adapter = "crashrecovery-4533611d-v1";
AndroidRescueStatus android_rescue_probe(
    const std::function<bool(const std::string&)>& exists,
    const std::function<std::string(const std::string&)>& sha256,
    const std::function<std::string(const std::string&)>& property);
// Only the sentinel performs accounting, after the old framework has exited.
// A temporary zero admits one expected noteBoot(); prior in-window history is
// returned immediately afterwards, plus any additional real restart observed.
// No RescueParty disable flag, mitigation counter or persistent file is changed.
class AndroidRescueRestart {
public:
    AndroidRescueRestart(const AndroidDisplayIo&, const std::string& adapter);
    ~AndroidRescueRestart();
    void verify_access(); // same-value write/readback before Android is touched
    void arm();
    void finish(int old_pid, const std::string& old_start);
    void cancel();
private:
    const AndroidDisplayIo& io_;
    bool enabled_ = false, armed_ = false;
    std::string original_count_, original_start_;
    int history_ = 0;
    void reconcile(bool expected_boot);
};
}
