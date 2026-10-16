// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "backend.h"
#include "runtime/managed_process.h"
#include "control_http.h"

namespace droidvm::network {
// One real gvswitch data path. VM port/forward attachment is added by the VM
// integration; this class currently owns only the switch and its runtime files.
class Gvswitch final : public Backend {
public:
    Gvswitch(std::string executable, int run_directory);
    ~Gvswitch() override;
    void start(const Json::Value& config) override;
    bool healthy() const override;
    void recover(const Json::Value& config) override;
    void stop() override;
    ProcessStatus status() const { return process_.status(); }
    std::deque<ProcessLine> log() const { return process_.log(); }
    // Administrative lifecycle control uses held pidfd, never a raw PID.
    bool signal(int number) { return process_.signal(number); }
private:
    std::string executable_, directory_name_;
    Fd parent_, directory_;
    ManagedProcess process_;
    std::unique_ptr<ControlHttp> client_;
    bool ready_ = false;
    void remove_directory();
};
}
