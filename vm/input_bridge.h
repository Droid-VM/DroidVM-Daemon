// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "vm/crosvm_command.h"
#include "common/fd.h"
#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace droidvm::vm {
// NativeDisplayInputBridge: crosvm is the client of each --input socket, so
// they are bound before it starts and fed the UI's evdev bytes (vm_input).
// Keyboard-channel peers send 8-byte LED status records back.
class InputBridge {
public:
    using Status = std::function<void(const std::string& screen, int channel, std::string records)>;
    ~InputBridge();
    // True when every socket listens; a failed bind is skipped as legacy.
    bool listen(const std::vector<InputSocket>& sockets, Status status = {});
    bool write(const std::string& screen, int channel, std::string_view data);
    void release();
private:
    struct Slot {
        InputSocket socket;
        Fd server;
        std::shared_ptr<Fd> peer;
        std::mutex lock;
        std::thread acceptor;
        std::vector<std::thread> readers;
    };
    std::mutex mutex_;
    std::map<std::string, std::unique_ptr<Slot>> slots_;
    std::atomic<bool> closed_{false};
    Status status_;
    static std::string key(const std::string& screen, int channel);
    void accept(Slot& slot);
};
}
