// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "input/keyboard_grab.h"
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace droidvm::platform {
// NativeDisplayBinder: the daemon-hosted INativeDisplayRootService. It looks
// up the per-screen display binder crosvm registers (an untrusted_app cannot),
// writes evdev straight to the VM's input sockets and owns the console's
// keyboard grab. display_attach broadcasts it to the requesting UI.
class DisplayBroker {
public:
    struct Hooks {
        // VMState.name() of a known VM, nullopt when unknown.
        std::function<std::optional<std::string>(const std::string& vm)> state;
        // VMInstance.writeNativeInput: false unless RUNNING and delivered.
        std::function<bool(const std::string& vm, const std::string& screen, int channel, std::string_view data)> write_input;
        input::KeyboardGrab* keyboard = nullptr;
        std::string package; // broadcast target, the app's APPLICATION_ID
        std::function<void(const std::string& level, const std::string& text)> log = [](const std::string&, const std::string&) {};
    };
    explicit DisplayBroker(Hooks hooks);
    ~DisplayBroker();
    // NativeDisplayBinder.attach: build the broker once and broadcast it with
    // nonce. Failures are logged, as the legacy handler returns success.
    void attach(const std::string& nonce);
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
