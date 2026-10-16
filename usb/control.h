// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// Port of daemon/usb/CrosvmUsbControl. The wire is the bundled crosvm CLI,
// not the control socket itself: crosvm opens the usbfs node in its own
// process and passes the fd across, so the fd has to come from a crosvm.
//   crosvm usb attach 0:0:0:0 <node> <socket>  -> "ok <port>" | "<token>"
//   crosvm usb detach <port> <socket>          -> "ok <port>" | "<token>"
//   crosvm usb list <socket>                   -> "devices [<port> <vid> <pid>]..." | "<token>"
// One line on stdout; "failed to connect to socket" on stderr when the CLI
// never reached the VMM.
namespace droidvm::usb {
// IOException: the CLI or its transport failed.
class ControlIoError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};
// UsbVmmUnreachableException: the CLI could not connect to the socket.
class VmmUnreachable : public ControlIoError {
public:
    explicit VmmUnreachable(const std::string& stderr_text);
};
// UsbControlException: crosvm answered with a refusal token.
class ControlRefused : public std::runtime_error {
public:
    ControlRefused(std::string token, std::string stderr_text = {})
        : std::runtime_error(token), token(std::move(token)), stderr_text(std::move(stderr_text)) {}
    const std::string token, stderr_text;
};
struct ListEntry { int port = 0; std::string vid, pid; };

class UsbControl {
public:
    virtual ~UsbControl() = default;
    // Each throws ControlRefused, VmmUnreachable or ControlIoError.
    virtual int attach(const std::string& socket, const std::string& node) = 0;
    virtual int detach(const std::string& socket, int port) = 0;
    virtual std::vector<ListEntry> list(const std::string& socket) = 0;
    // controlSocketReady: a SEQPACKET connect and close, nothing said.
    virtual bool ready(const std::string& socket);
};

// The production channel: <data_dir>/usr/bin/crosvm with the VMM's loader
// environment (LD_PRELOAD libsimpledump + libcompat_a<release>, LD_LIBRARY_PATH).
class CrosvmCli : public UsbControl {
public:
    CrosvmCli(std::string data_dir, std::string android_release, std::chrono::milliseconds timeout = std::chrono::seconds(15));
    int attach(const std::string& socket, const std::string& node) override;
    int detach(const std::string& socket, int port) override;
    std::vector<ListEntry> list(const std::string& socket) override;
    // The argv/env a command runs with (for logging and probes).
    std::vector<std::string> argv(const std::vector<std::string>& args) const;
    std::vector<std::pair<std::string, std::string>> environment() const;
private:
    std::string data_dir_, release_;
    std::chrono::milliseconds timeout_;
    std::pair<std::string, std::string> run(const std::vector<std::string>& args) const;
};

// The pure parsers, exactly as the legacy static helpers.
int parse_ok_port(const std::string& stdout_text);
std::vector<ListEntry> parse_list(const std::string& stdout_text);
bool is_unreachable(const std::string& stderr_text);
std::optional<std::string> first_error_line(const std::string& text);
std::string attach_failure_message(const std::string& token, const std::string& cli_stderr, const std::string& vmm_log);
// requireOutput: throws VmmUnreachable or ControlIoError for an empty stdout.
void require_output(const std::string& stdout_text, const std::string& stderr_text);
}
