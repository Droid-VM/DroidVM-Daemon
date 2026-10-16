// SPDX-License-Identifier: GPL-3.0-or-later
#include "usb/control.h"
#include "usb/java.h"
#include "common/fd.h"
#include "runtime/child.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <algorithm>
#include <regex>

extern char** environ;

namespace droidvm::usb {
namespace {
constexpr const char* connect_failed = "failed to connect to socket";
std::vector<std::string> lines(const std::string& text) {
    std::vector<std::string> out;
    size_t start = 0;
    while (true) {
        const auto nl = text.find('\n', start);
        out.push_back(text.substr(start, nl == std::string::npos ? std::string::npos : nl - start));
        if (nl == std::string::npos) break;
        start = nl + 1;
    }
    return out;
}
// String.split("\\s+") of a trimmed line.
std::vector<std::string> words(const std::string& line) {
    std::vector<std::string> out;
    std::string current;
    for (char c : line) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r') {
            if (!current.empty()) out.push_back(std::move(current));
            current.clear();
        } else {
            current += c;
        }
    }
    if (!current.empty() || out.empty()) out.push_back(std::move(current));
    return out;
}
std::string first_line(const std::string& text) {
    const auto nl = text.find('\n');
    return trim(nl == std::string::npos ? text : text.substr(0, nl));
}
std::string path_join(std::string root, const std::string& child) {
    if (!root.empty() && root.back() == '/') root.pop_back();
    return root + "/" + child;
}
}
VmmUnreachable::VmmUnreachable(const std::string& stderr_text)
    : ControlIoError("control socket not reachable: " + first_line(stderr_text)) {}
bool UsbControl::ready(const std::string& socket_path) {
    Fd socket_fd(socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0));
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (socket_fd.get() < 0 || socket_path.size() >= sizeof(address.sun_path)) return false;
    std::copy(socket_path.begin(), socket_path.end(), address.sun_path);
    return connect(socket_fd.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0;
}
int parse_ok_port(const std::string& stdout_text) {
    for (const auto& raw : lines(stdout_text)) {
        const auto line = trim(raw);
        if (line.empty()) continue;
        const auto parts = words(line);
        if (parts.size() < 2 || parts[0] != "ok") throw ControlRefused(parts[0]);
        const auto port = parse_int(parts[1]);
        if (!port) throw ControlRefused(line);
        return *port;
    }
    throw ControlRefused(trim(stdout_text));
}
std::vector<ListEntry> parse_list(const std::string& stdout_text) {
    for (const auto& raw : lines(stdout_text)) {
        const auto line = trim(raw);
        if (line.empty()) continue;
        const auto parts = words(line);
        if (parts[0] != "devices") throw ControlRefused(parts[0]);
        // port/vid/pid repeated; a trailing partial group is not a list.
        if ((parts.size() - 1) % 3 != 0) throw ControlRefused(line);
        std::vector<ListEntry> entries;
        for (size_t i = 1; i + 2 < parts.size(); i += 3) {
            const auto port = parse_int(parts[i]);
            if (!port) throw ControlRefused(line);
            entries.push_back({*port, parts[i + 1], parts[i + 2]});
        }
        return entries;
    }
    throw ControlRefused(trim(stdout_text));
}
bool is_unreachable(const std::string& stderr_text) { return stderr_text.find(connect_failed) != std::string::npos; }
std::optional<std::string> first_error_line(const std::string& text) {
    // [<time> ERROR <target>] <message>; the time is optional.
    static const std::regex error_line(R"(^\[(?:\S+\s+)?ERROR\s+([^\]\s]*)\]\s*(.*)$)");
    std::optional<std::string> any;
    for (const auto& raw : lines(text)) {
        const auto line = trim(raw);
        std::smatch match;
        if (!std::regex_match(line, match, error_line)) continue;
        const auto message = trim(match[2].str());
        if (message.empty()) continue;
        if (match[1].str().find("usb") != std::string::npos) return message;
        if (!any) any = message;
    }
    return any;
}
std::string attach_failure_message(const std::string& token, const std::string& cli_stderr, const std::string& vmm_log) {
    const auto cause = first_error_line(cli_stderr + "\n" + vmm_log);
    if (!cause) return "crosvm usb attach failed: " + token;
    return "crosvm usb attach failed: " + token + " (" + *cause + ")";
}
void require_output(const std::string& stdout_text, const std::string& stderr_text) {
    if (!trim(stdout_text).empty()) return;
    if (is_unreachable(stderr_text)) throw VmmUnreachable(stderr_text);
    throw ControlIoError("crosvm usb printed nothing; stderr: " + stderr_text);
}

CrosvmCli::CrosvmCli(std::string data_dir, std::string android_release, std::chrono::milliseconds timeout)
    : data_dir_(std::move(data_dir)), release_(std::move(android_release)), timeout_(timeout) {}
std::vector<std::string> CrosvmCli::argv(const std::vector<std::string>& args) const {
    std::vector<std::string> out{path_join(path_join(path_join(data_dir_, "usr"), "bin"), "crosvm")};
    out.insert(out.end(), args.begin(), args.end());
    return out;
}
std::vector<std::pair<std::string, std::string>> CrosvmCli::environment() const {
    return {{"LD_PRELOAD", path_join(path_join(data_dir_, "lib"), "libsimpledump.so") + ":" + path_join(path_join(data_dir_, "lib"), "libcompat_a" + release_ + ".so")},
            {"LD_LIBRARY_PATH", path_join(path_join(data_dir_, "usr"), "lib")}};
}
std::pair<std::string, std::string> CrosvmCli::run(const std::vector<std::string>& args) const {
    ChildOptions options;
    options.argv = argv(args);
    // NativeProcess.Builder: the inherited environment, overrides in place.
    std::vector<std::pair<std::string, std::string>> rows;
    for (char** entry = environ; entry && *entry; ++entry) {
        const std::string text = *entry;
        const auto eq = text.find('=');
        if (eq != std::string::npos) rows.emplace_back(text.substr(0, eq), text.substr(eq + 1));
    }
    for (const auto& [key, value] : environment()) {
        auto at = std::find_if(rows.begin(), rows.end(), [&](const auto& row) { return row.first == key; });
        if (at != rows.end()) at->second = value; else rows.emplace_back(key, value);
    }
    options.environment.emplace();
    for (const auto& [key, value] : rows) options.environment->push_back(key + "=" + value);
    ChildOutput output;
    try {
        Child child(options);
        child.close_stdin();
        output = child.communicate({}, timeout_);
    } catch (const std::exception& error) {
        throw ControlIoError(error.what());
    }
    if (output.timed_out)
        throw ControlIoError("crosvm usb did not answer in " + std::to_string(std::chrono::duration_cast<std::chrono::seconds>(timeout_).count()) + "s");
    return {utf8_lossy(output.output), trim(utf8_lossy(output.error))};
}
int CrosvmCli::attach(const std::string& socket_path, const std::string& node) {
    const auto [out, err] = run({"usb", "attach", "0:0:0:0", node, socket_path});
    require_output(out, err);
    try { return parse_ok_port(out); } catch (const ControlRefused& e) { throw ControlRefused(e.token, err); }
}
int CrosvmCli::detach(const std::string& socket_path, int port) {
    const auto [out, err] = run({"usb", "detach", std::to_string(port), socket_path});
    require_output(out, err);
    try { return parse_ok_port(out); } catch (const ControlRefused& e) { throw ControlRefused(e.token, err); }
}
std::vector<ListEntry> CrosvmCli::list(const std::string& socket_path) {
    const auto [out, err] = run({"usb", "list", socket_path});
    require_output(out, err);
    try { return parse_list(out); } catch (const ControlRefused& e) { throw ControlRefused(e.token, err); }
}
}
