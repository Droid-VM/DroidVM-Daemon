// SPDX-License-Identifier: GPL-3.0-or-later
#include "android_wifi.h"
#include <algorithm>
#include <chrono>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef __ANDROID__
#include "runtime/child.h"
#include <arpa/inet.h>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <thread>
#include <unistd.h>
#endif

namespace droidvm {
namespace {
using namespace std::chrono_literals;
std::string trim(std::string s) {
    const auto first = s.find_first_not_of(" \r\n\t");
    if (first == std::string::npos) return {};
    return s.substr(first, s.find_last_not_of(" \r\n\t") - first + 1);
}
std::vector<std::string> words(const std::string& s) {
    std::istringstream in(s); std::vector<std::string> out;
    for (std::string word; in >> word;) out.push_back(word);
    std::sort(out.begin(), out.end());
    return out;
}
[[maybe_unused]] void need(bool ok, const char* why) { if (!ok) throw std::runtime_error(std::string("Wi-Fi takeover: ") + why); }
}

bool android_wifi_config_matches(const std::string& config, const std::string& ssid) {
    std::istringstream in(config);
    unsigned networks = 0, matches = 0, ssids = 0;
    bool inside = false;
    for (std::string line; std::getline(in, line);) {
        line = trim(line);
        if (line.empty() || line.front() == '#') continue;
        if (line == "network={") { if (inside) return false; inside = true; ++networks; }
        else if (line == "}") { if (!inside) return false; inside = false; }
        else if (line.starts_with("ssid=")) {
            if (!inside) return false;
            ++ssids;
            auto value = line.substr(5);
            if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
                value = value.substr(1, value.size() - 2);
                // Ambiguous escapes require another adapter, not guessing.
                if (value.find_first_of("\\\"") != std::string::npos) return false;
            } else {
                if (value.size() % 2 || value.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) return false;
                std::string decoded;
                for (size_t i = 0; i < value.size(); i += 2) decoded += static_cast<char>(std::stoul(value.substr(i, 2), nullptr, 16));
                value = decoded;
            }
            if (value == ssid) ++matches;
        }
    }
    return !inside && networks == 1 && ssids == 1 && matches == 1 && !ssid.empty();
}

bool android_wifi_lease_matches(const Json::Value& plan, const std::string& event, unsigned& lease) {
    std::istringstream in(event);
    std::vector<std::string> fields;
    for (std::string line; std::getline(in, line);) fields.push_back(trim(line));
    if (fields.size() != 6 || (fields[0] != "bound" && fields[0] != "renew") ||
        fields[1] != plan["ip"].asString() || fields[2] != plan["mask"].asString() ||
        words(fields[3]) != words(plan["gateway"].asString()) ||
        words(fields[4]) != words(plan["dns"].asString()) || fields[5].empty() ||
        fields[5].find_first_not_of("0123456789") != std::string::npos) return false;
    try {
        const auto seconds = std::stoull(fields[5]);
        if (seconds < 60 || seconds > 0x7fffffff) return false;
        lease = static_cast<unsigned>(seconds);
        return true;
    } catch (...) { return false; }
}

#ifdef __ANDROID__
namespace {
constexpr const char* config_path = "/data/vendor/wifi/wpa/wpa_supplicant.conf";
constexpr const char* supplicant_path = "/vendor/bin/hw/wpa_supplicant";
constexpr const char* cli_path = "/vendor/bin/wpa_cli";
using Clock = std::chrono::steady_clock;
std::string run(std::vector<std::string> args, std::chrono::milliseconds timeout = 3s) {
    ChildOptions options; options.argv = std::move(args);
    Child child(options);
    const auto result = child.communicate({}, timeout, 1u << 20);
    // Do not propagate stdout/stderr: vendor tools can print credentials.
    need(result.exit_code == 0 && !result.timed_out && !result.truncated, "helper command failed or timed out");
    return result.output;
}
std::string file(const std::string& path) {
    Fd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    need(fd.get() >= 0, "cannot read required file");
    std::string text; char buffer[4096];
    for (;;) {
        const auto n = read(fd.get(), buffer, sizeof(buffer));
        if (n < 0 && errno == EINTR) continue;
        need(n >= 0 && text.size() + static_cast<size_t>(n) <= (1u << 20), "invalid or oversized file");
        if (!n) return text;
        text.append(buffer, static_cast<size_t>(n));
    }
}
void create(const std::string& path, const std::string& data, mode_t mode, bool wifi = false) {
    Fd fd(open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode));
    need(fd.get() >= 0, "cannot create private file");
    if (wifi) need(fchown(fd.get(), 1010, 1010) == 0, "cannot set Wi-Fi file owner");
    for (size_t pos = 0; pos < data.size();) {
        const auto n = write(fd.get(), data.data() + pos, data.size() - pos);
        if (n < 0 && errno == EINTR) continue;
        need(n > 0, "cannot write private file"); pos += static_cast<size_t>(n);
    }
}
std::string field(const std::string& text, const std::string& prefix) {
    std::istringstream in(text);
    for (std::string line; std::getline(in, line);) {
        line = trim(line);
        if (line.starts_with(prefix)) return trim(line.substr(prefix.size()));
    }
    return {};
}
bool ipv4(const std::string& text) { in_addr addr{}; return inet_pton(AF_INET, text.c_str(), &addr) == 1; }
std::string property(const char* name) { char value[PROP_VALUE_MAX]{}; __system_property_get(name, value); return value; }

class Wifi final : public AndroidWifiSession {
public:
    explicit Wifi(Json::Value plan) : plan_(std::move(plan)) {}
    ~Wifi() override { try { stop(); } catch (...) {} }
    void prepare() {
        auto config = file(config_path);
        need(android_wifi_config_matches(config, plan_["ssid"].asString()), "persisted network changed before handoff");
        char path[] = "/data/local/tmp/droidvm-wifi-XXXXXX";
        need(mkdtemp(path) != nullptr, "cannot create session directory");
        directory_ = path;
        // Parent remains root-owned, while the vendor process drops to AID_WIFI.
        need(chmod(path, 0711) == 0, "cannot make session traversable");
        const auto control = directory_ + "/control";
        need(mkdir(control.c_str(), 0770) == 0 && chown(control.c_str(), 1010, 1010) == 0 && chmod(control.c_str(), 0770) == 0,
             "cannot create Wi-Fi control directory");
        // Never give a standalone process write access to Android's configuration.
        std::istringstream lines(config); std::string copy;
        for (std::string line; std::getline(lines, line);)
            if (!trim(line).starts_with("update_config=")) copy += line + "\n";
        copy += "\nupdate_config=0\n";
        create(directory_ + "/supplicant.conf", copy, 0400, true);
        create(directory_ + "/dhcp.sh", "#!/system/bin/sh\n"
            "cd \"${0%/*}\" || exit 1\n"
            "umask 077\n"
            "printf '%s\\n' \"$1\" \"$ip\" \"$subnet\" \"$router\" \"$dns\" \"$lease\" > lease.tmp || exit 1\n"
            "/system/bin/mv -f lease.tmp lease\n", 0700);
    }
    void start() override {
        need(!supplicant_, "session already started");
        const auto until = Clock::now() + 8s;
        while (property("init.svc.wpa_supplicant") != "stopped") {
            need(Clock::now() < until, "framework supplicant did not exit");
            std::this_thread::sleep_for(100ms);
        }
        need(property("init.svc.zygote") == "stopped", "zygote must exit before Wi-Fi handoff");
        supplicant_ = launch({supplicant_path, "-i", iface(), "-D", "nl80211", "-c", directory_ + "/supplicant.conf", "-O", directory_ + "/control"});
        const auto connected_by = Clock::now() + 25s;
        bool selected = false;
        for (;;) {
            need(!supplicant_->poll_exit(), "standalone supplicant exited");
            need(Clock::now() < connected_by, "AP association timed out");
            if (!selected) {
                try {
                    if (trim(cli("ping")) == "PONG") {
                        need(trim(cli("ap_scan", "1")) == "OK", "cannot enable scanning");
                        // The preflight accepted exactly one matching network block.
                        need(trim(cli("select_network", "0")) == "OK", "cannot select saved network");
                        need(trim(cli("reconnect")) == "OK", "cannot connect saved network");
                        selected = true;
                    }
                } catch (const std::exception&) {}
            }
            if (selected && field(cli("status"), "wpa_state=") == "COMPLETED") break;
            std::this_thread::sleep_for(250ms);
        }
        if (plan_["dynamic"].asBool()) {
            dhcp_ = launch({plan_["busybox"].asString(), "udhcpc", "-f", "-i", iface(), "-r", plan_["ip"].asString(), "-s", directory_ + "/dhcp.sh"});
            const auto deadline = Clock::now() + 20s;
            while (!leased_) {
                check_lease();
                need(Clock::now() < deadline, "DHCP did not confirm the retained address");
                if (!leased_) std::this_thread::sleep_for(200ms);
            }
        }
        verify_link();
        run({"/system/bin/ping", "-c", "1", "-W", "2", plan_["gateway"].asString()}, 3s);
    }
    void check() override {
        need(supplicant_ && !supplicant_->poll_exit(), "standalone supplicant exited");
        check_lease();
        // Allow the supplicant to reconnect after a transient AP disconnect.
        try { verify_link(); disconnected_ = {}; }
        catch (const std::exception&) {
            if (disconnected_ == Clock::time_point{}) disconnected_ = Clock::now();
            need(Clock::now() - disconnected_ < 30s, "Wi-Fi association lost for 30 seconds");
        }
    }
    void stop() override {
        if (dhcp_) { dhcp_->stop(); dhcp_.reset(); }
        if (supplicant_) { supplicant_->stop(); supplicant_.reset(); }
        if (directory_.empty()) return;
        for (const auto& path : {"/control/" + iface(), std::string("/supplicant.conf"), std::string("/dhcp.sh"), std::string("/lease"), std::string("/lease.tmp")})
            unlink((directory_ + path).c_str());
        rmdir((directory_ + "/control").c_str());
        rmdir(directory_.c_str()); directory_.clear();
    }
private:
    Json::Value plan_;
    std::string directory_;
    std::unique_ptr<Child> supplicant_, dhcp_;
    bool leased_ = false;
    timespec lease_stamp_{};
    Clock::time_point lease_until_{}, disconnected_{};
    std::string iface() const { return plan_["interface"].asString(); }
    std::unique_ptr<Child> launch(std::vector<std::string> argv) {
        Fd null(open("/dev/null", O_RDWR | O_CLOEXEC)); need(null.get() >= 0, "cannot open null stdio");
        ChildOptions options; options.argv = std::move(argv); options.stdio = {null.get(), null.get(), null.get()};
        return std::make_unique<Child>(options);
    }
    std::string cli(const std::string& command, const std::string& value = {}) {
        std::vector<std::string> args{cli_path, "-p", directory_ + "/control", "-i", iface(), command};
        if (!value.empty()) args.push_back(value);
        return run(std::move(args));
    }
    void verify_link() {
        const auto link = run({"/system/bin/iw", "dev", iface(), "link"});
        need(link.starts_with("Connected to ") && field(link, "SSID:") == plan_["ssid"].asString(), "not associated to the original network");
        const auto addresses = run({"/system/bin/ip", "-4", "-o", "addr", "show", "dev", iface()});
        need(addresses.find("inet " + plan_["cidr"].asString() + " ") != std::string::npos, "retained IPv4 address disappeared");
    }
    void check_lease() {
        if (!dhcp_) return;
        need(!dhcp_->poll_exit(), "DHCP client exited");
        struct stat info{};
        if (stat((directory_ + "/lease").c_str(), &info) == 0 &&
            (info.st_mtim.tv_sec != lease_stamp_.tv_sec || info.st_mtim.tv_nsec != lease_stamp_.tv_nsec)) {
            const auto event = file(directory_ + "/lease");
            if (!(event.starts_with("deconfig\n") && !leased_)) {
                unsigned lease = 0;
                need(android_wifi_lease_matches(plan_, event, lease), "DHCP address, gateway or DNS changed, or lease lost");
                // Renew only the existing address lifetime; keep Android policy
                // routing, netd DNS, VM bridges and firewall rules intact.
                run({"/system/bin/ip", "addr", "change", plan_["cidr"].asString(), "dev", iface(),
                     "valid_lft", std::to_string(lease), "preferred_lft", std::to_string(lease)});
                leased_ = true; lease_until_ = Clock::now() + std::chrono::seconds(lease - 15);
            }
            lease_stamp_ = info.st_mtim;
        }
        need(!leased_ || Clock::now() < lease_until_, "DHCP lease is expiring without renewal");
    }
};
}

Json::Value android_wifi_plan() {
    // Inventory sysfs first, so a phone without Wi-Fi does not need iw installed.
    std::vector<std::string> interfaces;
    DIR* directory = opendir("/sys/class/net"); need(directory != nullptr, "cannot enumerate interfaces");
    while (const auto* item = readdir(directory)) {
        const std::string name = item->d_name;
        struct stat info{};
        if (stat(("/sys/class/net/" + name + "/phy80211").c_str(), &info) == 0) interfaces.push_back(name);
    }
    closedir(directory);
    Json::Value plan;
    for (const auto& iface : interfaces) {
        const auto link = run({"/system/bin/iw", "dev", iface, "link"});
        if (!link.starts_with("Connected to ")) continue;
        need(plan.isNull(), "multiple associated Wi-Fi interfaces are unsupported");
        plan["interface"] = iface; plan["ssid"] = field(link, "SSID:");
    }
    if (plan.isNull()) return plan;
    need(access(supplicant_path, X_OK) == 0 && access(cli_path, X_OK) == 0, "vendor supplicant/control tool unavailable");
    need(property("init.svc.wpa_supplicant") == "running", "unrecognized framework supplicant service");
    need(android_wifi_config_matches(file(config_path), plan["ssid"].asString()), "saved supplicant config must contain only the currently associated network");
    const auto iface = plan["interface"].asString();
    const auto addresses = run({"/system/bin/ip", "-4", "-o", "addr", "show", "dev", iface});
    const auto inet = addresses.find(" inet ");
    need(inet != std::string::npos && addresses.find(" inet ", inet + 1) == std::string::npos, "expected one retained IPv4 address");
    const auto end = addresses.find(' ', inet + 6);
    const auto cidr = addresses.substr(inet + 6, end - inet - 6);
    const auto slash = cidr.find('/');
    need(slash != std::string::npos && ipv4(cidr.substr(0, slash)), "invalid IPv4 address");
    const int prefix = std::stoi(cidr.substr(slash + 1));
    need(prefix > 0 && prefix <= 32, "invalid IPv4 prefix");
    in_addr mask{htonl(0xffffffffu << (32 - prefix))}; char mask_text[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &mask, mask_text, sizeof(mask_text));
    plan["ip"] = cidr.substr(0, slash); plan["cidr"] = cidr; plan["mask"] = mask_text;
    plan["dynamic"] = addresses.find(" dynamic ") != std::string::npos;
    const auto routes = run({"/system/bin/ip", "-4", "route", "show", "table", "all", "dev", iface});
    auto gateway = field(routes, "default via "); gateway = gateway.substr(0, gateway.find(' '));
    need(ipv4(gateway), "IPv4 gateway unavailable"); plan["gateway"] = gateway;
    const auto connectivity = run({"/system/bin/dumpsys", "-t", "2", "connectivity"});
    std::istringstream lines(connectivity); std::string dns;
    for (std::string line; std::getline(lines, line);) {
        if (line.find("NetworkAgentInfo{") == std::string::npos || line.find("InterfaceName: " + iface + " ") == std::string::npos) continue;
        const auto begin = line.find("DnsAddresses: [ "); need(begin != std::string::npos, "DNS baseline unavailable");
        const auto close = line.find(']', begin); need(close != std::string::npos, "invalid DNS baseline");
        auto values = line.substr(begin + 16, close - begin - 16);
        for (char& c : values) if (c == ',' || c == '/') c = ' ';
        for (const auto& value : words(values)) if (ipv4(value)) dns += (dns.empty() ? "" : " ") + value;
    }
    need(!dns.empty(), "retained IPv4 DNS unavailable"); plan["dns"] = dns;
    if (plan["dynamic"].asBool()) {
        for (const char* path : {"/data/adb/ksu/bin/busybox", "/data/adb/magisk/busybox", "/data/adb/ap/bin/busybox"}) {
            if (access(path, X_OK) != 0) continue;
            const auto applets = run({path, "--list"});
            if (("\n" + applets).find("\nudhcpc\n") != std::string::npos) { plan["busybox"] = path; break; }
        }
        need(plan["busybox"].isString(), "DHCP renewal client unavailable");
    }
    run({"/system/bin/ping", "-c", "1", "-W", "2", gateway}, 3s);
    return plan;
}
std::unique_ptr<AndroidWifiSession> android_wifi_prepare(const Json::Value& plan) {
    if (plan.isNull()) return {};
    auto wifi = std::make_unique<Wifi>(plan);
    wifi->prepare();
    return wifi;
}
#else
Json::Value android_wifi_plan() { return {}; }
std::unique_ptr<AndroidWifiSession> android_wifi_prepare(const Json::Value&) { return {}; }
#endif
}
