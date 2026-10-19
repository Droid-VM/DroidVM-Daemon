// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "acm_control.h"
#include <json/json.h>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>

namespace droidvm::vm {
// UsbAcmPool: a fixed pool of acm.dvmpool<N> functions grafted onto the
// framework's gadget, shared by every USB_ACM serial port. Only a pool
// rebuild rebinds the UDC; attach and release never do.
inline constexpr const char* acm_enable_key = "usb_acm_enable";
inline constexpr const char* acm_ports_key = "usb_acm_ports";
inline constexpr bool acm_default_enable = false;
inline constexpr int acm_default_ports = 4, acm_max_ports = 6;
bool acm_enabled(const Json::Value& app_config); // enabledOf
int acm_ports(const Json::Value& app_config);    // portsOf, clamped to [1, max]

// SlotUnavailableException: the slot is off, busy or outside the pool; the VM
// start is refused. Any other runtime_error from acquire degrades to a sink.
class AcmSlotUnavailable : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Every configfs and UDC mutation the pool makes; tests substitute a kernel
// model. Each returns 0 or an errno.
class GadgetFs {
public:
    virtual ~GadgetFs() = default;
    virtual int write(const std::string& path, std::string_view text); // FileUtils.writeFile
    virtual int make_directory(const std::string& path);                // File.mkdir
    virtual int symlink(const std::string& target, const std::string& link);
    virtual int remove(const std::string& path);                        // File.delete
    virtual bool tty_node(const std::string& path) const;
};

struct AcmTiming {
    std::chrono::milliseconds node_wait{3000}, node_poll{50};
    int udc_retries = 3;
    std::chrono::milliseconds settle_probe{300}, settle_poll{500}, settle_timeout{15000};
};

struct AcmOptions {
    std::string gadget = "/config/usb_gadget/g1";
    std::string udc_class = "/sys/class/udc";
    std::string dev = "/dev"; // parent of ttyGS<n>
    std::shared_ptr<GadgetFs> fs; // null = real writes
    AcmTiming timing;
    std::function<std::string(const char*)> property; // null = system property
    std::function<std::chrono::steady_clock::time_point()> now;
    std::function<void(std::chrono::milliseconds)> sleep;
    std::function<void(const char* level, const std::string& text)> log;
};

class AcmPool : public AcmControl {
public:
    explicit AcmPool(AcmOptions options = {});
    // applyConfig: builds or tears down the pool; failures only log.
    void apply_config(const Json::Value& app_config);
    // Attaches [slot] to [owner] and returns its tty path. Throws
    // AcmSlotUnavailable (refuse the boot) or runtime_error (degrade).
    std::string acquire(int slot, const std::string& owner, const Json::Value& app_config);
    void release(const std::string& owner); // never rebinds
    std::map<std::string, std::string> owners() const; // instance -> owner
    void transaction(const std::function<void(AcmTransaction&)>&) override;
private:
    class Transaction;
    AcmOptions options_;
    std::string functions_, config_, udc_;
    mutable std::mutex mutex_;
    std::map<std::string, std::string> owners_;
    bool managed_ = false;
    std::optional<AcmDesired> desired_;
    Json::Value live_locked(const AcmDesired&) const;
    void admit_locked(const AcmDesired&) const;
    void reconcile(int pool_size);
    void with_udc_unbound(const std::function<void()>& op);
    bool usb_settled();
    void await_usb_settled();
    std::string dev_path_of(const std::string& instance);
    void wait_for_node(const std::string& path);
    void log(const char* level, const std::string& text) const { if (options_.log) options_.log(level, text); }
};
}
