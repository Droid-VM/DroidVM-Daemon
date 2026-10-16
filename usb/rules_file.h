// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "usb/rules.h"
#include "store/json_file.h"
#include <functional>
#include <memory>
#include <string>

// Port of daemon/usb/UsbRulesFile: <files>/usb_rules.json, written only by
// the daemon (on usb_rules_set) and read once at start-up. Persistence is
// store/json_file's atomic replace, owned by the directory's owner, mode 0600.
namespace droidvm::usb {
class RulesFile {
public:
    static constexpr const char* name = "usb_rules.json";
    using Log = std::function<void(const char* level, const std::string& message)>;
    // [directory] is the app files directory; empty disables persistence.
    RulesFile(std::string directory, Log log);
    std::string path() const { return directory_ + "/" + name; }
    // The saved rules, or none when absent or unreadable (the file is kept).
    Rules load();
    // Throws on failure; the caller only logs it.
    void save(const Rules& rules);
private:
    std::string directory_;
    Log log_;
    std::unique_ptr<config::JsonFile> file_;
    config::JsonFile& file();
};
}
