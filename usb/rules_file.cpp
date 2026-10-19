// SPDX-License-Identifier: GPL-3.0-or-later
#include "usb/rules_file.h"
#include "common/fd.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <cerrno>
#include <cstdio>
#include <system_error>

namespace droidvm::usb {
RulesFile::RulesFile(std::string directory, Log log, config::JsonFile::Observer observer)
    : directory_(std::move(directory)), log_(std::move(log)), observer_(std::move(observer)) {}
config::JsonFile& RulesFile::file() {
    if (file_) return *file_;
    Fd directory(open(directory_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    struct stat owner{};
    if (directory.get() < 0 || fstat(directory.get(), &owner) != 0)
        throw std::system_error(errno, std::generic_category(), "no directory for " + path());
    // The daemon is root and the UI is not: the file belongs to the directory's owner.
    file_ = std::make_unique<config::JsonFile>(directory.get(), name, owner.st_uid, observer_);
    return *file_;
}
Rules RulesFile::load(bool* persisted) {
    if (persisted) *persisted = false;
    struct stat info{};
    if (directory_.empty() || stat(path().c_str(), &info) != 0 || !S_ISREG(info.st_mode)) return Rules::empty();
    try {
        auto loaded = file().load();
        // A recovery copy is not what the legacy daemon would have read.
        if (!loaded || loaded->recovered) throw std::runtime_error("unreadable");
        // No VM check: a rule for a VM deleted meanwhile is kept and never matches.
        auto rules = Rules::from_json(loaded->value, nullptr);
        if (persisted) *persisted = true;
        if (log_) log_("I", "Loaded USB rules from " + path());
        return rules;
    } catch (const std::exception& error) {
        if (log_) log_("W", "Cannot read " + path() + "; starting with no USB rules: " + error.what());
        return Rules::empty();
    }
}
bool RulesFile::save(const Rules& rules) {
    if (directory_.empty()) return false;
    auto& target = file();
    // JsonFile refuses to replace a damaged file it has no copy of; the
    // legacy writer replaced it. Keep it as evidence beside the new one.
    try { target.load(); } catch (const std::exception&) {
        const auto corrupt = path() + ".corrupt";
        if (std::rename(path().c_str(), corrupt.c_str()) != 0)
            throw std::system_error(errno, std::generic_category(), "cannot replace " + path());
    }
    target.save(rules.to_json());
    return true;
}
}
