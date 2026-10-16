// SPDX-License-Identifier: GPL-3.0-or-later
#include "config_transaction.h"
#include <array>
#include <set>
#include <fcntl.h>
#include <sys/stat.h>
#include <cerrno>
#include <system_error>

namespace droidvm::config {
namespace {
constexpr const char* journal = "config-transaction.json";
size_t limit(const std::string& name) {
    if (name == "vms.json") return 16u << 20;
    if (name == "networks.json" || name == "disks.json") return 8u << 20;
    throw std::invalid_argument("Unsupported configuration transaction target");
}
std::string staged(const std::string& name) { return "transaction-" + name; }
JsonSyntax syntax(const std::string& name) { return name == "vms.json" ? JsonSyntax::strict : JsonSyntax::compatible; }
void require(bool ok, const char* message) {
    if (!ok) throw std::system_error(errno, std::generic_category(), message);
}
}
ConfigTransaction::ConfigTransaction(int directory, uid_t owner, Observer observer, std::vector<std::string> targets)
    : directory_(fcntl(directory, F_DUPFD_CLOEXEC, 3)), owner_(owner), observer_(std::move(observer)), targets_(std::move(targets)) {
    require(directory_.get() >= 0, "duplicate transaction directory");
    if (targets_.empty() || targets_.size() > 3) throw std::invalid_argument("Invalid owned transaction targets");
    std::set<std::string> seen;
    for (const auto& name : targets_) {
        limit(name);
        if (!seen.insert(name).second) throw std::invalid_argument("Duplicate owned transaction target");
    }
    recover();
}
size_t ConfigTransaction::target_limit(const std::string& name) const {
    for (const auto& target : targets_) if (target == name) return limit(name);
    throw std::invalid_argument("Configuration transaction target is not owned");
}
void ConfigTransaction::sync() { require(fsync(directory_.get()) == 0, "sync configuration transaction"); }
void ConfigTransaction::remove(const std::string& name) {
    struct stat info{};
    if (fstatat(directory_.get(), name.c_str(), &info, AT_SYMLINK_NOFOLLOW) < 0) {
        if (errno == ENOENT) return;
        require(false, "stat transaction artifact");
    }
    if (!S_ISREG(info.st_mode) || info.st_nlink != 1 || (info.st_uid != owner_ && info.st_uid != geteuid()))
        throw std::runtime_error("Unsafe configuration transaction artifact");
    require(unlinkat(directory_.get(), name.c_str(), 0) == 0, "remove transaction artifact");
}
void ConfigTransaction::cleanup() {
    // Only after the decision's absence is durable may staged documents vanish.
    for (const auto& name : targets_) {
        // Reuse JsonFile's narrowly scoped abandoned temporary reclamation.
        JsonFile file(directory_.get(), staged(name), owner_, {}, limit(name), JsonSyntax::strict);
        remove(staged(name)); remove(staged(name) + ".bak"); remove(staged(name) + ".corrupt");
    }
    sync();
}
void ConfigTransaction::recover() {
    std::lock_guard lock(mutex_);
    try { recover_unlocked(); }
    catch (const std::exception& error) {
        pending_ = true;
        throw TransactionError(error.what(), true);
    }
}
void ConfigTransaction::recover_unlocked() {
    JsonFile decision(directory_.get(), journal, owner_, {}, 16384, JsonSyntax::strict);
    auto loaded = decision.load();
    if (!loaded) {
        sync(); cleanup(); pending_ = false; return;
    }
    pending_ = true;
    const auto& manifest = loaded->value;
    if (loaded->recovered || manifest.size() != 2 || manifest["version"] != 1
        || !manifest["targets"].isArray() || manifest["targets"].empty() || manifest["targets"].size() > targets_.size())
        throw std::runtime_error("Invalid configuration transaction decision");
    std::set<std::string> names;
    std::vector<Update> updates;
    // Read and validate ALL participants before touching any target. Never use
    // staging backups: they could belong to an earlier, unrelated transaction.
    for (const auto& entry : manifest["targets"]) {
        if (!entry.isString()) throw std::runtime_error("Invalid transaction target");
        auto name = entry.asString(); const auto capacity = target_limit(name);
        if (!names.insert(name).second) throw std::runtime_error("Duplicate transaction target");
        JsonFile file(directory_.get(), staged(name), owner_, {}, capacity, JsonSyntax::strict);
        auto value = file.load();
        if (!value || value->recovered) throw std::runtime_error("Transaction document unavailable");
        updates.push_back({std::move(name), std::move(value->value)});
    }
    // A previous attempt may have failed immediately after decision rename.
    // Make that decision durable before the first target can change.
    sync();
    point("decision_synced");
    for (size_t i = 0; i < updates.size(); ++i) {
        const auto& update = updates[i];
        JsonFile file(directory_.get(), update.name, owner_,
            [&, i](const char* stage) { point(stage, i); }, limit(update.name), syntax(update.name));
        file.save(update.document);
        point("participant_synced", i);
    }
    point("before_forget");
    remove(journal);
    sync();
    point("decision_removed");
    cleanup();
    pending_ = false;
}
void ConfigTransaction::commit(const std::vector<Update>& updates) {
    std::lock_guard lock(mutex_);
    if (pending_) throw TransactionError("Recover pending configuration transaction before writing", true);
    if (updates.empty() || updates.size() > targets_.size()) throw std::invalid_argument("Invalid transaction participant count");
    Json::Value manifest;
    manifest["version"] = 1; manifest["targets"] = Json::Value(Json::arrayValue);
    std::set<std::string> names;
    for (const auto& update : updates) {
        const auto capacity = target_limit(update.name);
        if (!names.insert(update.name).second) throw std::invalid_argument("Duplicate transaction target");
        // All malformed/oversized documents fail before staging or target IO.
        parse_json(encode_json(update.document, capacity));
        manifest["targets"].append(update.name);
    }
    try {
        for (const auto& update : updates) {
            JsonFile target(directory_.get(), update.name, owner_, {}, limit(update.name), syntax(update.name));
            target.load(); // Refuse unreadable/corrupt/aliased targets before deciding.
        }
        for (size_t i = 0; i < updates.size(); ++i) {
            const auto& update = updates[i];
            JsonFile file(directory_.get(), staged(update.name), owner_, {}, limit(update.name), JsonSyntax::strict);
            file.save(update.document);
            point("staged", i);
        }
        point("before_decision");
        JsonFile decision(directory_.get(), journal, owner_, [&](const char* stage) {
            const auto name = "decision_" + std::string(stage);
            point(name.c_str());
        }, 16384, JsonSyntax::strict);
        try { decision.save(manifest); }
        catch (const CommitError& error) { pending_ = error.installed; throw; }
        pending_ = true;
        recover_unlocked();
    } catch (const std::exception& error) {
        // Without a decision the old targets remain authoritative. Staging is
        // reclaimed before another attempt; after a decision only redo is legal.
        const bool decided = pending_;
        if (!decided) {
            try { cleanup(); }
            catch (...) { pending_ = true; }
        }
        throw TransactionError(error.what(), decided);
    }
}
}
