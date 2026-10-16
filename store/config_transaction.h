// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "json_file.h"
#include <vector>

namespace droidvm::config {
class TransactionError : public std::runtime_error {
public:
    TransactionError(std::string message, bool decided) : std::runtime_error(std::move(message)), decided(decided) {}
    // A durable decision may exist. Do not roll back, publish partial state or
    // accept other writes: retry recovery before exposing any configuration.
    const bool decided;
};
// Redo journal for the existing vms/networks/disks JSON files. The caller must
// hold the daemon Instance lock, claim participating persistent ownership gates,
// AND exclude all participating service readers, writers and runtime admission
// until commit/recovery completes. Construct and
// recover before loading services. This alone is NOT a live service transaction.
// No format changes to the target files; JsonFile owns their backups and IO.
class ConfigTransaction {
public:
    struct Update { std::string name; Json::Value document; };
    using Observer = std::function<void(const char* stage, size_t participant)>;
    explicit ConfigTransaction(int directory, uid_t owner, Observer observer = {});
    void commit(const std::vector<Update>& updates);
    void recover();
private:
    Fd directory_;
    uid_t owner_;
    Observer observer_;
    std::mutex mutex_;
    bool pending_ = false;
    void recover_unlocked();
    void cleanup();
    void sync();
    void remove(const std::string& name);
    void point(const char* stage, size_t participant = 0) { if (observer_) observer_(stage, participant); }
};
}
