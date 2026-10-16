// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "common/identity.h"
#include "store/json_file.h"
#include "store/config_transaction.h"
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>

using namespace droidvm;
using namespace droidvm::test;
using namespace droidvm::config;
namespace {
struct Temporary {
    std::string path = "/data/local/tmp/droidvm-config-file-" + random_id(false);
    Fd directory;
    Temporary() {
        check(mkdir(path.c_str(), 0700) == 0, "create test directory");
        directory = Fd(open(path.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC));
        check(directory.get() >= 0, "open test directory");
    }
    ~Temporary() {
        DIR* scan = opendir(path.c_str());
        if (scan) {
            while (auto* entry = readdir(scan)) if (std::string_view(entry->d_name) != "." && std::string_view(entry->d_name) != "..")
                unlinkat(directory.get(), entry->d_name, 0);
            closedir(scan);
        }
        rmdir(path.c_str());
    }
    void raw(const char* name, std::string_view bytes) {
        Fd file(openat(directory.get(), name, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600));
        check(file.get() >= 0 && write(file.get(), bytes.data(), bytes.size()) == static_cast<ssize_t>(bytes.size()), "write fixture");
    }
};
Json::Value value(int generation) {
    Json::Value result;
    result["generation"] = generation;
    result["text"] = "网络🌏";
    result["unknown"]["integer"] = Json::Int64(9007199254740993LL);
    result["unknown"]["max"] = Json::Int64(INT64_MAX);
    result["unknown"]["min"] = Json::Int64(INT64_MIN);
    result["unknown"]["null"] = Json::Value();
    result["networks"] = Json::Value(Json::arrayValue);
    return result;
}
void roundtrip_backup_recovery() {
    Temporary temp;
    JsonFile file(temp.directory.get(), "networks.json", getuid());
    check(!file.load(), "missing is distinct from empty configuration");
    file.save(value(1));
    check(file.load()->value == value(1) && !file.load()->recovered, "exact JSON roundtrip");
    file.save(value(2));
    auto integral = value(2);
    integral["floating_integer"] = 256.0;
    file.save(integral);
    check(file.load()->value["floating_integer"].type() == Json::intValue, "JSONObject-compatible integral double token");
    file.save(value(1));
    file.save(value(2));
    struct stat info{};
    check(fstatat(temp.directory.get(), "networks.json", &info, 0) == 0 && (info.st_mode & 0777) == 0600 && info.st_uid == getuid(), "private primary");
    temp.raw("networks.json", "{broken");
    check(file.load()->recovered && file.load()->value == value(1), "last good backup recovered");
    file.save(value(3));
    check(file.load()->value == value(3) && !file.load()->recovered, "save after recovery");
    Fd corrupt(openat(temp.directory.get(), "networks.json.corrupt", O_RDONLY | O_CLOEXEC));
    char bytes[8]{};
    check(read(corrupt.get(), bytes, sizeof(bytes)) == 7 && std::string_view(bytes, 7) == "{broken", "damaged primary retained");
    temp.raw("networks.json", "[]");
    check(file.load()->value == value(1), "bad primary never replaced backup");
    temp.raw("networks.json.bak", "also broken");
    bool failed = false;
    try { file.save(value(4)); } catch (const std::exception&) { failed = true; }
    check(failed, "no silent empty reset when both copies corrupt");
}
void crash_boundaries() {
    for (const char* stage : {"value_synced", "backup_synced", "before_install", "installed"}) {
        Temporary temp;
        { JsonFile file(temp.directory.get(), "networks.json", getuid()); file.save(value(1)); }
        pid_t child = fork();
        check(child >= 0, "fork crash helper");
        if (!child) {
            JsonFile file(temp.directory.get(), "networks.json", getuid(), [stage](const char* current) {
                if (std::string_view(stage) == current) _exit(73);
            });
            file.save(value(2));
            _exit(74);
        }
        int status = 0;
        check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 73, "crashed at boundary");
        JsonFile recovered(temp.directory.get(), "networks.json", getuid());
        auto current = recovered.load();
        check(current && current->value == value(std::string_view(stage) == "installed" ? 2 : 1), "whole old or new document after crash");
        DIR* scan = opendir(temp.path.c_str());
        check(scan, "open leftover scan");
        bool orphan = false;
        while (auto* entry = readdir(scan)) if (std::string_view(entry->d_name).ends_with(".tmp")) orphan = true;
        closedir(scan);
        check(!orphan, "restart reclaims interrupted temporaries");
    }
}
void failed_writes_and_uncertain_commit() {
    Temporary temp;
    { JsonFile file(temp.directory.get(), "networks.json", getuid()); file.save(value(1)); }
    JsonFile file(temp.directory.get(), "networks.json", getuid());
    rlimit previous{};
    check(getrlimit(RLIMIT_FSIZE, &previous) == 0, "read file limit");
    auto limited = previous; limited.rlim_cur = 0;
    auto old = signal(SIGXFSZ, SIG_IGN);
    check(setrlimit(RLIMIT_FSIZE, &limited) == 0, "inject write failure");
    bool rejected = false;
    try { file.save(value(2)); } catch (const CommitError& error) { rejected = !error.installed; }
    check(setrlimit(RLIMIT_FSIZE, &previous) == 0, "restore file limit");
    signal(SIGXFSZ, old);
    check(rejected && file.load()->value == value(1), "write failure preserves primary");
    JsonFile uncertain(temp.directory.get(), "networks.json", getuid(), [](const char* stage) {
        if (std::string_view(stage) == "installed") throw std::runtime_error("injected directory sync failure");
    });
    bool installed = false;
    try { uncertain.save(value(2)); } catch (const CommitError& error) { installed = error.installed; }
    check(installed && file.load()->value == value(2), "post-rename error reports installed value");
}
void transaction_crash_boundaries() {
    for (const char* stage : {"staged", "before_decision", "decision_value_synced", "decision_before_install",
            "decision_installed", "decision_synced", "value_synced", "before_install", "installed",
            "participant_synced", "before_forget", "decision_removed"}) {
        Temporary temp;
        for (const char* name : {"vms.json", "networks.json", "disks.json"})
            JsonFile(temp.directory.get(), name, getuid()).save(value(1));
        pid_t child = fork();
        check(child >= 0, "fork transaction crash helper");
        if (!child) {
            ConfigTransaction transaction(temp.directory.get(), getuid(), [stage](const char* current, size_t) {
                if (std::string_view(stage) == current) { kill(getpid(), SIGKILL); _exit(75); }
            });
            transaction.commit({{"vms.json", value(2)}, {"networks.json", value(2)}, {"disks.json", value(2)}});
            _exit(74);
        }
        int status = 0;
        check(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
            "transaction helper killed at requested boundary");
        ConfigTransaction recovered(temp.directory.get(), getuid());
        recovered.recover(); // Idempotent and no stale decision resurrection.
        const std::string_view boundary(stage);
        int generation = boundary == "staged" || boundary == "before_decision" || boundary == "decision_value_synced"
            || boundary == "decision_before_install" ? 1 : 2;
        for (const char* name : {"vms.json", "networks.json", "disks.json"})
            check(JsonFile(temp.directory.get(), name, getuid()).load()->value == value(generation),
                "crash recovery exposes one complete generation");
        recovered.commit({{"vms.json", value(3)}, {"networks.json", value(3)}});
        ConfigTransaction reopened(temp.directory.get(), getuid());
        check(JsonFile(temp.directory.get(), "vms.json", getuid()).load()->value == value(3)
            && JsonFile(temp.directory.get(), "networks.json", getuid()).load()->value == value(3), "later commit survives reopening");
        DIR* scan = opendir(temp.path.c_str()); check(scan, "scan transaction leftovers");
        bool orphan = false;
        while (auto* entry = readdir(scan)) {
            const std::string_view name(entry->d_name);
            if (name.starts_with("transaction-") || name.starts_with("config-transaction") || name.ends_with(".tmp")) orphan = true;
        }
        closedir(scan); check(!orphan, "recovery reclaims transaction artifacts");
    }
}
void transaction_failures_and_recovery() {
    for (const char* stage : {"before_decision", "decision_installed", "installed", "participant_synced", "decision_removed"}) {
        Temporary temp;
        JsonFile vm(temp.directory.get(), "vms.json", getuid()); vm.save(value(1));
        JsonFile network(temp.directory.get(), "networks.json", getuid()); network.save(value(1));
        bool fail = true;
        ConfigTransaction transaction(temp.directory.get(), getuid(), [&](const char* current, size_t) {
            if (fail && std::string_view(stage) == current) throw std::runtime_error("injected transaction failure");
        });
        const bool decided = std::string_view(stage) != "before_decision";
        bool rejected = false;
        try { transaction.commit({{"vms.json", value(2)}, {"networks.json", value(2)}}); }
        catch (const TransactionError& error) { rejected = error.decided == decided; }
        check(rejected, "failure distinguishes pre-decision from redo required");
        if (decided) {
            rejected = false;
            try { transaction.commit({{"vms.json", value(3)}}); }
            catch (const TransactionError& error) { rejected = error.decided; }
            check(rejected, "pending recovery rejects unrelated commits");
        } else check(vm.load()->value == value(1) && network.load()->value == value(1), "pre-decision failure leaves all targets old");
        fail = false; transaction.recover();
        check(vm.load()->value == value(decided ? 2 : 1) && network.load()->value == value(decided ? 2 : 1),
            "recovery finishes every participant");
        transaction.commit({{"vms.json", value(3)}, {"networks.json", value(3)}});
        check(vm.load()->value == value(3) && network.load()->value == value(3), "writes resume after successful recovery");
    }
}
void transaction_validation_and_missing_stage() {
    Temporary temp;
    JsonFile vm(temp.directory.get(), "vms.json", getuid()); vm.save(value(1));
    JsonFile network(temp.directory.get(), "networks.json", getuid()); network.save(value(1));
    ConfigTransaction transaction(temp.directory.get(), getuid());
    auto invalid = value(2); invalid["oversize"] = std::string(8u << 20, 'x');
    for (auto updates : std::vector<std::vector<ConfigTransaction::Update>>{
            {{"vms.json", value(2)}, {"../outside.json", value(2)}},
            {{"vms.json", value(2)}, {"vms.json", value(2)}},
            {{"vms.json", value(2)}, {"networks.json", invalid}},
            {{"vms.json", value(2)}, {"networks.json", Json::Value(Json::arrayValue)}}}) {
        bool rejected = false;
        try { transaction.commit(updates); } catch (const std::exception&) { rejected = true; }
        check(rejected && vm.load()->value == value(1) && network.load()->value == value(1), "invalid batch never touches targets");
    }
    bool fail = true;
    ConfigTransaction interrupted(temp.directory.get(), getuid(), [&](const char* stage, size_t) {
        if (fail && std::string_view(stage) == "decision_synced") throw std::runtime_error("stop before targets");
    });
    try { interrupted.commit({{"vms.json", value(2)}, {"networks.json", value(2)}}); }
    catch (const TransactionError& error) { check(error.decided, "decision retained"); }
    check(unlinkat(temp.directory.get(), "transaction-networks.json", 0) == 0, "remove staged participant");
    fail = false;
    bool rejected = false;
    try { interrupted.recover(); } catch (const TransactionError& error) { rejected = error.decided; }
    check(rejected && vm.load()->value == value(1) && network.load()->value == value(1), "missing later stage blocks all recovery writes");
    JsonFile(temp.directory.get(), "transaction-networks.json", getuid()).save(value(2));
    interrupted.recover();
    check(vm.load()->value == value(2) && network.load()->value == value(2), "retained intent permits repair and redo");
}
void transaction_capacity_and_aliases() {
    Temporary temp;
    ConfigTransaction transaction(temp.directory.get(), getuid());
    std::vector<ConfigTransaction::Update> updates;
    for (const char* name : {"vms.json", "networks.json", "disks.json"}) {
        const size_t capacity = std::string_view(name) == "vms.json" ? 16u << 20 : 8u << 20;
        auto document = value(1); document["padding"] = "";
        document["padding"] = std::string(capacity - encode_json(document).size(), 'x');
        updates.push_back({name, std::move(document)});
    }
    transaction.commit(updates);
    for (const auto& update : updates) {
        const size_t capacity = update.name == "vms.json" ? 16u << 20 : 8u << 20;
        JsonFile file(temp.directory.get(), update.name, getuid(), {}, capacity);
        check(file.load()->value == update.document, "full 32 MiB transaction retains each document capacity");
    }
    updates.clear();
    JsonFile(temp.directory.get(), "outside.json", getuid()).save(value(9));
    for (const char* alias : {"networks.json", "transaction-networks.json", "config-transaction.json"}) {
        if (std::string_view(alias) == "networks.json") check(unlinkat(temp.directory.get(), alias, 0) == 0, "remove target for alias fixture");
        check(symlinkat("outside.json", temp.directory.get(), alias) == 0, "create transaction alias");
        bool rejected = false;
        try {
            ConfigTransaction unsafe(temp.directory.get(), getuid());
            unsafe.commit({{"vms.json", value(2)}, {"networks.json", value(2)}});
        } catch (const std::exception&) { rejected = true; }
        check(rejected, "transaction refuses target, stage and decision aliases");
        check(JsonFile(temp.directory.get(), "outside.json", getuid()).load()->value == value(9), "alias destination remains unchanged");
        check(unlinkat(temp.directory.get(), alias, 0) == 0, "remove alias fixture");
    }
}
void transaction_owned_targets() {
    Temporary temp;
    JsonFile vm(temp.directory.get(), "vms.json", getuid()); vm.save(value(1));
    JsonFile disk(temp.directory.get(), "disks.json", getuid()); disk.save(value(1));
    {
        ConfigTransaction restricted(temp.directory.get(), getuid(), {}, {"vms.json", "networks.json"});
        bool refused = false;
        try { restricted.commit({{"vms.json", value(2)}, {"disks.json", value(2)}}); }
        catch (const std::invalid_argument&) { refused = true; }
        check(refused, "unowned participant rejected before staging");
    }
    {
        ConfigTransaction interrupted(temp.directory.get(), getuid(), [](const char* stage, size_t) {
            if (std::string_view(stage) == "decision_synced") throw std::runtime_error("interrupt before installs");
        });
        try { interrupted.commit({{"vms.json", value(2)}, {"disks.json", value(2)}}); }
        catch (const TransactionError& error) { check(error.decided, "intent persisted"); }
    }
    bool refused = false;
    try { ConfigTransaction restricted(temp.directory.get(), getuid(), {}, {"vms.json", "networks.json"}); }
    catch (const TransactionError& error) { refused = error.decided; }
    check(refused && vm.load()->value == value(1) && disk.load()->value == value(1), "recovery validates ownership before changing any target");
    ConfigTransaction recovered(temp.directory.get(), getuid());
    check(vm.load()->value == value(2) && disk.load()->value == value(2), "owned recovery retains staged documents after refusal");
}
void bounds_and_path_refusal() {
    Temporary temp;
    JsonFile file(temp.directory.get(), "networks.json", getuid());
    file.save(value(1));
    auto huge = value(2); huge["blob"] = std::string(JsonFile::max_bytes, 'x');
    bool rejected = false;
    try { file.save(huge); } catch (const std::exception&) { rejected = true; }
    check(rejected && file.load()->value == value(1), "oversized write has no side effects");
    check(renameat(temp.directory.get(), "networks.json", temp.directory.get(), "target.json") == 0, "save target");
    for (int kind = 0; kind < 3; ++kind) {
        if (kind == 0) check(symlinkat("target.json", temp.directory.get(), "networks.json") == 0, "create symlink");
        if (kind == 1) check(linkat(temp.directory.get(), "target.json", temp.directory.get(), "networks.json", 0) == 0, "create hardlink");
        if (kind == 2) check(mkfifoat(temp.directory.get(), "networks.json", 0600) == 0, "create FIFO");
        rejected = false;
        try { file.save(value(2)); } catch (const std::exception&) { rejected = true; }
        check(rejected, "unsafe primary rejected before commit");
        unlinkat(temp.directory.get(), "networks.json", 0);
    }
    JsonFile target(temp.directory.get(), "target.json", getuid());
    check(target.load()->value == value(1), "alias target unchanged");
}
}
int main() {
    return run({{"json_unknown_int64_backup_recovery", roundtrip_backup_recovery},
                {"four_process_crash_boundaries", crash_boundaries},
                {"write_failure_and_post_rename_result", failed_writes_and_uncertain_commit},
                {"twelve_transaction_sigkill_boundaries", transaction_crash_boundaries},
                {"transaction_failure_redo_and_writer_gate", transaction_failures_and_recovery},
                {"transaction_validation_and_missing_stage", transaction_validation_and_missing_stage},
                {"transaction_full_capacity_and_aliases", transaction_capacity_and_aliases},
                {"transaction_owned_targets", transaction_owned_targets},
                {"bounded_io_symlink_hardlink_fifo", bounds_and_path_refusal}});
}
