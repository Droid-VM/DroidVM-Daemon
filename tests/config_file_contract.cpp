// SPDX-License-Identifier: GPL-3.0-or-later
#include "contracts.h"
#include "common/identity.h"
#include "store/json_file.h"
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
                {"bounded_io_symlink_hardlink_fifo", bounds_and_path_refusal}});
}
