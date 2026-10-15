// SPDX-License-Identifier: GPL-3.0-or-later
// Shared syscall core extracted from unixhelper/native_process.c; no JNI/JVM.
#pragma once
#include <stddef.h>
#include <sys/resource.h>
#include <sys/types.h>
#ifdef __cplusplus
extern "C" {
#endif
enum droidvm_exec_stage { DROIDVM_EXEC_OK, DROIDVM_EXEC_STDIO, DROIDVM_EXEC_GROUP,
    DROIDVM_EXEC_DIRECTORY, DROIDVM_EXEC_SIGNALS, DROIDVM_EXEC_LIMIT, DROIDVM_EXEC_IMAGE };
struct droidvm_process_limit { int resource; rlim_t soft, hard; };
struct droidvm_process_options {
    char* const* argv;
    char* const* envp; // NULL inherits the parent's environment, as the JNI did.
    const char* directory;
    const int* preserve_fds;
    size_t preserve_count;
    const struct droidvm_process_limit* limits;
    size_t limit_count;
    int stdio[3]; // -1 creates a pipe; otherwise duplicate this caller-owned FD.
    int new_process_group;
};
struct droidvm_process_result {
    pid_t pid;
    int pipes[3]; // parent stdin-write, stdout-read, stderr-read; -1 if redirected.
    int exec_stage, exec_errno;
};
// Success means fork succeeded. exec_stage/errno distinguish child setup/exec
// failure from a program legitimately exiting 126/127. Caller MUST reap pid.
int droidvm_process_spawn(const struct droidvm_process_options* options, struct droidvm_process_result* result);
// 1 reaped, 0 still running, -1 error; exit_code keeps JNI's -signal convention.
int droidvm_process_wait(pid_t pid, int block, int* exit_code);
#ifdef __cplusplus
}
#endif
