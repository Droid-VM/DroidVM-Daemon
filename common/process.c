// SPDX-License-Identifier: GPL-3.0-or-later
// Fork/stdio/env/cwd/preserve-fd/rlimit behavior extracted from native_process.c.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "process.h"
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char** environ;
static int compare_fd(const void* left, const void* right) { return (*(const int*)left > *(const int*)right) - (*(const int*)left < *(const int*)right); }
static int high_fd(int fd) {
    if (fd < 0 || fd >= 3) return fd;
    int moved = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    int error = errno;
    close(fd);
    errno = error;
    return moved;
}
static int high_pipe(int pair[2]) {
    if (pipe2(pair, O_CLOEXEC)) return -1;
    pair[0] = high_fd(pair[0]);
    if (pair[0] < 0) return -1;
    pair[1] = high_fd(pair[1]);
    return pair[1] < 0 ? -1 : 0;
}
static void close_unwanted(const int* keep, size_t count, int max_fd) {
    // All allocation and range sorting happen before fork. close_range is an
    // optimization; old kernels retain the original per-FD close behavior.
#ifdef __NR_close_range
    unsigned first = 3;
    int supported = 1;
    for (size_t i = 0; i < count; ++i) {
        const unsigned next = (unsigned)keep[i];
        if (next < first) continue;
        if (next > first && syscall(__NR_close_range, first, next - 1, 0) < 0) { supported = 0; break; }
        first = next + 1;
    }
    if (supported && syscall(__NR_close_range, first, UINT_MAX, 0) == 0) return;
#endif
    size_t index = 0;
    for (int fd = 3; fd < max_fd; ++fd) {
        while (index < count && keep[index] < fd) ++index;
        if (index == count || keep[index] != fd) close(fd);
    }
}
static void child_error(int fd, int stage, int error) {
    const int record[2] = {stage, error};
    ssize_t written;
    do { written = write(fd, record, sizeof(record)); } while (written < 0 && errno == EINTR);
    _exit(stage == DROIDVM_EXEC_IMAGE || stage == DROIDVM_EXEC_DIRECTORY ? 127 : 126);
}
int droidvm_process_spawn(const struct droidvm_process_options* options, struct droidvm_process_result* result) {
    return droidvm_process_spawn_gated(options, result, NULL, NULL);
}
int droidvm_process_spawn_gated(const struct droidvm_process_options* options, struct droidvm_process_result* result,
    int (*before_exec)(pid_t, void*), void* context) {
    if (!options || !result || !options->argv || !options->argv[0] || !options->argv[0][0] ||
        options->preserve_count > 4096 || options->limit_count > 64 ||
        (options->preserve_count && !options->preserve_fds) || (options->limit_count && !options->limits)) {
        errno = EINVAL; return -1;
    }
    result->pid = -1;
    result->exec_stage = result->exec_errno = 0;
    for (int i = 0; i < 3; ++i) result->pipes[i] = -1;
    for (size_t i = 0; i < options->preserve_count; ++i) {
        if (options->preserve_fds[i] < 0) { errno = EINVAL; return -1; }
        if (fcntl(options->preserve_fds[i], F_GETFD) < 0) return -1;
    }
    int pairs[3][2] = {{-1, -1}, {-1, -1}, {-1, -1}};
    int child_stdio[3] = {-1, -1, -1}, report[2] = {-1, -1}, gate[2] = {-1, -1};
    int* keep = malloc((options->preserve_count + 2) * sizeof(int));
    if (!keep) return -1;
    // Read the parent's limit before fork (sysconf is not child-side safe).
    struct rlimit files;
    if (getrlimit(RLIMIT_NOFILE, &files)) goto fail;
    int max_fd = files.rlim_max < INT_MAX ? (int)files.rlim_max : INT_MAX;
    // Existing descriptors can remain above a subsequently lowered hard limit.
    DIR* descriptors = opendir("/proc/self/fd");
    if (!descriptors) goto fail;
    struct dirent* entry;
    while ((entry = readdir(descriptors))) {
        char* end;
        long fd = strtol(entry->d_name, &end, 10);
        if (*entry->d_name && !*end && fd >= max_fd && fd < INT_MAX) max_fd = (int)fd + 1;
    }
    closedir(descriptors);
    for (int i = 0; i < 3; ++i) {
        if (options->stdio[i] < -1) { errno = EINVAL; goto fail; }
        if (options->stdio[i] >= 0) {
            child_stdio[i] = fcntl(options->stdio[i], F_DUPFD_CLOEXEC, 3);
            if (child_stdio[i] < 0) goto fail;
        } else {
            if (high_pipe(pairs[i])) goto fail;
            child_stdio[i] = pairs[i][i == 0 ? 0 : 1];
        }
    }
    if (high_pipe(report)) goto fail;
    if (before_exec) {
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, gate)) goto fail;
        gate[0] = high_fd(gate[0]); gate[1] = high_fd(gate[1]);
        if (gate[0] < 0 || gate[1] < 0) goto fail;
    }
    for (size_t i = 0; i < options->preserve_count; ++i) keep[i] = options->preserve_fds[i];
    keep[options->preserve_count] = report[1];
    size_t keep_count = options->preserve_count + 1;
    if (before_exec) keep[keep_count++] = gate[0];
    qsort(keep, keep_count, sizeof(int), compare_fd);
    const pid_t pid = fork();
    if (pid < 0) goto fail;
    if (pid == 0) {
        // Only async-signal-safe operations below: no JNI, allocation or logging.
        for (int i = 0; i < 3; ++i) if (dup2(child_stdio[i], i) < 0) child_error(report[1], DROIDVM_EXEC_STDIO, errno);
        close_unwanted(keep, keep_count, max_fd);
        for (size_t i = 0; i < options->preserve_count; ++i)
            if (fcntl(options->preserve_fds[i], F_SETFD, 0) < 0) child_error(report[1], DROIDVM_EXEC_STDIO, errno);
        if (options->new_process_group && setpgid(0, 0)) child_error(report[1], DROIDVM_EXEC_GROUP, errno);
        if (options->directory && chdir(options->directory)) child_error(report[1], DROIDVM_EXEC_DIRECTORY, errno);
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_handler = SIG_DFL;
        sigemptyset(&action.sa_mask);
        for (int signal = 1; signal < NSIG; ++signal) sigaction(signal, &action, NULL);
        sigset_t empty;
        sigemptyset(&empty);
        if (sigprocmask(SIG_SETMASK, &empty, NULL)) child_error(report[1], DROIDVM_EXEC_SIGNALS, errno);
        for (size_t i = 0; i < options->limit_count; ++i) {
            struct rlimit limit = {options->limits[i].soft, options->limits[i].hard};
            if (setrlimit(options->limits[i].resource, &limit)) child_error(report[1], DROIDVM_EXEC_LIMIT, errno);
        }
        if (before_exec) {
            char release = 0;
            ssize_t received;
            do { received = read(gate[0], &release, 1); } while (received < 0 && errno == EINTR);
            close(gate[0]);
            if (received != 1 || release != 1) _exit(126);
        }
        execve(options->argv[0], options->argv, options->envp ? options->envp : environ);
        child_error(report[1], DROIDVM_EXEC_IMAGE, errno);
    }
    result->pid = pid;
    close(report[1]); report[1] = -1;
    for (int i = 0; i < 3; ++i) {
        if (options->stdio[i] >= 0) close(child_stdio[i]);
        else {
            close(child_stdio[i]);
            result->pipes[i] = pairs[i][i == 0 ? 1 : 0];
        }
    }
    free(keep);
    if (before_exec) {
        close(gate[0]);
        int accepted = before_exec(pid, context);
        const char release = 1;
        ssize_t sent = -1;
        if (accepted == 0) do { sent = send(gate[1], &release, 1, MSG_NOSIGNAL); } while (sent < 0 && errno == EINTR);
        const int gate_error = errno;
        close(gate[1]);
        if (sent != 1) {
            if (options->new_process_group) kill(-pid, SIGKILL);
            kill(pid, SIGKILL);
            while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
            close(report[0]);
            for (int i = 0; i < 3; ++i) if (result->pipes[i] >= 0) close(result->pipes[i]);
            result->pid = -1;
            errno = gate_error ? gate_error : EIO;
            return -1;
        }
    }
    struct pollfd ready = {report[0], POLLIN, 0};
    struct timespec start, current;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int polled;
    int remaining = 5000;
    for (;;) {
        polled = poll(&ready, 1, remaining);
        if (polled >= 0 || errno != EINTR) break;
        clock_gettime(CLOCK_MONOTONIC, &current);
        const int64_t elapsed = (int64_t)(current.tv_sec - start.tv_sec) * 1000 + (current.tv_nsec - start.tv_nsec) / 1000000;
        if (elapsed >= 5000) { polled = 0; break; }
        remaining = (int)(5000 - elapsed);
    }
    int message[2];
    ssize_t count = -1;
    if (polled > 0) do { count = read(report[0], message, sizeof(message)); } while (count < 0 && errno == EINTR);
    const int error = polled == 0 ? ETIMEDOUT : errno;
    close(report[0]);
    if (count == sizeof(message)) { result->exec_stage = message[0]; result->exec_errno = message[1]; }
    else if (count != 0) {
        if (options->new_process_group) kill(-pid, SIGKILL);
        kill(pid, SIGKILL);
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
        for (int i = 0; i < 3; ++i) if (result->pipes[i] >= 0) close(result->pipes[i]);
        result->pid = -1;
        errno = error ? error : EIO;
        return -1;
    }
    return 0;
fail: {
        const int error = errno;
        for (int i = 0; i < 3; ++i) {
            if (options->stdio[i] >= 0 && child_stdio[i] >= 0) close(child_stdio[i]);
            for (int j = 0; j < 2; ++j) if (pairs[i][j] >= 0) close(pairs[i][j]);
        }
        for (int i = 0; i < 2; ++i) if (report[i] >= 0) close(report[i]);
        for (int i = 0; i < 2; ++i) if (gate[i] >= 0) close(gate[i]);
        free(keep);
        errno = error;
        return -1;
    }
}
int droidvm_process_wait(pid_t pid, int block, int* exit_code) {
    if (pid <= 0 || !exit_code) { errno = EINVAL; return -1; }
    int status;
    pid_t waited;
    do { waited = waitpid(pid, &status, block ? 0 : WNOHANG); } while (waited < 0 && errno == EINTR);
    if (waited <= 0) return (int)waited;
    *exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : (WIFSIGNALED(status) ? -WTERMSIG(status) : -1);
    return 1;
}
