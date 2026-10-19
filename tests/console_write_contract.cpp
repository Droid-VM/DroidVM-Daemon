// SPDX-License-Identifier: GPL-3.0-or-later
#include "vm/console_write.h"
#include "common/fd.h"
#include <array>
#include <chrono>
#include <iostream>
#include <source_location>

using namespace droidvm;
namespace {
void require(bool value, const std::source_location& at = std::source_location::current()) {
    if (!value) throw std::runtime_error("Console write contract failed at line " + std::to_string(at.line()));
}
template<class Work> void rejected(ErrorCode code, Work work) {
    try { work(); } catch (const ServiceError& error) { require(error.code() == code); return; }
    throw std::runtime_error("Expected console write rejection");
}
void socket_writes() {
    int pair[2]; require(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
    Fd writer(pair[0]), reader(pair[1]);
    const auto flags = fcntl(writer.get(), F_GETFL);
    const std::string bytes(vm::console_write_limit, 's');
    require(vm::bounded_console_write(writer.get(), bytes) == bytes.size());
    std::array<char, vm::console_write_limit> received{};
    require(recv(reader.get(), received.data(), received.size(), MSG_DONTWAIT) == static_cast<ssize_t>(bytes.size()));
    require(std::string_view(received.data(), received.size()) == bytes);
    rejected(ErrorCode::invalid_argument, [&] { vm::bounded_console_write(writer.get(), {}); });
    rejected(ErrorCode::invalid_argument, [&] { vm::bounded_console_write(writer.get(), std::string(513, 'x')); });
    bool backpressure = false;
    const auto started = std::chrono::steady_clock::now();
    for (size_t index = 0; index < 16384; ++index) {
        const auto accepted = vm::bounded_console_write(writer.get(), bytes);
        require(accepted <= bytes.size());
        if (!accepted) { backpressure = true; break; }
    }
    require(backpressure && std::chrono::steady_clock::now() - started < std::chrono::seconds(2));
    require(fcntl(writer.get(), F_GETFL) == flags);
    reader = Fd();
    rejected(ErrorCode::unavailable, [&] { vm::bounded_console_write(writer.get(), bytes); });
}
void pipe_writes() {
    int pair[2]; require(pipe2(pair, O_CLOEXEC) == 0);
    Fd reader(pair[0]), writer(pair[1]);
    const auto flags = fcntl(writer.get(), F_GETFL);
    const std::string bytes(vm::console_write_limit, 'p');
    require(vm::bounded_console_write(writer.get(), bytes) == bytes.size());
    require(fcntl(writer.get(), F_GETFL) == flags);
    std::array<char, vm::console_write_limit> received{};
    require(read(reader.get(), received.data(), received.size()) == static_cast<ssize_t>(bytes.size()));
    require(std::string_view(received.data(), received.size()) == bytes);
    bool backpressure = false;
    const auto started = std::chrono::steady_clock::now();
    for (size_t index = 0; index < 16384; ++index) {
        const auto accepted = vm::bounded_console_write(writer.get(), bytes);
        require(accepted == 0 || accepted == bytes.size()); // <= PIPE_BUF is atomic
        require(fcntl(writer.get(), F_GETFL) == flags);
        if (!accepted) { backpressure = true; break; }
    }
    require(backpressure && std::chrono::steady_clock::now() - started < std::chrono::seconds(2));
    sigset_t previous{}, after{};
    require(pthread_sigmask(SIG_SETMASK, nullptr, &previous) == 0);
    reader = Fd();
    rejected(ErrorCode::unavailable, [&] { vm::bounded_console_write(writer.get(), bytes); });
    require(fcntl(writer.get(), F_GETFL) == flags);
    require(pthread_sigmask(SIG_SETMASK, nullptr, &after) == 0);
    require(sigismember(&previous, SIGPIPE) == sigismember(&after, SIGPIPE));
    // The shared helper must preserve a SIGPIPE that predates this write.
    sigset_t block{}, restore{}, pending{};
    sigemptyset(&block); sigaddset(&block, SIGPIPE);
    require(pthread_sigmask(SIG_BLOCK, &block, &restore) == 0);
    require(raise(SIGPIPE) == 0);
    rejected(ErrorCode::unavailable, [&] { vm::bounded_console_write(writer.get(), bytes); });
    require(sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 1);
    timespec zero{};
    require(sigtimedwait(&block, nullptr, &zero) == SIGPIPE);
    require(pthread_sigmask(SIG_SETMASK, &restore, nullptr) == 0);
}
}
int main() {
    try {
        socket_writes(); pipe_writes();
        std::cout << "console write contracts passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
