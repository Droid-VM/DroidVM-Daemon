// SPDX-License-Identifier: GPL-3.0-or-later
#include "input_bridge.h"
#include <cerrno>
#include <chrono>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace droidvm::vm {
namespace {
constexpr int keyboard = 1;
bool per_screen(int channel) { return channel == 0 || channel == 3 || channel == keyboard; }
}
std::string InputBridge::key(const std::string& screen, int channel) {
    return (per_screen(channel) ? screen : std::string()) + "/" + std::to_string(channel);
}
InputBridge::~InputBridge() { release(); }
bool InputBridge::listen(const std::vector<InputSocket>& sockets, Status status) {
    release();
    closed_ = false;
    status_ = std::move(status);
    bool all = true;
    std::lock_guard lock(mutex_);
    for (const auto& socket : sockets) {
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        if (socket.path.size() >= sizeof(address.sun_path)) throw std::invalid_argument("unix socket path too long: " + socket.path);
        std::copy(socket.path.begin(), socket.path.end(), address.sun_path);
        Fd server(::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
        unlink(socket.path.c_str());
        if (server.get() < 0 || bind(server.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 || ::listen(server.get(), 1) != 0) {
            unlink(socket.path.c_str());
            all = false;
            continue;
        }
        auto slot = std::make_unique<Slot>();
        slot->socket = socket;
        slot->server = std::move(server);
        auto* raw = slot.get();
        slots_[key(socket.screen, socket.channel)] = std::move(slot);
        // crosvm connects during its own startup, possibly after it was execed.
        raw->acceptor = std::thread(&InputBridge::accept, this, std::ref(*raw));
    }
    return all;
}
void InputBridge::accept(Slot& slot) {
    while (!closed_) {
        const int fd = accept4(slot.server.get(), nullptr, nullptr, SOCK_CLOEXEC);
        if (fd < 0) {
            if (closed_) break;
            if (errno != EINTR) std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }
        auto peer = std::make_shared<Fd>(fd);
        std::lock_guard lock(slot.lock);
        if (closed_) break;
        if (slot.peer) shutdown(slot.peer->get(), SHUT_RDWR);
        slot.peer = peer;
        if (slot.socket.channel != keyboard) continue;
        // Guest LED status, delivered in whole 8-byte records.
        slot.readers.emplace_back([this, peer, screen = slot.socket.screen] {
            std::string held;
            char buffer[256];
            for (;;) {
                const auto count = read(peer->get(), buffer, sizeof(buffer));
                if (count < 0 && errno == EINTR) continue;
                if (count <= 0 || closed_) break;
                held.append(buffer, static_cast<size_t>(count));
                const auto whole = held.size() - held.size() % 8;
                if (whole && status_) status_(screen, keyboard, held.substr(0, whole));
                held.erase(0, whole);
            }
        });
    }
}
bool InputBridge::write(const std::string& screen, int channel, std::string_view data) {
    if (channel < 0 || channel >= 4 || data.empty()) return false;
    Slot* slot;
    {
        std::lock_guard lock(mutex_);
        const auto at = slots_.find(key(screen, channel));
        if (at == slots_.end()) return false;
        slot = at->second.get();
    }
    std::lock_guard lock(slot->lock);
    if (!slot->peer) return false;
    while (!data.empty()) {
        const auto sent = send(slot->peer->get(), data.data(), data.size(), MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) { shutdown(slot->peer->get(), SHUT_RDWR); slot->peer.reset(); return false; }
        data.remove_prefix(static_cast<size_t>(sent));
    }
    return true;
}
void InputBridge::release() {
    std::map<std::string, std::unique_ptr<Slot>> slots;
    { std::lock_guard lock(mutex_); slots.swap(slots_); }
    closed_ = true;
    for (auto& [name, slot] : slots) {
        shutdown(slot->server.get(), SHUT_RDWR); // wakes the blocked accept
        {
            std::lock_guard lock(slot->lock);
            if (slot->peer) shutdown(slot->peer->get(), SHUT_RDWR);
        }
        if (slot->acceptor.joinable()) slot->acceptor.join();
        for (auto& reader : slot->readers) if (reader.joinable()) reader.join();
        unlink(slot->socket.path.c_str());
    }
}
}
