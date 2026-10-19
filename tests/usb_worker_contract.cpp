// SPDX-License-Identifier: GPL-3.0-or-later
#include "usb/worker.h"
#include <future>
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace droidvm::usb;
using namespace std::chrono_literals;
namespace {
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
}
int main() {
    try {
        Worker worker("usb-contract");
        std::promise<void> entered, release, following;
        auto entered_future = entered.get_future();
        auto release_future = release.get_future().share();
        auto following_future = following.get_future();
        std::vector<int> order;
        auto first = std::async(std::launch::async, [&] {
            return worker.submit([&] {
                check(worker.on_worker(), "mutation runs on worker");
                order.push_back(1);
                entered.set_value();
                release_future.wait();
                auto nested = worker.submit([&] { order.push_back(2); return 42; });
                order.push_back(3);
                return nested.value();
            });
        });
        check(entered_future.wait_for(2s) == std::future_status::ready, "first mutation entered");
        const bool accepted = worker.schedule([&] { order.push_back(4); following.set_value(); });
        const bool waited = following_future.wait_for(20ms) == std::future_status::timeout;
        release.set_value();
        check(accepted && waited, "another mutation waits through validation and operation");
        check(first.wait_for(2s) == std::future_status::ready && first.get() == 42, "nested submit completes inline");
        check(following_future.wait_for(2s) == std::future_status::ready, "queued work continues");
        check(worker.wait_idle(2s), "worker idle");
        check(order == std::vector<int>({1, 2, 3, 4}), "nested mutation cannot be interleaved");
        std::cout << "PASS serialized validation, nested work and concurrent request\n";
        bool rejected = false, applied = false;
        try {
            worker.submit([&]() -> int {
                worker.submit([]() -> int { throw std::runtime_error("stale observation"); });
                applied = true;
                return 0;
            });
        } catch (const std::runtime_error& error) { rejected = std::string(error.what()) == "stale observation"; }
        check(rejected && !applied, "validation exception aborts operation and reaches caller");
        check(worker.submit([] { return 7; }) == 7, "worker survives validation rejection");
        std::cout << "PASS rejection prevents side effect and preserves worker\n";
        check(worker.shutdown(2s), "clean shutdown");
        check(!worker.submit([] { return 1; }), "shutdown rejects new requests");
        std::cout << "PASS shutdown rejects new operations\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
