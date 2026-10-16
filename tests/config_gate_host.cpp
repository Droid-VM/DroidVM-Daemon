// SPDX-License-Identifier: GPL-3.0-or-later
// Standalone C++20 host test, using the same gate/drain test as Android inventory.
#include "config_gate_contract.h"
#include <iostream>
#include <vector>

using namespace droidvm;
using namespace droidvm::test;
int main() {
    try {
        configuration_gate_drains_nested_admissions();
        auto gate = std::make_shared<ConfigurationGate>();
        {
            auto exclusive = gate->transaction();
            gate_unavailable([&] { ConfigurationGate::enter(gate); });
            exclusive.require_recovery();
        }
        gate_unavailable([&] { ConfigurationGate::enter(gate); });
        {
            auto recovery = gate->transaction();
            recovery.recovered();
            gate_unavailable([&] { ConfigurationGate::enter(gate); });
        }
        { auto admitted = ConfigurationGate::enter(gate); }
        std::atomic<int> inside{0}, completed{0};
        std::vector<std::future<void>> writers;
        for (int i = 0; i < 12; ++i) writers.push_back(std::async(std::launch::async, [gate, &inside, &completed] {
            auto exclusive = gate->transaction();
            gate_check(++inside == 1, "transactions overlapped");
            std::this_thread::yield();
            --inside; ++completed;
        }));
        for (auto& writer : writers) writer.get();
        gate_check(completed == 12, "transaction writer was lost");
        std::cout << "PASS: nested admission drain, persistent fault/recovery, 12 exclusive writers\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n'; return 1;
    }
}
