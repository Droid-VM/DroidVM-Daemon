// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "services/config_gate.h"
#include <atomic>
#include <chrono>
#include <future>
#include <optional>
#include <thread>

namespace droidvm::test {
using namespace std::chrono_literals;
inline void gate_check(bool value, const char* detail) {
    if (!value) throw std::runtime_error(detail);
}
template<class F> void gate_unavailable(F&& work) {
    try { work(); }
    catch (const ServiceError& error) {
        gate_check(error.code() == ErrorCode::unavailable, "unexpected gate error"); return;
    }
    throw std::runtime_error("gate admitted an excluded operation");
}
inline void configuration_gate_drains_nested_admissions() {
    auto gate = std::make_shared<ConfigurationGate>();
    std::optional<ConfigurationGate::Admission> outer, nested;
    outer.emplace(ConfigurationGate::enter(gate));
    nested.emplace(ConfigurationGate::enter(gate));
    std::atomic<bool> acquired{false};
    auto transaction = std::async(std::launch::async, [&] {
        auto exclusive = gate->transaction();
        acquired = true;
        exclusive.require_recovery();
    });
    bool draining = false;
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!draining && std::chrono::steady_clock::now() < deadline) {
        try { auto another = ConfigurationGate::enter(gate); }
        catch (const ServiceError& error) { draining = error.code() == ErrorCode::unavailable; }
        std::this_thread::yield();
    }
    const bool early = acquired.load();
    nested.reset();
    const bool after_nested = acquired.load();
    outer.reset();
    transaction.get();
    gate_check(draining && !early && !after_nested && acquired, "transaction drains all nested admissions before domain work");
    gate_unavailable([&] { ConfigurationGate::enter(gate); });
    { auto recovery = gate->transaction(); recovery.recovered(); }
    auto admitted = ConfigurationGate::enter(gate);
}
}
