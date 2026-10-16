// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <string>
namespace droidvm::test {
// Runs in a private network namespace; bridgedhcp is resolved beside netbox.
// Fixture owner that is SIGKILLed with a live PD delegation in a data layout.
int linux_backend_pd_crash_child(const std::string& netbox, const std::string& data);
int linux_backend_namespace_child(const std::string& netbox, const std::string& work, const std::string& daemon);
}
