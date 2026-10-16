// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <string>
namespace droidvm::test {
// Runs in a private network namespace; bridgedhcp is resolved beside netbox.
int linux_backend_namespace_child(const std::string& netbox, const std::string& work, const std::string& daemon);
}
