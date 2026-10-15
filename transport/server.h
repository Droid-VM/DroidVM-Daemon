// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
namespace droidvm {
class Instance;
class SystemService;
int serve(Instance& instance, SystemService& service, const char* token, int signal_fd);
}
