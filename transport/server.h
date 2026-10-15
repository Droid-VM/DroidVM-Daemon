// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
namespace droidvm {
class Instance;
class RequestDispatcher;
int serve(Instance& instance, RequestDispatcher& service, const char* token, int signal_fd);
}
