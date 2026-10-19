// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <string>

namespace droidvm {
std::string random_id(bool uuid);
// 256 random bits, encoded as 64 lowercase hex characters. No UUID bit masking.
std::string random_secret();
}
