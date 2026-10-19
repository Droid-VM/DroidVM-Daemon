// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
void droidvm_sha256(const unsigned char* bytes, size_t length, unsigned char output[32]);
#ifdef __cplusplus
}
#endif
