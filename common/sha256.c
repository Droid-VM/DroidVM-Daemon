// SPDX-License-Identifier: GPL-3.0-or-later
// Use the SHA-256 implementation already bundled with liblzma.
#include "sha256.h"
#include "check.h"
#include <string.h>

void droidvm_sha256(const unsigned char* bytes, size_t length, unsigned char output[32]) {
    lzma_check_state state;
    lzma_sha256_init(&state);
    lzma_sha256_update(bytes, length, &state);
    lzma_sha256_finish(&state);
    memcpy(output, state.buffer.u8, 32);
}
