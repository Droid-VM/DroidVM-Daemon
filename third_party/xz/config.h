/* Hand-written liblzma configuration for DroidVM's Android builds (arm64-v8a, x86_64).
   Single-threaded .xz encoder/decoder with the LZMA2 filter and the
   CRC32/CRC64/SHA-256 checks; no BCJ/delta filters, no lzip/microlzma. */
#pragma once
#define HAVE_STDBOOL_H 1
#define HAVE__BOOL 1
#define HAVE_STDINT_H 1
#define HAVE_INTTYPES_H 1
#define SIZEOF_SIZE_T 8
#define HAVE_CHECK_CRC32 1
#define HAVE_CHECK_CRC64 1
#define HAVE_CHECK_SHA256 1
#define HAVE_ENCODERS 1
#define HAVE_DECODERS 1
#define HAVE_ENCODER_LZMA2 1
#define HAVE_DECODER_LZMA2 1
#define HAVE_MF_HC3 1
#define HAVE_MF_HC4 1
#define HAVE_MF_BT2 1
#define HAVE_MF_BT3 1
#define HAVE_MF_BT4 1
#define MYTHREAD_POSIX 1
#define HAVE_CLOCK_GETTIME 1
#define HAVE_CLOCK_MONOTONIC 1
#define HAVE_PTHREAD_CONDATTR_SETCLOCK 1
#define HAVE___BUILTIN_BSWAPXX 1
#define HAVE___BUILTIN_ASSUME_ALIGNED 1
#define TUKLIB_FAST_UNALIGNED_ACCESS 1
#define TUKLIB_SYMBOL_PREFIX lzma_
#define HAVE_VISIBILITY 0
