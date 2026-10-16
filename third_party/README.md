# Third-party code in the native daemon

`android_audio/` and `binder_ndk/` are header-only; each carries its own `UPSTREAM.json`.
The two libraries below back `vm_export`/`vm_import` (`pkg/compression.cpp`). Both are
unmodified subsets of the official release tarballs, built by small CMake files of our own
instead of their upstream build systems, and linked statically into `droidvmd` (and the
`droidvm_*_fixture` daemons). Nothing is shipped as a separate shared object.

| | zstd | liblzma (XZ Utils) |
|---|---|---|
| Version | 1.5.7 | 5.8.1 |
| Release asset | `zstd-1.5.7.tar.gz` (github.com/facebook/zstd) | `xz-5.8.1.tar.gz` (github.com/tukaani-project/xz) |
| SHA-256 of the tarball | `eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3` | `507825b599356c10dca1cd720c9d0d0c9d5400b9de300af00e4d1ea150795543` |
| License | BSD-3-Clause OR GPL-2.0-only (`zstd/LICENSE`, `zstd/COPYING`); used under BSD-3-Clause | 0BSD for liblzma (`xz/COPYING`, `xz/COPYING.0BSD`) |
| CMake target | `droidvm_zstd` (`zstd/CMakeLists.txt`) | `droidvm_lzma` (`xz/CMakeLists.txt`) |
| Legacy counterpart | zstd-jni 1.5.7-11 (bundles zstd 1.5.7) | xz-java 1.10 (same `.xz` container format) |

Gzip uses the NDK's system zlib (`libz`), as `java.util.zip` does on Android.

## Subset kept

* zstd: `lib/zstd.h`, `lib/zstd_errors.h`, and every file of `lib/common`, `lib/compress`
  and `lib/decompress` except `huf_decompress_amd64.S`. Not kept: `lib/legacy`,
  `lib/deprecated`, `lib/dictBuilder`, `lib/dll`, programs, tests, contrib, docs, build files.
* liblzma: the public headers (`src/liblzma/api`), the single-threaded `.xz` stream
  encoder and decoder (`common/`), the LZ match finders and decoder (`lz/`), LZMA1/LZMA2
  (`lzma/`), the range coder (`rangecoder/`), the CRC32/CRC64/SHA-256 checks (`check/`)
  and the five `src/common` headers they include. `simple/` and `delta/` keep only the
  three declaration headers each that `filter_common.c`/`filter_*coder.c` include; their
  coders are not compiled. Not kept: the multithreaded coders, `.lzma`/lzip/microlzma
  formats, BCJ and delta filters, string conversion, the `xz`/`xzdec` tools, translations,
  tests, docs and the autotools/CMake build systems.

## Configuration

* zstd: `ZSTD_MULTITHREAD` (pthreads) so `ZSTD_c_nbWorkers` works like zstd-jni's
  `setWorkers(4)`; `ZSTD_LEGACY_SUPPORT=0` (frames older than v0.8 are not read);
  `ZSTD_DISABLE_ASM` (the x86-64 Huffman assembly is replaced by its C fallback);
  `XXH_NAMESPACE=droidvm_zstd_` keeps xxHash symbols private.
* liblzma: `xz/config.h` is hand-written for Android API 33+ on 64-bit ABIs: LZMA2
  encoder and decoder, CRC32/CRC64/SHA-256, all match finders, POSIX threads/clock,
  `TUKLIB_FAST_UNALIGNED_ACCESS`; no architecture-specific CRC code (generic tables).
  The encoder is `lzma_easy_encoder(6, LZMA_CHECK_CRC64)`, which is what xz-java's
  `new XZOutputStream(out, new LZMA2Options())` writes; the decoder reads concatenated
  streams with padding, as `XZInputStream` does.

## Build

Both are static, position-independent C99 libraries compiled with `-O2` even in unoptimised
daemon builds, and with warnings disabled (`-w`): `-Wall -Wextra -Werror` applies to our code
only. ABIs built and tested: `arm64-v8a` and `x86_64` (`build/migration/standalone-*` and the
APK's externalNativeBuild).

## Updating

Replace the files from the new release tarball with the same subset, re-check the source lists
(zstd globs its three directories; `xz/CMakeLists.txt` lists files explicitly), update this table
and run `droidvm_pkg_contract` plus `scripts/migration/run_pkg_probe.py`.
