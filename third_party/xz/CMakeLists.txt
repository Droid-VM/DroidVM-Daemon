# liblzma 5.8.1 subset (see ../README.md); upstream's build system is not used.
set(DROIDVM_LZMA "${CMAKE_CURRENT_SOURCE_DIR}/src/liblzma")
add_library(droidvm_lzma STATIC
    ${DROIDVM_LZMA}/check/check.c ${DROIDVM_LZMA}/check/crc32_fast.c ${DROIDVM_LZMA}/check/crc64_fast.c ${DROIDVM_LZMA}/check/sha256.c
    ${DROIDVM_LZMA}/common/common.c ${DROIDVM_LZMA}/common/block_util.c ${DROIDVM_LZMA}/common/easy_preset.c
    ${DROIDVM_LZMA}/common/filter_common.c ${DROIDVM_LZMA}/common/index.c ${DROIDVM_LZMA}/common/stream_flags_common.c
    ${DROIDVM_LZMA}/common/vli_size.c
    ${DROIDVM_LZMA}/common/block_encoder.c ${DROIDVM_LZMA}/common/block_header_encoder.c ${DROIDVM_LZMA}/common/easy_encoder.c
    ${DROIDVM_LZMA}/common/filter_encoder.c ${DROIDVM_LZMA}/common/filter_flags_encoder.c ${DROIDVM_LZMA}/common/index_encoder.c
    ${DROIDVM_LZMA}/common/stream_encoder.c ${DROIDVM_LZMA}/common/stream_flags_encoder.c ${DROIDVM_LZMA}/common/vli_encoder.c
    ${DROIDVM_LZMA}/common/block_decoder.c ${DROIDVM_LZMA}/common/block_header_decoder.c ${DROIDVM_LZMA}/common/filter_decoder.c
    ${DROIDVM_LZMA}/common/filter_flags_decoder.c ${DROIDVM_LZMA}/common/index_decoder.c ${DROIDVM_LZMA}/common/index_hash.c
    ${DROIDVM_LZMA}/common/stream_decoder.c ${DROIDVM_LZMA}/common/stream_flags_decoder.c ${DROIDVM_LZMA}/common/vli_decoder.c
    ${DROIDVM_LZMA}/lz/lz_encoder.c ${DROIDVM_LZMA}/lz/lz_encoder_mf.c ${DROIDVM_LZMA}/lz/lz_decoder.c
    ${DROIDVM_LZMA}/lzma/fastpos_table.c ${DROIDVM_LZMA}/lzma/lzma_encoder.c ${DROIDVM_LZMA}/lzma/lzma_encoder_optimum_fast.c
    ${DROIDVM_LZMA}/lzma/lzma_encoder_optimum_normal.c ${DROIDVM_LZMA}/lzma/lzma_encoder_presets.c ${DROIDVM_LZMA}/lzma/lzma_decoder.c
    ${DROIDVM_LZMA}/lzma/lzma2_encoder.c ${DROIDVM_LZMA}/lzma/lzma2_decoder.c
    ${DROIDVM_LZMA}/rangecoder/price_table.c
)
target_include_directories(droidvm_lzma PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/src/common"
    ${DROIDVM_LZMA}/api ${DROIDVM_LZMA}/common ${DROIDVM_LZMA}/check ${DROIDVM_LZMA}/lz ${DROIDVM_LZMA}/lzma
    ${DROIDVM_LZMA}/rangecoder ${DROIDVM_LZMA}/simple ${DROIDVM_LZMA}/delta)
target_include_directories(droidvm_lzma SYSTEM PUBLIC ${DROIDVM_LZMA}/api)
target_compile_definitions(droidvm_lzma PRIVATE HAVE_CONFIG_H PUBLIC LZMA_API_STATIC)
set_target_properties(droidvm_lzma PROPERTIES POSITION_INDEPENDENT_CODE ON C_STANDARD 99)
# Third-party code: optimized even in unoptimized daemon builds, upstream warnings not ours to fix.
target_compile_options(droidvm_lzma PRIVATE -O2 -w)
target_link_libraries(droidvm_lzma PRIVATE Threads::Threads)
