# zstd 1.5.7 library subset (see ../README.md); upstream's build system is not used.
file(GLOB DROIDVM_ZSTD_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/lib/common/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/lib/compress/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/lib/decompress/*.c")
add_library(droidvm_zstd STATIC ${DROIDVM_ZSTD_SOURCES})
target_include_directories(droidvm_zstd SYSTEM PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/lib")
# ZSTD_MULTITHREAD backs ZSTD_c_nbWorkers (zstd-jni setWorkers). No legacy
# formats, no dictionary builder; the x86-64 Huffman assembly is replaced by C.
target_compile_definitions(droidvm_zstd PRIVATE ZSTD_MULTITHREAD ZSTD_LEGACY_SUPPORT=0 ZSTD_DISABLE_ASM XXH_NAMESPACE=droidvm_zstd_)
set_target_properties(droidvm_zstd PROPERTIES POSITION_INDEPENDENT_CODE ON C_STANDARD 99)
target_compile_options(droidvm_zstd PRIVATE -O2 -w)
target_link_libraries(droidvm_zstd PRIVATE Threads::Threads)
