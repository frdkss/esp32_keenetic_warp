cmake_minimum_required(VERSION 3.16)
project(warp_stage10_tls LANGUAGES C CXX)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
add_compile_definitions(MBEDTLS_USER_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/tls12_config.h")
# Compile the very same pinned Mbed TLS sources; ESP hardware acceleration and
# the ROM certificate bundle are replaced by desktop RNG and a test-only CA.
add_subdirectory("${WARP_MBEDTLS}" mbedtls EXCLUDE_FROM_ALL)
add_executable(stage10_tls main.cpp)
target_compile_features(stage10_tls PRIVATE cxx_std_17)
target_include_directories(stage10_tls PRIVATE . ../../include)
target_link_libraries(stage10_tls PRIVATE mbedtls mbedx509 mbedcrypto)
