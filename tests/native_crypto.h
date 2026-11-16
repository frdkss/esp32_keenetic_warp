#pragma once
#include <Windows.h>
#include <bcrypt.h>
#include <cstddef>
#pragma comment(lib, "bcrypt.lib")
inline int nativeHash(LPCWSTR algorithm, const unsigned char* input, std::size_t size, unsigned char* output, ULONG length) {
    BCRYPT_ALG_HANDLE provider = nullptr;
    if (BCryptOpenAlgorithmProvider(&provider, algorithm, nullptr, 0) < 0) return -1;
    const auto result = BCryptHash(provider, nullptr, 0, const_cast<PUCHAR>(input), static_cast<ULONG>(size), output, length);
    BCryptCloseAlgorithmProvider(provider, 0); return result < 0 ? -1 : 0;
}
int mbedtls_md5(const unsigned char* data, std::size_t size, unsigned char* output) {
    return nativeHash(BCRYPT_MD5_ALGORITHM, data, size, output, 16);
}
int mbedtls_sha256(const unsigned char* data, std::size_t size, unsigned char* output, int is224) {
    if (is224) return -1;
    return nativeHash(BCRYPT_SHA256_ALGORITHM, data, size, output, 32);
}
