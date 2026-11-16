#pragma once
#include <cstddef>
#include "esp_crt_bundle.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

namespace warp::detail {
// One socket and one TLS context, destroyed on every return path. No session cache.
struct Transport {
    mbedtls_net_context socket{};
    mbedtls_ssl_context ssl{};
    mbedtls_ssl_config config{};
    mbedtls_entropy_context entropy{};
    mbedtls_ctr_drbg_context random{};
    bool secure{false};
    Transport() {
        mbedtls_net_init(&socket);
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&config);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&random);
    }
    ~Transport() {
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&config);
        mbedtls_ctr_drbg_free(&random);
        mbedtls_entropy_free(&entropy);
        mbedtls_net_free(&socket);
    }
    int setupTls(const char* host) {
        secure = true;
        static const unsigned char personalization[] = "warp-site-probe";
        int rc = mbedtls_ctr_drbg_seed(&random, mbedtls_entropy_func, &entropy,
                                      personalization, sizeof(personalization) - 1);
        if (rc) return rc;
        rc = mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT,
                                        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
        if (rc) return rc;
        mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &random);
        rc = esp_crt_bundle_attach(&config);
        if (rc) return rc;
        rc = mbedtls_ssl_setup(&ssl, &config);
        if (rc) return rc;
        rc = mbedtls_ssl_set_hostname(&ssl, host);  // SNI and certificate SAN/CN verification
        if (rc) return rc;
        mbedtls_ssl_set_bio(&ssl, &socket, mbedtls_net_send, mbedtls_net_recv, nullptr);
        return 0;
    }
    int write(const unsigned char* bytes, std::size_t size) {
        return secure ? mbedtls_ssl_write(&ssl, bytes, size) : mbedtls_net_send(&socket, bytes, size);
    }
    int read(unsigned char* bytes, std::size_t size) {
        return secure ? mbedtls_ssl_read(&ssl, bytes, size) : mbedtls_net_recv(&socket, bytes, size);
    }
};
}  // namespace warp::detail
