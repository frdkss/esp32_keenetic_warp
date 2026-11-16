#include "warp/tls_transport.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/version.h"
#include <cstdlib>
#include <iostream>

mbedtls_x509_crt authority;
int esp_crt_bundle_attach(mbedtls_ssl_config* config) {
    mbedtls_ssl_conf_ca_chain(config, &authority, nullptr);
    return 0;
}
int main(int argc, char** argv) {
    if (argc != 4) return 2;
    mbedtls_x509_crt_init(&authority);
    if (mbedtls_x509_crt_parse_file(&authority, argv[1])) return 3;
    int rc = 0;
    unsigned flags = 0;
    {
        // This is the transport used by both firmware HTTP clients.
        warp::detail::Transport io;
        rc = mbedtls_net_connect(&io.socket, "127.0.0.1", argv[2], MBEDTLS_NET_PROTO_TCP);
        if (!rc) rc = io.setupTls("router.stage10.invalid");
        if (!rc) rc = mbedtls_ssl_handshake(&io.ssl);
        flags = mbedtls_ssl_get_verify_result(&io.ssl);
        std::cout << "mbedtls=" << MBEDTLS_VERSION_STRING << " rc=" << rc << " flags=" << flags << "\n";
        const unsigned expected = static_cast<unsigned>(std::strtoul(argv[3], nullptr, 10));
        if (expected) {
            if (rc != MBEDTLS_ERR_X509_CERT_VERIFY_FAILED || flags != expected || !io.secure) return 4;
        } else {
            if (rc || flags) return 5;
            static const unsigned char payload[] = "STAGE10-APPLICATION-DATA";
            if (io.write(payload, sizeof(payload) - 1) != sizeof(payload) - 1) return 6;
            unsigned char acknowledgement = 0;
            if (io.read(&acknowledgement, 1) != 1 || acknowledgement != '!') return 7;
            mbedtls_ssl_close_notify(&io.ssl);
        }
    }
    mbedtls_x509_crt_free(&authority);
}
