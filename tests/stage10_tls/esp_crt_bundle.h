#pragma once
#include "mbedtls/ssl.h"
// Test-only seam for the platform CA bundle. Certificate verification is real.
int esp_crt_bundle_attach(mbedtls_ssl_config* config);
