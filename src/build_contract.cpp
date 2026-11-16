#include "warp/build_profile.h"
#include "sdkconfig.h"
#include "esp_idf_version.h"
#include "esp_arduino_version.h"
#include <optional>

static_assert(__cplusplus == 201703L, "Project sources must compile as C++17");
static_assert(std::optional<int>{17}.value() == 17, "C++17 library required");
static_assert(ESP_IDF_VERSION == ESP_IDF_VERSION_VAL(5, 5, 5), "ESP-IDF version drift");
static_assert(ESP_ARDUINO_VERSION == ESP_ARDUINO_VERSION_VAL(3, 3, 12), "Arduino version drift");
static_assert(CONFIG_ESPTOOLPY_FLASHSIZE_4MB == 1, "Profile requires 4 MB flash");
static_assert(CONFIG_PARTITION_TABLE_OFFSET == 0xF000, "Reserved secure bootloader space changed");
static_assert(CONFIG_ESP32C3_REV_MIN_FULL >= 3, "Secure Boot v2 requires revision v0.3 or newer");
#if !defined(CONFIG_MBEDTLS_HAVE_TIME_DATE) || !defined(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE)
#error HTTPS requires certificate date validation and a trusted root bundle
#endif
#if defined(CONFIG_AUTOSTART_ARDUINO) || defined(CONFIG_ESP_TLS_INSECURE) || defined(CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY)
#error Startup must preserve NVS and HTTPS verification must remain enabled
#endif
#if !defined(CONFIG_MBEDTLS_PSK_MODES) || !defined(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK)
#error Arduino 3.3.12 ssl_client.cpp requires PSK modes to compile its TLS implementation
#endif

#if WARP_PROTECTED_BUILD
#if !defined(CONFIG_SECURE_BOOT_V2_ENABLED) || !defined(CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE) || !defined(CONFIG_NVS_ENCRYPTION)
#error Protected profile requires Secure Boot v2, Release Flash Encryption and encrypted NVS
#endif
#if defined(CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES) || defined(CONFIG_SECURE_BOOT_FLASH_BOOTLOADER_DEFAULT)
#error Signing and bootloader flashing must remain separate from ordinary builds
#endif
#if !defined(CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE)
#error Preserve Secure Download Mode for the planned USB update process
#endif
#if defined(CONFIG_SECURE_BOOT_ALLOW_JTAG) || defined(CONFIG_SECURE_BOOT_V2_ALLOW_EFUSE_RD_DIS) || defined(CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_ENC) || defined(CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_CACHE) || defined(CONFIG_SECURE_FLASH_SKIP_WRITE_PROTECTION_CACHE) || defined(CONFIG_SECURE_DISABLE_ROM_DL_MODE) || defined(CONFIG_SECURE_INSECURE_ALLOW_DL_MODE) || defined(CONFIG_SECURE_BOOT_ENABLE_AGGRESSIVE_KEY_REVOKE)
#error Unsafe security exception in protected profile
#endif
#if defined(CONFIG_SECURE_BOOT_ALLOW_UNUSED_DIGEST_SLOTS) || defined(CONFIG_SECURE_BOOT_INSECURE)
#error Protected profile uses one trusted signing key and revokes unused slots
#endif
#else
#if defined(CONFIG_SECURE_BOOT) || defined(CONFIG_SECURE_FLASH_ENC_ENABLED) || defined(CONFIG_NVS_ENCRYPTION)
#error Test profile must never enable irreversible protection or encrypted NVS
#endif
#endif
