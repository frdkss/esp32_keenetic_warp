#include "warp/config_tag.h"
#include <cstring>
#include "mbedtls/md.h"

namespace warp {
bool configurationTag(const RuntimeConfiguration& c, const unsigned char* key64, unsigned char* output32) {
    if (!validSchedulerSettings(c.scheduler) || c.network.targetCount > maxCheckUrls || c.network.controlCount > maxCheckUrls) return false;
    mbedtls_md_context_t md;
    mbedtls_md_init(&md);
    bool ok = mbedtls_md_setup(&md, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1) == 0 &&
              mbedtls_md_hmac_starts(&md, key64, 64) == 0;
    const auto bytes = [&](const void* pointer, std::size_t length) {
        if (ok) ok = mbedtls_md_hmac_update(&md, static_cast<const unsigned char*>(pointer), length) == 0;
    };
    const auto number = [&](std::uint32_t n) {
        const unsigned char b[]{static_cast<unsigned char>(n), static_cast<unsigned char>(n >> 8),
            static_cast<unsigned char>(n >> 16), static_cast<unsigned char>(n >> 24)};
        bytes(b, sizeof(b));
    };
    const auto text = [&](const char* s) { number(static_cast<std::uint32_t>(std::strlen(s))); bytes(s, std::strlen(s)); };
    constexpr char domain[] = "WARP-CFG-2";
    bytes(domain, sizeof(domain));
    text(c.wifiSsid.data()); text(c.wifiPassword.data()); text(c.routerLogin.data()); text(c.routerPassword.data());
    text(c.router.address.data()); text(c.router.tlsName.data()); text(c.router.interfaceName.data()); text(c.network.timezone.data());
    const char time[]{static_cast<char>('0' + c.scheduler.hour / 10), static_cast<char>('0' + c.scheduler.hour % 10),
        ':', static_cast<char>('0' + c.scheduler.minute / 10), static_cast<char>('0' + c.scheduler.minute % 10), '\0'};
    text(time);
    number(c.router.port); number(c.scheduler.weekday); number(c.monitor.failureThreshold);
    number(c.network.checkIntervalMs / 1000); number(c.network.connectTimeoutMs / 1000); number(c.network.readTimeoutMs / 1000);
    number(c.monitor.disablePauseMs / 1000); number(c.monitor.warmupMs / 1000); number(c.monitor.cooldownMs / 1000);
    number(c.monitor.autoRecovery); number(c.scheduler.enabled); number(c.oledEnabled);
    number(static_cast<std::uint32_t>(c.monitor.targetFailurePolicy));
    number(c.network.targetCount);
    for (unsigned i = 0; i < c.network.targetCount; ++i) text(c.network.targets[i].data());
    number(c.network.controlCount);
    for (unsigned i = 0; i < c.network.controlCount; ++i) text(c.network.controls[i].data());
    if (ok) ok = mbedtls_md_hmac_finish(&md, output32) == 0;
    mbedtls_md_free(&md);
    return ok;
}
}
