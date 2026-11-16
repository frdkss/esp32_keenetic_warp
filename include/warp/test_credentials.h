#pragma once
#include "build_profile.h"
#include "types.h"

#if WARP_PROTECTED_BUILD
#error Test credentials must never be included in protected firmware
#endif

namespace warp::test {
// Deliberately fictitious fixtures. No owner settings or sites in test firmware.
inline constexpr CredentialsView credentials{
    "TEST_ONLY_NO_WIFI", "TEST_ONLY_WIFI_PASSWORD",
    "TEST_ONLY_ROUTER_LOGIN", "TEST_ONLY_ROUTER_PASSWORD"};
}  // namespace warp::test
