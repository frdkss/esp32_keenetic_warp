#pragma once

#ifndef WARP_PROTECTED_BUILD
#error Select an explicit test or protected build
#endif
#ifndef OLED_ENABLED
#error Select OLED_ENABLED=0 or OLED_ENABLED=1
#endif
#if (WARP_PROTECTED_BUILD != 0 && WARP_PROTECTED_BUILD != 1) || (OLED_ENABLED != 0 && OLED_ENABLED != 1)
#error Invalid build profile
#endif

namespace warp::build {
inline constexpr bool protectedBuild = WARP_PROTECTED_BUILD == 1;
inline constexpr bool oledEnabled = OLED_ENABLED == 1;
}  // namespace warp::build
