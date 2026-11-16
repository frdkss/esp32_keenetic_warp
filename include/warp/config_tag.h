#pragma once
#include "runtime_config.h"
namespace warp {
// Keyed fingerprint of the settings actually loaded by the running firmware.
bool configurationTag(const RuntimeConfiguration& configuration, const unsigned char* key64, unsigned char* output32);
}
