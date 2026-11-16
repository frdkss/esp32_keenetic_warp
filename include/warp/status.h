#pragma once
#include "types.h"
class Print;

namespace warp::status {
const char* label(SystemState state);
const char* label(ErrorReason reason);
const char* label(DisplayState display);
const char* label(RecoveryPhase phase);
const char* label(ScheduleState state);
const char* label(RestartDecision decision);
void writeSerial(Print& output, const SystemStatus& snapshot);
}  // namespace warp::status
