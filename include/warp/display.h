#pragma once
#include "board_profile.h"
#include "types.h"

namespace warp {
class Display {
public:
    DisplayState begin(const board::DisplayProfile& profile, bool enabled = true);
    DisplayState check();
    void render(const SystemStatus& snapshot);
private:
    bool ready_{false};
    DisplayState state_{DisplayState::Disabled};
    std::uint8_t address_{0};
};
}  // namespace warp
