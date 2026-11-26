#pragma once

namespace warp::wifi_update {
// Discovery and the HTTPS staging endpoint run only after Wi-Fi is connected.
// Outside protected builds this is a no-op.
void tick(bool wifiConnected);
}
