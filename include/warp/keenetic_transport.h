#pragma once
#include "keenetic_protocol.h"

namespace warp {
class KeeneticTransport {
public:
    virtual ~KeeneticTransport() = default;
    // Must copy the request before returning; response lives until next start/cancel.
    virtual bool start(const keenetic::Settings& settings, std::string_view request) = 0;
    virtual const keenetic::Response* poll() = 0;
    virtual void cancel() = 0;
};
}  // namespace warp
