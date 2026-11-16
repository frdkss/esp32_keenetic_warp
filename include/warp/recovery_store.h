#pragma once
#include "keenetic_protocol.h"

namespace warp {
// Durable write-ahead obligation, bound to exactly one HTTPS endpoint/interface.
// Credentials, cookie, and per-cycle counters are never stored here.
class RecoveryStore {
public:
    virtual ~RecoveryStore() = default;
    virtual OperationResult load(const keenetic::Settings& router, bool& pending) = 0;
    virtual OperationResult arm(const keenetic::Settings& router) = 0;
    virtual OperationResult clear() = 0;
};
class NvsRecoveryStore final : public RecoveryStore {
public:
    OperationResult load(const keenetic::Settings& router, bool& pending) override;
    OperationResult arm(const keenetic::Settings& router) override;
    OperationResult clear() override;
};
}  // namespace warp
