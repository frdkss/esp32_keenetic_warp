#pragma once
#include "keenetic_transport.h"

namespace warp {
class Monitor;
class Network;
class KeeneticClient {
public:
    explicit KeeneticClient(Network& network) : network_(network) {}
    KeeneticClient(Network& network, KeeneticTransport& transport) : network_(network), transport_(&transport) {}
    ~KeeneticClient() {
        keenetic::erase(login_.data(), login_.size());
        keenetic::erase(password_.data(), password_.size());
        keenetic::erase(cookie_.data(), cookie_.size());
        keenetic::erase(loginBody_.data(), loginBody_.size());
    }
    KeeneticClient(const KeeneticClient&) = delete;
    KeeneticClient& operator=(const KeeneticClient&) = delete;
    OperationResult begin(CredentialsView credentials, const keenetic::Settings& settings);
    OperationResult readWarpState();  // Pending means queued, never success.
    void tick(std::uint32_t nowMs);
    bool busy() const { return step_ != Step::Idle; }
    bool blocked() const { return blocked_; }
    OperationResult result() const { return result_; }
    const keenetic::WarpState& state() const { return state_; }
    const keenetic::Identity& identity() const { return identity_; }
    const CheckResult& diagnostic() const { return diagnostic_; }

private:
    // Only Monitor may drive recovery; Scheduler cannot send router commands.
    friend class Monitor;
    OperationResult setWarpEnabled(bool enabled);
    OperationResult startOperation(bool change, bool enabled);
    void finish(ErrorReason reason);
    bool send();
    enum class Step { Idle, Challenge, Login, Identity, Read, Change, Verify };
    Network& network_;
    KeeneticTransport* transport_{nullptr};
    keenetic::Settings settings_{};
    keenetic::WarpState state_{};
    keenetic::Identity identity_{};
    std::array<char, 129> login_{};
    std::array<char, 257> password_{};
    std::array<char, 1025> cookie_{}, loginBody_{};
    OperationResult result_{ErrorReason::NotConfigured};
    CheckResult diagnostic_{ErrorReason::NotConfigured};
    Step step_{Step::Idle}, resume_{Step::Read};
    bool configured_{false}, blocked_{false}, authenticated_{false}, identified_{false};
    bool pending_{false}, change_{false}, enabled_{false}, renewed_{false};
    std::uint32_t stamp_{0}, securitySeen_{0};
};
}  // namespace warp
