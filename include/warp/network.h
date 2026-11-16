#pragma once
#include <array>
#include "types.h"

namespace warp {
inline constexpr std::size_t maxCheckUrls = 8;
inline constexpr std::size_t maxUrlBytes = 512;
using CheckUrl = std::array<char, maxUrlBytes + 1>;

struct NetworkSettings {
    std::array<CheckUrl, maxCheckUrls> controls{}, targets{};
    std::uint8_t controlCount{0}, targetCount{0};
    std::array<char, 129> timezone{};
    std::uint32_t checkIntervalMs{60000}, connectTimeoutMs{5000}, readTimeoutMs{5000};
    std::uint32_t wifiAttemptMs{15000}, wifiRetryMs{5000};
};
struct CheckCycle {
    std::array<CheckResult, maxCheckUrls> controls{}, targets{};
    CheckSummary controlSummary{}, targetSummary{};
    bool complete{false}, internetConfirmed{false};
    std::uint32_t sequence{0};
};
// One owner (the loop task). The adapter runs at most one bounded probe at a time.
class NetworkPlatform {
public:
    virtual ~NetworkPlatform() = default;
    virtual bool beginWifi(CredentialsView credentials) = 0;
    virtual void connectWifi() = 0;
    virtual void disconnectWifi() = 0;
    virtual bool wifiConnected() const = 0;
    virtual std::uint32_t wifiLossGeneration() const = 0;
    virtual bool startTimeSync(const char* timezone) = 0;
    virtual std::uint32_t timeSyncGeneration() const = 0;
    virtual std::int64_t epochSeconds() const = 0;
    virtual bool startProbe(std::string_view url, std::uint32_t connectMs, std::uint32_t readMs) = 0;
    virtual bool pollProbe(CheckResult& result) = 0;
    virtual void cancelProbe() = 0;
};
class Network {
public:
    explicit Network(NetworkPlatform& platform) : platform_(platform) {}
    OperationResult begin(CredentialsView credentials, const NetworkSettings& settings, std::uint32_t nowMs);
    void tick(std::uint32_t nowMs);
    bool requestChecks();
    bool wifiConnected() const { return connected_; }
    bool timeSynchronized() const { return timeValid_; }
    bool internetConfirmed() const { return connected_ && timeValid_ && cycle_.internetConfirmed; }
    bool busy() const { return cycling_; }
    ErrorReason reason() const { return reason_; }
    const CheckCycle& checks() const { return cycle_; }
    const NetworkSettings& settings() const { return settings_; }
    // Also changes when a clock correction revokes trust and is confirmed in the same tick.
    std::uint32_t securityGeneration() const { return securityGeneration_; }
private:
    void invalidate(ErrorReason reason);
    void startCycle();
    void record(CheckResult result);
    NetworkPlatform& platform_;
    NetworkSettings settings_{};
    CheckCycle cycle_{};
    ErrorReason reason_{ErrorReason::NotConfigured};
    bool configured_{false}, connected_{false}, connecting_{false}, timeValid_{false};
    bool cycling_{false}, probing_{false}, targetsPhase_{false}, requested_{true};
    std::uint8_t index_{0};
    std::uint32_t wifiStamp_{0}, cycleStamp_{0}, timeStamp_{0}, syncSeen_{0}, lossSeen_{0};
    std::uint32_t timeRetryStamp_{0};
    std::uint32_t securityGeneration_{0};
    std::int64_t epochAnchor_{0};
};
}  // namespace warp
