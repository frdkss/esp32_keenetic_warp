#include "warp/network.h"
#include "warp/network_protocol.h"
#include <cstdlib>

namespace warp {
namespace {
constexpr std::uint32_t timeFreshMs = 6 * 60 * 60 * 1000;
constexpr std::int64_t minEpoch = 1735689600;  // 2025-01-01 UTC, plus a sync callback is required
constexpr std::int64_t maxEpoch = 4102444800;  // 2100-01-01 UTC
}
OperationResult Network::begin(CredentialsView credentials, const NetworkSettings& settings, std::uint32_t now) {
    if (configured_) return {ErrorReason::NotConfigured};
    if (!net::validSettings(settings) || credentials.wifiSsid.empty() || credentials.wifiSsid.size() > 32 ||
        credentials.wifiPassword.size() > 64 || credentials.wifiSsid.find('\0') != credentials.wifiSsid.npos ||
        credentials.wifiPassword.find('\0') != credentials.wifiPassword.npos ||
        (!credentials.wifiPassword.empty() && credentials.wifiPassword.size() < 8)) return {ErrorReason::NotConfigured};
    if (credentials.wifiPassword.size() == 64) {
        for (char ch : credentials.wifiPassword) if (!((ch >= '0' && ch <= '9') ||
            (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))) return {ErrorReason::NotConfigured};
    }
    settings_ = settings;
    if (!platform_.beginWifi(credentials)) return {reason_ = ErrorReason::ResourceExhausted};
    configured_ = true;
    syncSeen_ = platform_.timeSyncGeneration();
    lossSeen_ = platform_.wifiLossGeneration();
    wifiStamp_ = now;
    connecting_ = true;
    platform_.connectWifi();
    return {reason_ = ErrorReason::None};
}
void Network::invalidate(ErrorReason reason) {
    ++securityGeneration_;
    if (probing_) platform_.cancelProbe();
    probing_ = cycling_ = false;
    cycle_.internetConfirmed = false;
    cycle_.complete = false;
    requested_ = true;
    reason_ = reason;
}
bool Network::requestChecks() {
    if (!configured_ || cycling_) return false;
    requested_ = true;
    cycle_.complete = false;
    cycle_.internetConfirmed = false;
    return true;
}
void Network::startCycle() {
    const auto sequence = cycle_.sequence;
    cycle_ = {};
    cycle_.sequence = sequence;
    cycle_.controlSummary.total = settings_.controlCount;
    cycle_.targetSummary.total = settings_.targetCount;
    cycling_ = true;
    targetsPhase_ = false;
    index_ = 0;
    requested_ = false;
}
void Network::record(CheckResult result) {
    result.reachable = result.error == ErrorReason::None && result.httpStatus >= 200 && result.httpStatus <= 399;
    if (result.error == ErrorReason::None && !result.reachable) result.error = ErrorReason::HttpFailure;
    auto& summary = targetsPhase_ ? cycle_.targetSummary : cycle_.controlSummary;
    (targetsPhase_ ? cycle_.targets : cycle_.controls)[index_++] = result;
    if (result.reachable) ++summary.reachable; else ++summary.failed;
}
void Network::tick(std::uint32_t now) {
    if (!configured_) return;
    const auto loss = platform_.wifiLossGeneration();
    if (loss != lossSeen_) {
        lossSeen_ = loss;
        if (connected_) { connecting_ = false; wifiStamp_ = now; }
        connected_ = false;
        timeValid_ = false;
        invalidate(ErrorReason::WifiDisconnected);
    }
    if (!platform_.wifiConnected()) {
        if (connected_) {
            connected_ = timeValid_ = false;
            invalidate(ErrorReason::WifiDisconnected);
            connecting_ = false;
            wifiStamp_ = now;
        }
        timeValid_ = false;
        syncSeen_ = platform_.timeSyncGeneration();
        reason_ = ErrorReason::WifiDisconnected;
        if (connecting_ && net::elapsed(now, wifiStamp_, settings_.wifiAttemptMs)) {
            platform_.disconnectWifi();
            connecting_ = false;
            wifiStamp_ = now;
        } else if (!connecting_ && net::elapsed(now, wifiStamp_, settings_.wifiRetryMs)) {
            platform_.connectWifi();
            connecting_ = true;
            wifiStamp_ = now;
        }
        return;
    }
    if (!connected_) {
        connected_ = true;
        connecting_ = false;
        syncSeen_ = platform_.timeSyncGeneration();
        timeValid_ = false;
        platform_.startTimeSync(settings_.timezone.data());
        timeRetryStamp_ = now;
    }
    const auto epoch = platform_.epochSeconds();
    const auto sync = platform_.timeSyncGeneration();
    if (sync != syncSeen_) {
        syncSeen_ = sync;
        const bool plausible = epoch >= minEpoch && epoch < maxEpoch;
        const bool stepped = !plausible || !timeValid_ || std::llabs(epoch - epochAnchor_ -
            static_cast<std::uint32_t>(now - timeStamp_) / 1000) > 2;
        if (stepped) invalidate(ErrorReason::TimeNotSynchronized);
        timeValid_ = plausible;
        timeStamp_ = now;
        epochAnchor_ = epoch;
    }
    if (timeValid_ && (epoch < minEpoch || epoch >= maxEpoch || net::elapsed(now, timeStamp_, timeFreshMs) ||
        std::llabs(epoch - epochAnchor_ - static_cast<std::uint32_t>(now - timeStamp_) / 1000) > 2)) {
        timeValid_ = false;
        invalidate(ErrorReason::TimeNotSynchronized);
        platform_.startTimeSync(settings_.timezone.data());
        timeRetryStamp_ = now;
    }
    if (!timeValid_) {
        reason_ = ErrorReason::TimeNotSynchronized;
        if (net::elapsed(now, timeRetryStamp_, 30000)) {
            platform_.startTimeSync(settings_.timezone.data());
            timeRetryStamp_ = now;
        }
        return;
    }
    if (reason_ == ErrorReason::TimeNotSynchronized || reason_ == ErrorReason::WifiDisconnected)
        reason_ = ErrorReason::None;
    if (!cycling_) {
        if (!requested_ && !net::elapsed(now, cycleStamp_, settings_.checkIntervalMs)) return;
        startCycle();
    }
    if (probing_) {
        CheckResult result;
        if (!platform_.pollProbe(result)) return;
        probing_ = false;
        record(result);
    }
    if (!targetsPhase_ && index_ == settings_.controlCount) {
        targetsPhase_ = true;
        index_ = 0;
        if (!cycle_.controlSummary.reachable) {
            while (index_ < settings_.targetCount) record({ErrorReason::InternetUnavailable});
        }
    }
    if (targetsPhase_ && index_ == settings_.targetCount) {
        cycling_ = false;
        cycle_.complete = true;
        cycle_.internetConfirmed = cycle_.controlSummary.reachable > 0;
        ++cycle_.sequence;
        cycleStamp_ = now;
        reason_ = cycle_.internetConfirmed ? ErrorReason::None : ErrorReason::InternetUnavailable;
        return;
    }
    const auto& url = (targetsPhase_ ? settings_.targets : settings_.controls)[index_];
    probing_ = platform_.startProbe(url.data(), settings_.connectTimeoutMs, settings_.readTimeoutMs);
}
}  // namespace warp
