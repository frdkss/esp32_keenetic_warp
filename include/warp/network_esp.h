#pragma once
#include "network.h"
#include <atomic>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "lwip/ip_addr.h"
#include "esp_event.h"

namespace warp {
// Lifetime must cover the whole application: lwIP may finish DNS after its deadline.
class EspNetworkPlatform final : public NetworkPlatform {
public:
    EspNetworkPlatform() = default;
    EspNetworkPlatform(const EspNetworkPlatform&) = delete;
    EspNetworkPlatform& operator=(const EspNetworkPlatform&) = delete;
    bool beginWifi(CredentialsView credentials) override;
    void connectWifi() override;
    void disconnectWifi() override;
    bool wifiConnected() const override { return connected_.load(); }
    std::uint32_t wifiLossGeneration() const override { return losses_.load(); }
    bool startTimeSync(const char* timezone) override;
    std::uint32_t timeSyncGeneration() const override;
    std::int64_t epochSeconds() const override;
    bool startProbe(std::string_view url, std::uint32_t connectMs, std::uint32_t readMs) override;
    bool pollProbe(CheckResult& result) override;
    void cancelProbe() override;
private:
    struct Job { CheckUrl url{}; std::uint32_t connectMs{0}, readMs{0}, generation{0}; };
    struct Reply { CheckResult result{}; std::uint32_t generation{0}; };
    struct DnsState {
        std::array<char, 254> host{};
        ip_addr_t address{};
        bool resolved{false};
        std::atomic<bool> pending{false};
    } dns_;
    static void event(void* arg, esp_event_base_t base, std::int32_t id, void* data);
    static void worker(void* arg);
    static void beginDns(void* arg);
    static void finishDns(const char*, const ip_addr_t* address, void* arg);
    CheckResult execute(const Job& job);
    bool cancelled(const Job& job) const;
    QueueHandle_t requests_{nullptr}, replies_{nullptr};
    std::atomic<bool> connected_{false}, active_{false};
    std::atomic<std::uint32_t> losses_{0}, generation_{0};
    bool sntpInitialized_{false}, initialized_{false};
};
}  // namespace warp
