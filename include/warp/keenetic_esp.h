#pragma once
#include "keenetic_transport.h"
#include <atomic>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

namespace warp {
// Application lifetime. One task, one queued job, no transport retry or redirect.
class EspKeeneticTransport final : public KeeneticTransport {
public:
    bool start(const keenetic::Settings& settings, std::string_view request) override;
    const keenetic::Response* poll() override;
    void cancel() override;
private:
    struct Job {
        keenetic::Settings settings{};
        std::array<char, keenetic::maxRequestBytes> request{};
        std::size_t size{0};
        std::uint32_t generation{0};
    };
    static void worker(void* argument);
    void execute(const Job& job);
    QueueHandle_t requests_{nullptr}, replies_{nullptr};
    keenetic::Response response_{};
    std::atomic<std::uint32_t> generation_{0};
    bool active_{false}, initialized_{false}, delivered_{false};
};
}  // namespace warp
