#pragma once
#include "network.h"

namespace warp::net {
struct Url {
    bool secure{true};
    std::array<char, 254> host{};
    std::array<char, maxUrlBytes + 2> path{};
    std::uint16_t port{443};
    bool ipv6{false};
};
bool parseUrl(std::string_view text, Url& url);
bool validSettings(const NetworkSettings& settings);
constexpr bool elapsed(std::uint32_t now, std::uint32_t then, std::uint32_t duration) {
    return static_cast<std::uint32_t>(now - then) >= duration;
}
// Streaming, bounded HTTP/1.x headers. Bodies and redirects are never consumed.
class ResponseHeaders {
public:
    static constexpr std::size_t maxBytes = 4096;
    void feed(char byte);
    bool done() const { return done_; }
    ErrorReason error() const { return error_; }
    int status() const { return status_; }
private:
    std::array<char, 128> statusLine_{};
    std::size_t bytes_{0}, lineSize_{0};
    unsigned tail_{0}, interim_{0};
    int status_{0};
    bool firstLine_{true}, done_{false}, pendingCr_{false};
    ErrorReason error_{ErrorReason::None};
};
}  // namespace warp::net
