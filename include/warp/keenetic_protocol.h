#pragma once
#include "types.h"
#include <array>
#include <cstddef>

namespace warp::keenetic {
// Only the profile observed in STAGE1 is supported. No command discovery/fallback.
struct Settings {
    std::array<char, 16> address{};  // Explicit LAN IPv4; never resolve the TLS name.
    std::array<char, 254> tlsName{};
    std::array<char, 65> interfaceName{};
    std::uint16_t port{443};
    std::uint32_t connectMs{5000}, readMs{5000};
};
bool validSettings(const Settings& settings);
inline void erase(void* data, std::size_t size) {
    auto* bytes = static_cast<volatile unsigned char*>(data);
    while (size--) *bytes++ = 0;
}
bool mergeCookies(std::array<char, 1025>& jar, std::string_view pairs, bool keepEmpty = false);
struct WarpState {
    bool valid{false}, enabled{false}, linkUp{false}, connected{false};
};
inline constexpr std::size_t maxBodyBytes = 32768;
inline constexpr std::size_t maxRequestBytes = 3072;
struct Response {
    CheckResult diagnostic{ErrorReason::None};
    std::array<char, 257> realm{}, challenge{};
    std::array<char, 129> authScheme{};
    std::array<char, 1025> cookie{};
    bool cookieSeen{false};
    std::array<char, maxBodyBytes + 1> body{};
    std::size_t bodySize{0};
    void clear() { erase(this, sizeof(*this)); }
};
// Bounded HTTP/1.x framing, including chunked/close-delimited bodies. No redirects.
class ResponseParser {
public:
    explicit ResponseParser(Response& response) : response_(response) {}
    void feed(char byte);
    void eof();
    bool done() const { return phase_ == Phase::Done; }
    ErrorReason error() const { return error_; }
private:
    enum class Phase { Status, Headers, Body, ChunkSize, ChunkData, ChunkCr, ChunkLf, Trailers, Done };
    void line();
    void fail(ErrorReason error) { error_ = error; }
    bool append(char byte);
    Response& response_;
    Phase phase_{Phase::Status};
    std::array<char, 1152> line_{};
    std::size_t lineSize_{0}, headerBytes_{0}, length_{0}, remaining_{0};
    unsigned interim_{0}, chunks_{0};
    bool cr_{false}, hasLength_{false}, chunked_{false};
    ErrorReason error_{ErrorReason::None};
};
ErrorReason parseIdentity(std::string_view body);
ErrorReason parseState(std::string_view body, std::string_view interfaceName, WarpState& state);
ErrorReason parseCommand(std::string_view body);
bool makeProof(std::string_view login, std::string_view password, std::string_view realm,
               std::string_view challenge, std::array<char, 65>& proof);
bool makeLoginBody(std::string_view login, std::string_view proof, std::array<char, 1025>& body);
}  // namespace warp::keenetic
