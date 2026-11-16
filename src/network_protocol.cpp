#include "warp/network_protocol.h"
#include <algorithm>
#include <cstring>

namespace warp::net {
bool parseUrl(std::string_view text, Url& url) {
    url = {};
    if (text.empty() || text.size() > maxUrlBytes) return false;
    for (unsigned char ch : text) if (ch <= 32 || ch >= 127 || ch == '\\' || ch == '#') return false;
    if (text.substr(0, 8) == "https://") text.remove_prefix(8);
    else if (text.substr(0, 7) == "http://") { text.remove_prefix(7); url.secure = false; url.port = 80; }
    else return false;
    const auto end = text.find_first_of("/?");
    auto authority = text.substr(0, end);
    auto path = end == text.npos ? std::string_view{} : text.substr(end);
    std::string_view host, port;
    if (authority.empty() || authority.find('@') != authority.npos) return false;
    if (authority.front() == '[') {
        const auto close = authority.find(']');
        if (close == authority.npos) return false;
        url.ipv6 = true;
        host = authority.substr(1, close - 1);
        const auto rest = authority.substr(close + 1);
        if (!rest.empty()) { if (rest.front() != ':') return false; port = rest.substr(1); if (port.empty()) return false; }
        if (host.find(':') == host.npos) return false;
        for (char ch : host) if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
            (ch >= 'A' && ch <= 'F') || ch == ':' || ch == '.')) return false;
    } else {
        const auto colon = authority.find(':');
        host = authority.substr(0, colon);
        if (colon != authority.npos) { port = authority.substr(colon + 1); if (port.empty()) return false; }
        if (host.empty() || host.front() == '.' || host.front() == '-' || host.back() == '-') return false;
        for (char ch : host) if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') ||
            (ch >= 'A' && ch <= 'Z') || ch == '.' || ch == '-')) return false;
    }
    if (host.empty() || host.size() >= url.host.size()) return false;
    if (!port.empty()) {
        unsigned number = 0;
        if (port.size() > 5) return false;
        for (char ch : port) { if (ch < '0' || ch > '9') return false; number = number * 10 + ch - '0'; }
        if (number == 0 || number > 65535) return false;
        url.port = static_cast<std::uint16_t>(number);
    }
    std::transform(host.begin(), host.end(), url.host.begin(),
        [](unsigned char ch) { return static_cast<char>(ch >= 'A' && ch <= 'Z' ? ch + ('a' - 'A') : ch); });
    std::size_t offset = 0;
    if (path.empty() || path.front() == '?') url.path[offset++] = '/';
    std::copy(path.begin(), path.end(), url.path.begin() + offset);
    return true;
}
bool validSettings(const NetworkSettings& s) {
    if (!s.controlCount || s.controlCount > maxCheckUrls || !s.targetCount || s.targetCount > maxCheckUrls ||
        s.checkIntervalMs < 1000 || s.checkIntervalMs > 86400000 ||
        s.connectTimeoutMs < 1000 || s.connectTimeoutMs > 60000 || s.readTimeoutMs < 1000 || s.readTimeoutMs > 60000 ||
        s.wifiAttemptMs < 1000 || s.wifiAttemptMs > 60000 || s.wifiRetryMs < 1000 || s.wifiRetryMs > 60000 ||
        s.timezone[0] == 0 || s.timezone.back() != 0) return false;
    for (char ch : s.timezone) {
        if (ch == 0) break;
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
            std::string_view("+-<>:,./").find(ch) != std::string_view::npos)) return false;
    }
    Url parsed, previousUrl;
    const auto count = static_cast<unsigned>(s.controlCount) + s.targetCount;
    for (unsigned i = 0; i < count; ++i) {
        const auto& item = i < s.controlCount ? s.controls[i] : s.targets[i - s.controlCount];
        if (item.back() != 0 || !parseUrl(item.data(), parsed)) return false;
        for (unsigned j = 0; j < i; ++j) {
            const auto& previous = j < s.controlCount ? s.controls[j] : s.targets[j - s.controlCount];
            if (!parseUrl(previous.data(), previousUrl)) return false;
            if (parsed.secure == previousUrl.secure && parsed.port == previousUrl.port &&
                std::strcmp(parsed.host.data(), previousUrl.host.data()) == 0 &&
                std::strcmp(parsed.path.data(), previousUrl.path.data()) == 0) return false;
        }
    }
    return true;
}
void ResponseHeaders::feed(char byte) {
    if (done_ || error_ != ErrorReason::None) return;
    if (++bytes_ > maxBytes) { error_ = ErrorReason::ResponseTooLarge; return; }
    const auto value = static_cast<unsigned char>(byte);
    if ((pendingCr_ && byte != '\n') || (byte == '\n' && !pendingCr_) || value == 127 ||
        (value < 32 && byte != '\r' && byte != '\n' && byte != '\t')) {
        error_ = ErrorReason::InvalidResponse;
        return;
    }
    pendingCr_ = byte == '\r';
    if (firstLine_) {
        if (lineSize_ == statusLine_.size()) { error_ = ErrorReason::InvalidResponse; return; }
        statusLine_[lineSize_++] = byte;
        if (byte == '\n') {
            const std::string_view line(statusLine_.data(), lineSize_);
            if (lineSize_ < 14 || (line.substr(0, 9) != "HTTP/1.1 " && line.substr(0, 9) != "HTTP/1.0 ") ||
                line.substr(lineSize_ - 2) != "\r\n" || line[9] < '1' || line[9] > '5' ||
                line[10] < '0' || line[10] > '9' || line[11] < '0' || line[11] > '9' || line[12] != ' ') {
                error_ = ErrorReason::InvalidResponse; return;
            }
            status_ = (line[9] - '0') * 100 + (line[10] - '0') * 10 + line[11] - '0';
            firstLine_ = false;
        }
    }
    tail_ = (tail_ << 8) | static_cast<unsigned char>(byte);
    if (tail_ == 0x0d0a0d0a) {
        if (status_ >= 200) done_ = true;
        else if (status_ == 101 || ++interim_ > 4) error_ = ErrorReason::InvalidResponse;
        else { firstLine_ = true; lineSize_ = 0; tail_ = 0; }
    }
}
}  // namespace warp::net
