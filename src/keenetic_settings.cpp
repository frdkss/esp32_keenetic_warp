#include "warp/keenetic_protocol.h"
#include "warp/network_protocol.h"
#include <cstring>

namespace warp::keenetic {
bool validSettings(const Settings& s) {
    if (!s.address[0] || s.address.back() || !s.tlsName[0] || s.tlsName.back() ||
        !s.interfaceName[0] || s.interfaceName.back() || !s.port || s.connectMs < 1000 || s.connectMs > 60000 ||
        s.readMs < 1000 || s.readMs > 60000) return false;
    std::string_view address(s.address.data());
    unsigned parts = 0;
    while (!address.empty()) {
        const auto dot = address.find('.');
        const auto part = address.substr(0, dot);
        unsigned n = 0;
        if (part.empty() || part.size() > 3 || (part.size() > 1 && part.front() == '0')) return false;
        for (char ch : part) { if (ch < '0' || ch > '9') return false; n = n * 10 + ch - '0'; }
        if (n > 255 || ++parts > 4) return false;
        if (dot == address.npos) break;
        address.remove_prefix(dot + 1); if (address.empty()) return false;
    }
    if (parts != 4) return false;
    net::Url url;
    const std::string_view host(s.tlsName.data());
    std::array<char, 270> text{};
    std::memcpy(text.data(), "https://", 8); std::memcpy(text.data() + 8, host.data(), host.size());
    if (!net::parseUrl(text.data(), url) || std::strlen(url.host.data()) != host.size() ||
        std::string_view(url.path.data()) != "/" || host.find(':') != host.npos ||
        host.find('/') != host.npos || host.find('?') != host.npos) return false;
    // A WARP profile must select a Wireguard interface, not WAN/Bridge/etc.
    const std::string_view interface(s.interfaceName.data());
    if (interface.substr(0, 9) != "Wireguard" || interface.size() == 9) return false;
    for (char ch : interface.substr(9)) if (ch < '0' || ch > '9') return false;
    return true;
}
}  // namespace warp::keenetic
